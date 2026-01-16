import azure.functions as func
import asyncio
import httpx
import json
import logging
import os
from aiolimiter import AsyncLimiter
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Optional

# Minimal logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = func.FunctionApp()

@app.route(route="Web3AddressAnalyzerHttp", auth_level=func.AuthLevel.ANONYMOUS)
async def Web3AddressAnalyzerHttp(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        api_key = os.getenv("ALCHEMY_API_KEY")
        if not api_key:
            return func.HttpResponse("ALCHEMY_API_KEY not set", status_code=500)

        addresses = parse_addresses_file(req.files.get('file'))

        # Single shared HTTP client
        http_client = httpx.AsyncClient(timeout=10, http2=True)

        alchemy_client = AlchemyClient(api_key, http_client)
        blockstream_client = BlockStreamClient(http_client)
        analyzer = AddressAnalyzer(alchemy_client, blockstream_client)

        results = await analyzer.process(addresses)

        await http_client.aclose()

        return func.HttpResponse(body=json.dumps(results), mimetype="application/json")

    except Exception as e:
        logger.error(f"Main error: {e}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

def parse_addresses_file(file) -> List[Dict]:
    if not file:
        raise ValueError("Missing addresses file")

    content = file.read().decode('utf-8')
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    addresses = []
    for line in lines:
        parts = line.split()
        network, address = parts[0].lower(), parts[1]
        if network in NETWORK_CAPABILITIES:
            # BTC addresses are case-sensitive, keep original case
            address = address if network == "btc" else address.lower()
            addresses.append((network, address))

    # Remove duplicates
    addresses = list(dict.fromkeys(addresses))
    return addresses

@dataclass
class NetworkCapabilities:
    network: str
    is_evm: bool
    native_symbol: str
    native_decimals: int
    alchemy_rpc_supported: bool
    alchemy_network_name: Optional[str]

NETWORK_CAPABILITIES = {
    "arbitrum": NetworkCapabilities("arbitrum", True, "ETH", 18, True, "arb"),
    "avalanche": NetworkCapabilities("avalanche", True, "AVAX", 18, True, "avax"),
    "base": NetworkCapabilities("base", True, "ETH", 18, True, "base"),
    "bsc": NetworkCapabilities("bsc", True, "BNB", 18, True, "bnb"),
    "btc": NetworkCapabilities("btc", False, "BTC", 8, False, None),
    "ethereum": NetworkCapabilities("ethereum", True, "ETH", 18, True, "eth"),
    "linea": NetworkCapabilities("linea", True, "ETH", 18, True, "linea"),
    "monad": NetworkCapabilities("monad", True, "MON", 18, True, "monad"),
    "optimism": NetworkCapabilities("optimism", True, "ETH", 18, True, "opt"),
    "polygon": NetworkCapabilities("polygon", True, "POL", 18, True, "polygon"),
    "sei": NetworkCapabilities("sei", True, "SEI", 18, True, "sei"),
    "zksync": NetworkCapabilities("zksync", True, "ETH", 18, True, "zksync"),
}

class BlockStreamClient:
    def __init__(self, http_client: httpx.AsyncClient):
        self._http = http_client
        self.base_url = "https://blockstream.info/api"
        self._rate_limit = AsyncLimiter(10, 1)  # 10 req/sec

    async def get_btc_address_info(self, address: str) -> dict:
        url = f"{self.base_url}/address/{address}"

        try:
            async with self._rate_limit:
                resp = await self._http.get(url)
            resp.raise_for_status()
            data = resp.json()

            # Calculate confirmed balance (funded - spent)
            chain_stats = data.get("chain_stats", {})
            confirmed_balance = (
                chain_stats.get("funded_txo_sum", 0) -
                chain_stats.get("spent_txo_sum", 0)
            )

            # Calculate mempool balance
            mempool_stats = data.get("mempool_stats", {})
            mempool_balance = (
                mempool_stats.get("funded_txo_sum", 0) -
                mempool_stats.get("spent_txo_sum", 0)
            )

            return {
                "confirmed_balance_satoshi": confirmed_balance,
                "mempool_balance_satoshi": mempool_balance,
                "total_balance_satoshi": confirmed_balance + mempool_balance
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Blockstream API error for {address}: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"Error fetching BTC address info for {address}: {e}")
            raise

class AddressAnalyzer:
    ETH_ADDRESS_SMART_CONTRACT_TYPE_IDS = {
        "0xd19d4b5d358258f05d7b411e21a1460d11b0876f": "linea_rollup",
        "0xb3b448833324511ab1e32ea4a28c39a02201e7be": "skl_staking",
        "0x0345e97b81cb9c42f2c58b6b94e5b65f0dc2eea0": "ninja_trading",
    }

    def __init__(self, alchemy_client, mempool_client):
        self.alchemy_client = alchemy_client
        self.mempool_client = mempool_client
        self.prices = {}

    async def _fetch_prices(self, addresses):
        unique_symbols = {
            caps.native_symbol
            for net, _ in addresses
            if (caps := NETWORK_CAPABILITIES.get(net))
        }

        if not unique_symbols:
            return

        price_data = await self.alchemy_client.get_prices_by_symbol(list(unique_symbols))
        for item in price_data:
            symbol = item.get("symbol")
            if symbol and item.get("prices"):
                price_info = item["prices"][0]
                self.prices[symbol] = {
                    "price_usd": Decimal(price_info.get("value", "0")),
                    "retrieved_at": price_info.get("lastUpdatedAt")
                }

    def _get_contract_notes(self, network: str, address: str, bytecode: str) -> dict:
        lower_address = address.lower()
        bytecode_sample = bytecode[:34].lower()

        notes = {
            "smart_contract_type": "PENDING TYPE ID",
            "bytecode_sample": bytecode_sample
        }

        if bytecode_sample.startswith("0xef0100"):
            notes["smart_contract_type"] = "eip_7702_delegation"
        elif bytecode_sample == "0x60806040526004361061006557600035":
            notes["smart_contract_type"] = "fee_distributor"

        if network == "ethereum":
            atype = self.ETH_ADDRESS_SMART_CONTRACT_TYPE_IDS.get(lower_address)
            if atype:
                notes["smart_contract_type"] = atype

        return notes

    async def analyze_btc(self, semaphore: asyncio.Semaphore, address: str):
        async with semaphore:
            result = {"network": "btc", "address": address}

            caps = NETWORK_CAPABILITIES.get("btc")
            if not caps:
                result["error"] = "BTC Network is not supported"
                return result

            try:
                btc_info = await self.mempool_client.get_btc_address_info(address)

                total_satoshi = btc_info["total_balance_satoshi"]
                confirmed_satoshi = btc_info["confirmed_balance_satoshi"]
                mempool_satoshi = btc_info["mempool_balance_satoshi"]

                # Convert satoshi to BTC
                balance_btc = Decimal(total_satoshi) / Decimal(10**caps.native_decimals)

                result["btc_properties"] = {
                    "confirmed_balance_satoshi": str(confirmed_satoshi),
                    "mempool_balance_satoshi": str(mempool_satoshi),
                    "total_balance_satoshi": str(total_satoshi),
                    "balance_btc": f"{balance_btc:.8f}".rstrip('0').rstrip('.')
                }

                # Add price info if available
                price_info = self.prices.get("BTC")
                if price_info:
                    price = price_info["price_usd"]
                    retrieved_at = price_info["retrieved_at"]
                    balance_usd = balance_btc * price

                    result["price_info"] = {
                        "native_balance": f"{balance_btc:.8f}".rstrip('0').rstrip('.'),
                        "native_balance_usd": f"{balance_usd:.2f}".rstrip('0').rstrip('.'),
                        "native_symbol": "BTC",
                        "price_retrieved_at": retrieved_at,
                        "price_usd": f"{price:.18f}".rstrip('0').rstrip('.')
                    }

            except Exception as e:
                logger.error(f"Error processing btc:{address}: {e}")
                result["error"] = str(e)

            return result

    async def analyze_evm(self, semaphore: asyncio.Semaphore, network: str, address: str):
        async with semaphore:
            result = {"network": network, "address": address}

            caps = NETWORK_CAPABILITIES.get(network)
            if not caps:
                result["error"] = "Network is not supported"
                return result

            try:
                balance_task = self.alchemy_client.get_native_balance(network, address)
                is_safe_task = self.alchemy_client.is_safe(network, address)
                bytecode_task = self.alchemy_client.get_bytecode(network, address)

                balance_wei_str, bytecode, is_safe = await asyncio.gather(
                    balance_task, bytecode_task, is_safe_task
                )

                balance_wei = int(balance_wei_str)
                balance_native = Decimal(balance_wei) / Decimal(10**caps.native_decimals)
                is_eoa = bytecode == '0x'

                result["evm_properties"] = {
                    "is_eoa": is_eoa,
                    "is_safe": is_safe,
                    "native_balance_wei": str(balance_wei)
                }

                price_info = self.prices.get(caps.native_symbol)
                if price_info:
                    price = price_info["price_usd"]
                    retrieved_at = price_info["retrieved_at"]
                    native_balance_usd = balance_native * price

                    result["price_info"] = {
                        "native_balance": f"{balance_native:.18f}".rstrip('0').rstrip('.'),
                        "native_balance_usd": f"{native_balance_usd:.2f}".rstrip('0').rstrip('.'),
                        "native_symbol": caps.native_symbol,
                        "price_retrieved_at": retrieved_at,
                        "price_usd": f"{price:.18f}".rstrip('0').rstrip('.')
                    }

                if not is_eoa and not is_safe:
                    result["notes"] = self._get_contract_notes(network, address, bytecode)

                if is_safe:
                    threshold_task = self.alchemy_client.get_safe_threshold(network, address)
                    nonce_task = self.alchemy_client.get_safe_nonce(network, address)
                    owners_task = self.alchemy_client.get_safe_owners(network, address)
                    threshold, nonce, owners = await asyncio.gather(
                        threshold_task, nonce_task, owners_task
                    )

                    result["safe_details"] = {
                        "threshold": threshold,
                        "nonce": nonce,
                        "owners": owners
                    }
            except Exception as e:
                logger.error(f"Error processing {network}:{address}: {e}")
                result["error"] = str(e)
            return result

    async def process(self, addresses):
        await self._fetch_prices(addresses)
        semaphore = asyncio.Semaphore(10)

        tasks = []
        for net, addr in addresses:
            if net == "btc":
                tasks.append(self.analyze_btc(semaphore, addr))
            else:
                tasks.append(self.analyze_evm(semaphore, net, addr))

        results = await asyncio.gather(*tasks)

        return results

class AlchemyClient:
    def __init__(self, api_key: str, http_client: httpx.AsyncClient):
        self._http = http_client
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

        self.base_urls = {
            net_name: f"https://{caps.alchemy_network_name}-mainnet.g.alchemy.com/v2"
            for net_name, caps in NETWORK_CAPABILITIES.items()
            if caps.alchemy_rpc_supported and caps.alchemy_network_name is not None
        }
        self.prices_api_url = "https://api.g.alchemy.com/prices/v1"

        self._rate_limit = AsyncLimiter(250, 1)  # 250 req/sec
        self._concurrency = asyncio.Semaphore(100)  # 100 concurrent

    async def get_prices_by_symbol(self, symbols: list[str]) -> list:
        url = f"{self.prices_api_url}/tokens/by-symbol"
        params = {"symbols": symbols}

        try:
            resp = await self._http.get(url, params=params, headers=self.headers)
            resp.raise_for_status()
            return resp.json().get("data", [])
        except httpx.HTTPStatusError as e:
            logger.error(f"Price API request failed: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            logger.error(f"Error fetching prices for symbols {symbols}: {e}")
            return []

    async def _blockchain_node_request(self, network, method, params):
        url = self.base_urls.get(network)
        if not url:
            raise ValueError(f"Network '{network}' is not supported by AlchemyClient.")
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}

        try:
            async with self._rate_limit:
                async with self._concurrency:
                    resp = await self._http.post(url, json=payload, headers=self.headers)
            resp.raise_for_status()
            return resp.json().get("result")
        except Exception as e:
            logger.error(f"Request error for {method} on {network}: {e}")
            return None

    async def get_native_balance(self, network, address):
        result = await self._blockchain_node_request(network, "eth_getBalance", [address, "latest"])
        return str(int(result, 16)) if result else "0"

    async def get_bytecode(self, network, address):
        return await self._blockchain_node_request(network, "eth_getCode", [address, "latest"])

    # Check for masterCopy() (method signature 0xa619486e),
    # a good indicator of a Gnosis Safe proxy
    async def is_safe(self, network, address):
        params = [{"to": address, "data": "0xa619486e"}, "latest"]
        result = await self._blockchain_node_request(network, "eth_call", params)
        return result is not None and result != '0x'

    # Check for getThreshold() (method signature 0xe75235b8)
    async def get_safe_threshold(self, network, address):
        params = [{"to": address, "data": "0xe75235b8"}, "latest"]
        result = await self._blockchain_node_request(network, "eth_call", params)
        return int(result, 16) if result and result != '0x' else None

    # Check for nonce() (method signature 0xaffed0e0)
    async def get_safe_nonce(self, network, address):
        params = [{"to": address, "data": "0xaffed0e0"}, "latest"]
        result = await self._blockchain_node_request(network, "eth_call", params)
        return int(result, 16) if result and result != '0x' else None

    # Check for getOwners() (method signature 0xa0e67e2b)
    async def get_safe_owners(self, network, address):
        params = [{"to": address, "data": "0xa0e67e2b"}, "latest"]
        result = await self._blockchain_node_request(network, "eth_call", params)
        if result and result != '0x':
            raw_owners = result[130:]
            owners = []
            for i in range(0, len(raw_owners), 64):
                padded_addr = raw_owners[i:i+64]
                addr_hex = padded_addr[24:64]
                owners.append(f"0x{addr_hex}")
            return owners
        return None
