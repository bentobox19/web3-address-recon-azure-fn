import azure.functions as func
import asyncio
import httpx
import json
import logging
import os
from aiolimiter import AsyncLimiter

# Minimal logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = func.FunctionApp()

@app.route(route="Web3AddressAnalyzerHttp", auth_level=func.AuthLevel.ANONYMOUS)
async def Web3AddressAnalyzerHttp(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        api_key = os.getenv("ALCHEMY_API_KEY")
        if not api_key:
            return func.HttpResponse("ALCHEMY_API_KEY not set", status_code=500)

        file = req.files.get('file')
        if file:
            content = file.read().decode('utf-8')
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            addresses = []
            for line in lines:
                parts = line.split()
                network, address = parts[0].lower(), parts[1].lower()
                addresses.append((network, address))

            # Remove duplicates
            addresses = list(dict.fromkeys(addresses))

        client = AlchemyClient(api_key)
        analyzer = AddressAnalyzer(client)
        results = await analyzer.process(addresses)
        await client.aclose()

        return func.HttpResponse(body=json.dumps(results), mimetype="application/json")

    except Exception as e:
        logger.error(f"Main error: {e}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

class AddressAnalyzer:
    ETH_ADDRESS_SMART_CONTRACT_TYPE_IDS = {
        "0xd19d4b5d358258f05d7b411e21a1460d11b0876f": "linea_rollup",
        "0xb3b448833324511ab1e32ea4a28c39a02201e7be": "skl_staking",
        "0x0345e97b81cb9c42f2c58b6b94e5b65f0dc2eea0": "ninja_trading",
    }

    def __init__(self, client):
        self.client = client

    def _get_contract_notes(self, network: str, address: str, bytecode: str) -> dict:
        lower_address = address.lower()
        bytecode_sample = bytecode[:34].lower()

        notes = {
            "smart_contract_type": "PENDING TYPE ID",
            "bytecode_sample": bytecode_sample
        }

        if network == "ethereum":
            atype = self.ETH_ADDRESS_SMART_CONTRACT_TYPE_IDS.get(lower_address)
            if atype:
                notes["smart_contract_type"] = atype
            elif bytecode_sample == "0x60806040526004361061006557600035":
                notes["smart_contract_type"] = "fee_distributor"
            elif bytecode_sample == "0xef010063c0c19a282a1b52b07dd5a65b":
                notes["smart_contract_type"] = "eip_7702_delegation"

        return notes

    async def analyze(self, semaphore: asyncio.Semaphore, network: str, address: str):
        async with semaphore:
            result = {"network": network, "address": address}
            try:
                balance_task = self.client.get_native_balance(network, address)
                is_safe_task = self.client.is_safe(network, address)
                bytecode_task = self.client.get_bytecode(network, address)

                balance, bytecode, is_safe = await asyncio.gather(
                    balance_task, bytecode_task, is_safe_task
                )

                is_eoa = bytecode == '0x'

                result["evm_properties"] = {
                    "native_balance": balance,
                    "is_eoa": is_eoa,
                    "is_safe": is_safe
                }

                if not is_eoa and not is_safe:
                    result["notes"] = self._get_contract_notes(network, address, bytecode)

                if is_safe:
                    threshold_task = self.client.get_safe_threshold(network, address)
                    nonce_task = self.client.get_safe_nonce(network, address)
                    owners_task = self.client.get_safe_owners(network, address)
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
        semaphore = asyncio.Semaphore(10)  # 10 concurrent workers (adjust as needed)
        tasks = [self.analyze(semaphore, net, addr) for net, addr in addresses]
        results = await asyncio.gather(*tasks)
        return results


class AlchemyClient:
    def __init__(self, api_key):
        self.base_urls = {
            "arbitrum": f"https://arb-mainnet.g.alchemy.com/v2",
            "avalanche": f"https://avax-mainnet.g.alchemy.com/v2",
            "base": f"https://base-mainnet.g.alchemy.com/v2",
            "bsc": f"https://bnb-mainnet.g.alchemy.com/v2",
            "ethereum": f"https://eth-mainnet.g.alchemy.com/v2",
            "linea": f"https://linea-mainnet.g.alchemy.com/v2",
            "optimism": f"https://opt-mainnet.g.alchemy.com/v2",
            "polygon": f"https://polygon-mainnet.g.alchemy.com/v2",
            "sei": f"https://sei-mainnet.g.alchemy.com/v2",
            "zksync": f"https://zksync-mainnet.g.alchemy.com/v2"
        }
        self._http = httpx.AsyncClient(timeout=10, http2=True)
        self._rate_limit = AsyncLimiter(250, 1)  # 250 req/sec
        self._concurrency = asyncio.Semaphore(100)  # 100 concurrent
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async def aclose(self):
        await self._http.aclose()

    async def _alchemy_request(self, network, method, params):
        if network not in self.base_urls:
            return None
        url = self.base_urls[network]
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
        result = await self._alchemy_request(network, "eth_getBalance", [address, "latest"])
        return str(int(result, 16)) if result else "0"

    async def get_bytecode(self, network, address):
        return await self._alchemy_request(network, "eth_getCode", [address, "latest"])

    # Check for masterCopy() (method signature 0xa619486e),
    # a good indicator of a Gnosis Safe proxy
    async def is_safe(self, network, address):
        params = [{"to": address, "data": "0xa619486e"}, "latest"]
        result = await self._alchemy_request(network, "eth_call", params)
        return result is not None and result != '0x'

    # Check for getThreshold() (method signature 0xe75235b8)
    async def get_safe_threshold(self, network, address):
        params = [{"to": address, "data": "0xe75235b8"}, "latest"]
        result = await self._alchemy_request(network, "eth_call", params)
        return int(result, 16) if result and result != '0x' else None

    # Check for nonce() (method signature 0xaffed0e0)
    async def get_safe_nonce(self, network, address):
        params = [{"to": address, "data": "0xaffed0e0"}, "latest"]
        result = await self._alchemy_request(network, "eth_call", params)
        return int(result, 16) if result and result != '0x' else None

    # Check for getOwners() (method signature 0xa0e67e2b)
    async def get_safe_owners(self, network, address):
        params = [{"to": address, "data": "0xa0e67e2b"}, "latest"]
        result = await self._alchemy_request(network, "eth_call", params)
        if result and result != '0x':
            raw_owners = result[130:]
            owners = []
            for i in range(0, len(raw_owners), 64):
                padded_addr = raw_owners[i:i+64]
                addr_hex = padded_addr[24:64]
                owners.append(f"0x{addr_hex}")
            return owners
        return None
