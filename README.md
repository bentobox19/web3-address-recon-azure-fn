# Web3 Address Reconnaissance Azure Function

<!-- MarkdownTOC -->

- Overview
- Development Notes
  - Tools
  - Running locally
  - Learning

<!-- /MarkdownTOC -->

## Overview

Azure functions cousin of https://github.com/bentobox19/web3-address-recon

## Development Notes

### Tools

````bash
# brew tap azure/functions
brew install azure/functions/azure-functions-core-tools@4
````

### Running locally

Add this file `local.settings.json`

````json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AzureWebJobsStorage": "",
    "ALCHEMY_API_KEY": "<YOUR ALCHEMY_API_KEY>"
  }
}
````

````bash
# First time
python3 -m venv .venv

# Active the virtual environment
source .venv/bin/activate

# Install the required packages
pip install -r requirements.txt
````

````bash
func start
````

````bash
# Try it this way

curl -X POST \
  http://localhost:7071/api/Web3AddressAnalyzerHttp \
  -F "file=@/path/to/your/list/of/wallets.txt"

# You can always pipe to `python3 -m json.tool` (or jq)
````

The expected format of the list of wallets is `[Network] [Address]`

````
Base 0x1F98431c8aD98523631AE4a59f267346ea31F984
Ethereum 0x00000000219ab540356cBB839Cbe05303d7705Fa
Optimism 0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb
````

### Learning

* Still remains to understand well the `host.json` file
* Still remains to understand well the `local.settings.json` file.
