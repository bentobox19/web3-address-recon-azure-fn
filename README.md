# Web3 Address Reconnaissance Azure Function

<!-- MarkdownTOC -->

- Overview
- Development Notes
  - Tools
  - Running locally
  - Render the output locally
  - Deploy to Azure
  - Learning

<!-- /MarkdownTOC -->

## Overview

Azure functions cousin of https://github.com/bentobox19/web3-address-recon

## Development Notes

### Tools

````bash
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
# Test the function locally
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

### Render the output locally

````bash
# In MacOS you can test the output

# (WORK IN PROGRESS)

sed "s#/\* EMBED JSON ARRAY HERE \*/#$(cat /tmp/json-output.json)#" ./viz/template.html > /tmp/test.html && open /tmp/test.html

````


### Deploy to Azure

````bash
brew install azure-cli

# Try and `az logout` when you are done
az login

# The following steps assume your function has been already created in the azure portal
# You can learn more about the process here:
# https://learn.microsoft.com/en-us/azure/azure-functions/how-to-create-function-azure-cli
func azure functionapp publish <YOUR AZURE_FUNCTION_NAME>
````

### Learning

* Still remains to understand well the `host.json` file
* Still remains to understand well the `local.settings.json` file.
