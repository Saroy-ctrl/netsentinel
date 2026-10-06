# Azure setup

Two Azure services are used: **Azure Machine Learning** (model registry for bundles, M2) and **Azure OpenAI** (incident briefs, M5).
Everything has a local fallback, so the demo works with Azure unreachable (see "Offline behaviour").

## 1. Azure ML workspace (M2-12)

```bash
az login
az account set --subscription "<subscription id>"
az group create -n netsentinel-rg -l westeurope
az extension add -n ml
az ml workspace create -n netsentinel-ws -g netsentinel-rg -l westeurope
```
Put the three values in `.env` (see `.env.example`):
```
AZURE_SUBSCRIPTION_ID=<id>
AZURE_RESOURCE_GROUP=netsentinel-rg
AZUREML_WORKSPACE=netsentinel-ws
```
Cost: the registry itself is free to use; you pay only for the small storage account the workspace creates (a few MB of bundles).
**Do not** create compute clusters or endpoints; nothing here needs them.

### Status (2026-10-06)
Workspace **`netsentinel-ws`** (Poland Central) holds all four bundles at **version 2**: `netsentinel-bundle` (cic-v1),
`netsentinel-demo-holdout-botnet`, `netsentinel-luflow`, `netsentinel-luflow-recal`. Each was downloaded back into an empty cache,
passed the sha256 check and loaded. Azure OpenAI deployment **`gpt-4.1-mini`** answers through the API (`source: azure_openai`,
~4-5 s per brief).

### Signing in
`scripts/azure_register.py` reads `.env` and signs in with, in order: an `az login` session, a service principal
(`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`), or, if neither exists, **a browser sign-in window**
(`NS_AZURE_INTERACTIVE=1`, set by the script only). The API never opens a browser: for `MODEL_REF=azureml:...` the machine running the
API needs `az login` or a service principal, or a warm cache (below). A browser sign-in lasts for one run, so register several bundles
in one run when using it.

### Register the bundles
```bash
python scripts/azure_register.py artifacts/bundles/cic-v1               --name netsentinel-bundle
python scripts/azure_register.py artifacts/bundles/cic-holdout-botnet   --name netsentinel-demo-holdout-botnet
python scripts/azure_register.py artifacts/bundles/luflow-v1            --name netsentinel-luflow
python scripts/azure_register.py artifacts/bundles/luflow-recal         --name netsentinel-luflow-recal
```
Each version carries tags (dataset, feature schema, contract version, scikit-learn version, headline metrics, held-out family)
so "which model is serving" is always traceable from the Azure portal.

### Use them
`MODEL_REF=azureml:netsentinel-bundle@latest` (or `:3` to pin). The API downloads into `artifacts/cache/azureml/<name>/<version>`
and verifies every file against `manifest.json`.

### Prove it works from a clean machine (task M2-12 exit criterion)
```bash
python scripts/azure_register.py --verify netsentinel-bundle
```
Downloads `@latest` into an empty temporary cache, verifies the hashes and loads the models.

### Offline behaviour (demo insurance)
* A **pinned** version (`name:3`) with a verified cached copy is served from disk with **no network call at all**.
* `@latest` with Azure unreachable falls back to the newest verified cached version and logs a WARNING.
* A download that fails the sha256 check is refused and never cached.
* **Before the demo:** load each bundle once with network on, so the cache is warm.

## 2. Azure OpenAI (M5-02)

Azure OpenAI provides grounded GenAI incident summaries for the SOC queue using a `gpt-4o-mini`-class model.
Like Azure ML, it is designed with a **deterministic local fallback** (`source: "template"`) so the system runs smoothly even if Azure OpenAI is unconfigured or unreachable.

### Provision the Azure OpenAI Resource
```bash
az login
az account set --subscription "<subscription id>"

# Register cognitive services provider (if not already registered)
az provider register --namespace Microsoft.CognitiveServices

# Create Azure OpenAI resource in a region supporting gpt-4o-mini (e.g. eastus2, westeurope)
az cognitiveservices account create \
  -n netsentinel-openai \
  -g netsentinel-rg \
  -l eastus2 \
  --kind OpenAI \
  --sku S0
```

### Deploy the Model (`gpt-4o-mini`)
```bash
az cognitiveservices account deployment create \
  -g netsentinel-rg \
  -n netsentinel-openai \
  --deployment-name gpt-4o-mini \
  --model-name gpt-4o-mini \
  --model-version "2024-07-18" \
  --model-format OpenAI \
  --sku-capacity 10 \
  --sku-name Standard
```

### Configure `.env`
Retrieve the resource endpoint and access key:
```bash
az cognitiveservices account show -n netsentinel-openai -g netsentinel-rg --query properties.endpoint -o tsv
az cognitiveservices account keys list -n netsentinel-openai -g netsentinel-rg --query key1 -o tsv
```

Add these values to your local `.env` file (never commit `.env`):
```env
AZURE_OPENAI_ENDPOINT=https://<resource-name>.openai.azure.com/
AZURE_OPENAI_API_KEY=<your-api-key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini
AZURE_OPENAI_API_VERSION=2024-10-21
```

### Offline & Fallback Behaviour (Demo Insurance)
The brief service (`api/app/services/brief.py`, M5-03) is built to be demo-proof:
* **Unconfigured or Missing Credentials:** If `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_API_KEY` are unset or empty, the service automatically skips remote network calls and returns a deterministic, grounded template brief (`source: "template"`).
* **Strict SLA Timeout:** Remote generation calls enforce an **8.0-second timeout** (`LLM_TIMEOUT_SECONDS = 8.0`). If Azure OpenAI latency spikes, the service immediately aborts the call and falls back to the template.
* **Network & API Error Resilience:** Transient HTTP 429 (rate limits), 500 errors, or network disconnections are caught and logged as warnings; the incident queue is never blocked.
* **Lazy Client Singleton:** The Azure OpenAI client is instantiated only when first needed and cached across calls.
* **Brief Caching:** Once generated, briefs are stored on the incident (`incident.brief`) and reused across queue views unless explicitly requested with `refresh=True`.

### Verification
Run the unit test suite with stubbed and template tests:
```bash
python -m pytest api/tests/test_brief.py
```
