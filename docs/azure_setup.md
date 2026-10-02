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

*Owner: M5. Provision the resource and a `gpt-4o-mini`-class deployment, then fill `AZURE_OPENAI_*` in `.env`. Add the setup notes here.*
