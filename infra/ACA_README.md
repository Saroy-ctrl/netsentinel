# NetSentinel Azure Deployment

This document provides instructions on how to deploy the NetSentinel platform to Azure Container Apps (ACA).

## Prerequisites
1. [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) installed and logged in (`az login`).
2. An active Azure Subscription.

## Deployment Script

The `deploy.ps1` script automates the full infrastructure provisioning and application deployment process using the Azure CLI.

### What it does:
1. Creates an Azure Resource Group.
2. Creates an Azure Container Registry (ACR).
3. Builds the `api` and `dashboard` Docker images remotely via ACR Build Tasks.
4. Provisions an Azure Container Apps Environment.
5. Deploys the `netsentinel-api` securely with internal ingress.
6. Deploys the `netsentinel-dashboard` with external ingress, pointing to the internal API FQDN.

### Usage
Run the deployment script from the `infra/` directory:

```powershell
.\deploy.ps1 -ResourceGroup "rg-netsentinel" -Location "eastus" -ApiKey "your-secure-api-key" -AdminKey "your-secure-admin-key"
```

## GitHub Actions CI/CD
The repository includes a `.github/workflows/ci.yml` file.

- **CI (Test Job):** Runs `ruff` linting and `pytest` automatically on PRs and pushes to `main` and `feature/m3-backend-platform`.
- **CD (Deploy Azure Job):** Triggers only on `main` branch or manual dispatch. Pushes images to ACR and updates the ACA instances.

**Required GitHub Secrets for CD:**
- `AZURE_CREDENTIALS`: A JSON payload from an Azure Service Principal with Contributor access.
- `AZURE_RG`: The name of the target resource group.
- `ACR_NAME`: The name of the target Azure Container Registry.
