<#
.SYNOPSIS
Deploy NetSentinel to Azure Container Apps

.DESCRIPTION
This script automates the creation of an Azure Resource Group, Azure Container Registry (ACR), and Azure Container Apps Environment.
It builds the API and Dashboard container images using ACR Tasks and deploys them to ACA.
#>

param(
    [string]$ResourceGroup = "rg-netsentinel",
    [string]$Location = "eastus",
    [string]$AcrName = "acrnetsentinel$((Get-Random -Maximum 9999))",
    [string]$EnvName = "env-netsentinel",
    [string]$ApiAppName = "netsentinel-api",
    [string]$DashboardAppName = "netsentinel-dashboard",
    [string]$ApiKey = "production_api_key_replace_me",
    [string]$AdminKey = "production_admin_key_replace_me"
)

Write-Host "Starting NetSentinel deployment to Azure..." -ForegroundColor Cyan

# 1. Create Resource Group
Write-Host "Creating Resource Group: $ResourceGroup in $Location..."
az group create --name $ResourceGroup --location $Location --output none

# 2. Create ACR
Write-Host "Creating Azure Container Registry: $AcrName..."
az acr create --resource-group $ResourceGroup --name $AcrName --sku Basic --admin-enabled true --output none

# 3. Build Images via ACR Tasks
Write-Host "Building API Image in ACR..."
az acr build --registry $AcrName --image "netsentinel-api:latest" --file Dockerfile.api ../

Write-Host "Building Dashboard Image in ACR..."
az acr build --registry $AcrName --image "netsentinel-dashboard:latest" --file Dockerfile.dashboard ../

# 4. Create Container Apps Environment
Write-Host "Creating Container Apps Environment: $EnvName..."
az containerapp env create --name $EnvName --resource-group $ResourceGroup --location $Location --output none

# 5. Deploy API App
Write-Host "Deploying API App: $ApiAppName..."
$ApiUrl = az containerapp create `
    --name $ApiAppName `
    --resource-group $ResourceGroup `
    --environment $EnvName `
    --image "$AcrName.azurecr.io/netsentinel-api:latest" `
    --registry-server "$AcrName.azurecr.io" `
    --target-port 8000 `
    --ingress internal `
    --env-vars "NS_API_KEY=$ApiKey" "NS_ADMIN_KEY=$AdminKey" "NS_MOCK=0" `
    --query properties.configuration.ingress.fqdn `
    --output tsv

$ApiUrl = "https://$ApiUrl"
Write-Host "API App deployed internally at: $ApiUrl" -ForegroundColor Green

# 6. Deploy Dashboard App
Write-Host "Deploying Dashboard App: $DashboardAppName..."
$DashboardUrl = az containerapp create `
    --name $DashboardAppName `
    --resource-group $ResourceGroup `
    --environment $EnvName `
    --image "$AcrName.azurecr.io/netsentinel-dashboard:latest" `
    --registry-server "$AcrName.azurecr.io" `
    --target-port 8501 `
    --ingress external `
    --env-vars "NS_API_URL=$ApiUrl" `
    --query properties.configuration.ingress.fqdn `
    --output tsv

$DashboardUrl = "https://$DashboardUrl"
Write-Host "Dashboard App deployed externally at: $DashboardUrl" -ForegroundColor Green

Write-Host "Deployment Complete!" -ForegroundColor Cyan
