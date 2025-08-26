# MXD Library Local Kubernetes Update Script for Windows
# This script updates an existing local MXD deployment to the latest runtime version

param(
    [Parameter(Mandatory=$false)]
    [string]$Environment = "local",
    
    [Parameter(Mandatory=$false)]
    [string]$ImageTag = "latest",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerCheck = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

Write-Host "=== MXD Library Local Kubernetes Update Script (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "Image Tag: $ImageTag" -ForegroundColor Cyan
Write-Host "NOTE: This script updates an existing deployment to the latest runtime version" -ForegroundColor Yellow
Write-Host ""

# Function to check if a command exists
function Test-Command {
    param($Command)
    $result = Get-Command $Command -ErrorAction SilentlyContinue
    if ($result) {
        return $true
    } else {
        return $false
    }
}

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Blue

if (-not $SkipDockerCheck) {
    if (-not (Test-Command "docker")) {
        Write-Host "ERROR: Docker is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        exit 1
    }

    # Check if Docker is running
    docker version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
        exit 1
    }
}

if (-not (Test-Command "kubectl")) {
    Write-Host "ERROR: kubectl is not installed or not in PATH" -ForegroundColor Red
    Write-Host "kubectl should be installed with Docker Desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host "Docker is available" -ForegroundColor Green
Write-Host "kubectl is available" -ForegroundColor Green

# Set kubectl context to docker-desktop
Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Could not set context to docker-desktop" -ForegroundColor Yellow
}

# Check if deployment exists
Write-Host "Checking existing deployment..." -ForegroundColor Blue
$deploymentExists = kubectl get deployment mxd-enterprise-local -n "mxd-$Environment" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: No existing deployment found in namespace mxd-$Environment" -ForegroundColor Red
    Write-Host "Please run the deploy script first:" -ForegroundColor Yellow
    Write-Host ".\scripts\deploy-local-windows.ps1 -Environment $Environment" -ForegroundColor White
    exit 1
}

Write-Host "Found existing deployment: mxd-enterprise-local" -ForegroundColor Green

# Get current deployment status
Write-Host "Current deployment status:" -ForegroundColor Blue
kubectl get deployment mxd-enterprise-local -n "mxd-$Environment"
kubectl get pods -n "mxd-$Environment"

if (-not $Force) {
    Write-Host ""
    Write-Host "This will update the deployment to use the latest runtime version." -ForegroundColor Yellow
    Write-Host "The update process will:" -ForegroundColor Yellow
    Write-Host "1. Rebuild the Docker image with latest code" -ForegroundColor White
    Write-Host "2. Update the Kubernetes deployment" -ForegroundColor White
    Write-Host "3. Perform a rolling update of running pods" -ForegroundColor White
    Write-Host "4. Wait for the new pods to be ready" -ForegroundColor White
    Write-Host ""
    $confirmation = Read-Host "Continue with update? (y/N)"
    if ($confirmation -ne "y" -and $confirmation -ne "Y") {
        Write-Host "Update cancelled" -ForegroundColor Yellow
        exit 0
    }
}

# Build updated Docker image
Write-Host ""
Write-Host "Building updated MXD Docker image..." -ForegroundColor Blue
$buildStartTime = Get-Date
docker build -t "mxdlib:$ImageTag" .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build updated Docker image" -ForegroundColor Red
    exit 1
}
$buildEndTime = Get-Date
$buildDuration = $buildEndTime - $buildStartTime
Write-Host "Docker image built successfully in $($buildDuration.TotalSeconds) seconds" -ForegroundColor Green

# Verify the updated image
Write-Host "Verifying updated Docker image..." -ForegroundColor Blue
docker images mxdlib:$ImageTag
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Updated Docker image not found after build" -ForegroundColor Red
    exit 1
}

# Force Kubernetes to pull the updated image by restarting the deployment
Write-Host "Updating Kubernetes deployment..." -ForegroundColor Blue
kubectl rollout restart deployment/mxd-enterprise-local -n "mxd-$Environment"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to restart deployment" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment restart initiated" -ForegroundColor Green

# Wait for rollout to complete
Write-Host "Waiting for rollout to complete..." -ForegroundColor Blue
kubectl rollout status deployment/mxd-enterprise-local -n "mxd-$Environment" --timeout=300s
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Rollout did not complete within 5 minutes" -ForegroundColor Yellow
    Write-Host "Check deployment status with: kubectl get pods -n mxd-$Environment" -ForegroundColor Yellow
    Write-Host "Check pod logs with: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor Yellow
} else {
    Write-Host "Rollout completed successfully" -ForegroundColor Green
}

# Get updated deployment information
Write-Host ""
Write-Host "Updated deployment status:" -ForegroundColor Blue
kubectl get deployment mxd-enterprise-local -n "mxd-$Environment"
kubectl get pods -n "mxd-$Environment"

# Get service information
Write-Host ""
Write-Host "Service endpoints:" -ForegroundColor Blue
kubectl get services -n "mxd-$Environment"

# Test health endpoint
Write-Host ""
Write-Host "Testing health endpoint..." -ForegroundColor Blue
Start-Sleep -Seconds 10  # Give the service time to start
try {
    $healthResponse = Invoke-WebRequest -Uri "http://localhost:30080/health" -TimeoutSec 10 -ErrorAction Stop
    if ($healthResponse.StatusCode -eq 200) {
        Write-Host "✓ Health endpoint is responding" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Health endpoint returned status $($healthResponse.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "WARNING: Could not reach health endpoint - service may still be starting" -ForegroundColor Yellow
    Write-Host "Try accessing http://localhost:30080/health in a few minutes" -ForegroundColor White
}

# Test wallet endpoint if available
Write-Host "Testing wallet endpoint..." -ForegroundColor Blue
try {
    $walletResponse = Invoke-WebRequest -Uri "http://localhost:30080/wallet" -TimeoutSec 10 -ErrorAction Stop
    if ($walletResponse.StatusCode -eq 200) {
        Write-Host "✓ Wallet endpoint is responding" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Wallet endpoint returned status $($walletResponse.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "WARNING: Could not reach wallet endpoint - service may still be starting" -ForegroundColor Yellow
    Write-Host "Try accessing http://localhost:30080/wallet in a few minutes" -ForegroundColor White
}

Write-Host ""
Write-Host "=== Local Update Complete ===" -ForegroundColor Green
Write-Host "Your MXD deployment has been updated to the latest runtime version!" -ForegroundColor White
Write-Host ""
Write-Host "Access your updated MXD node:" -ForegroundColor Cyan
Write-Host "Health endpoint: http://localhost:30080/health" -ForegroundColor White
Write-Host "Metrics endpoint: http://localhost:30080/metrics" -ForegroundColor White
Write-Host "Wallet endpoint: http://localhost:30080/wallet" -ForegroundColor White
Write-Host "P2P port: localhost:30000" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "Check pod status: kubectl get pods -n mxd-$Environment" -ForegroundColor White
Write-Host "View logs: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host "Check rollout history: kubectl rollout history deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host "Rollback if needed: kubectl rollout undo deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host ""
Write-Host "Local deployment update completed successfully!" -ForegroundColor Green
