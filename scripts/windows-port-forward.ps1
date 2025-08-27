# MXD Node Port Forward Script for Windows (PowerShell)
# Automatically detects and forwards port 8080 from MXD pod to localhost

param(
    [string]$Namespace = "default",
    [int]$LocalPort = 8080,
    [int]$RemotePort = 8080,
    [string]$ServiceName = "mxd-service",
    [string]$DeploymentName = "mxd-node"
)

Write-Host "=== MXD Node Port Forward Setup ===" -ForegroundColor Green
Write-Host "Checking kubectl availability..." -ForegroundColor Yellow

# Check if kubectl is available
try {
    $kubectlVersion = kubectl version --client --short 2>$null
    Write-Host "✓ kubectl found: $kubectlVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ kubectl not found. Please install kubectl and ensure it's in your PATH." -ForegroundColor Red
    exit 1
}

# Check if connected to cluster
Write-Host "Checking cluster connection..." -ForegroundColor Yellow
try {
    $context = kubectl config current-context 2>$null
    Write-Host "✓ Connected to cluster: $context" -ForegroundColor Green
} catch {
    Write-Host "✗ Not connected to any Kubernetes cluster. Please configure kubectl." -ForegroundColor Red
    exit 1
}

# Check for MXD pods
Write-Host "Looking for MXD pods..." -ForegroundColor Yellow
$pods = kubectl get pods -n $Namespace -l app=mxd-node --no-headers 2>$null

if (-not $pods) {
    Write-Host "✗ No MXD pods found in namespace '$Namespace'" -ForegroundColor Red
    Write-Host "Available pods:" -ForegroundColor Yellow
    kubectl get pods -n $Namespace
    exit 1
}

$runningPods = $pods | Where-Object { $_ -match "Running" }
if (-not $runningPods) {
    Write-Host "✗ No running MXD pods found" -ForegroundColor Red
    Write-Host "Pod status:" -ForegroundColor Yellow
    kubectl get pods -n $Namespace -l app=mxd-node
    exit 1
}

Write-Host "✓ Found running MXD pods" -ForegroundColor Green

# Check if port is already in use
Write-Host "Checking if port $LocalPort is available..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort $LocalPort -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "✗ Port $LocalPort is already in use" -ForegroundColor Red
    Write-Host "Please close the application using port $LocalPort or choose a different port" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Port $LocalPort is available" -ForegroundColor Green

# Start port forwarding
Write-Host "" -ForegroundColor White
Write-Host "Starting port forward..." -ForegroundColor Green
Write-Host "Local URL: http://localhost:$LocalPort" -ForegroundColor Cyan
Write-Host "Wallet UI: http://localhost:$LocalPort/wallet" -ForegroundColor Cyan
Write-Host "" -ForegroundColor White
Write-Host "Press Ctrl+C to stop port forwarding" -ForegroundColor Yellow
Write-Host "=================================" -ForegroundColor Green

# Try service first, then deployment
$forwardCommand = "kubectl port-forward service/$ServiceName $LocalPort`:$RemotePort -n $Namespace"
Write-Host "Attempting: $forwardCommand" -ForegroundColor Gray

try {
    Invoke-Expression $forwardCommand
} catch {
    Write-Host "Service port-forward failed, trying deployment..." -ForegroundColor Yellow
    $forwardCommand = "kubectl port-forward deployment/$DeploymentName $LocalPort`:$RemotePort -n $Namespace"
    Write-Host "Attempting: $forwardCommand" -ForegroundColor Gray
    Invoke-Expression $forwardCommand
}
