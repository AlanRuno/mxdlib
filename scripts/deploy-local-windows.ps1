# MXD Library Local Kubernetes Deployment for Windows

param(
    [Parameter(Mandatory=$false)]
    [string]$Environment = "local",

    [Parameter(Mandatory=$false)]
    [string]$ImageTag = "latest",

    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerCheck = $false,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPortForward = $false
)

Write-Host "=== MXD Library Local Kubernetes Deployment (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "Image Tag: $ImageTag" -ForegroundColor Cyan
Write-Host "Port Forward: $(if ($SkipPortForward) { 'Disabled' } else { 'Enabled' })" -ForegroundColor Cyan
Write-Host "NOTE: This script requires Docker Desktop with Kubernetes enabled" -ForegroundColor Yellow
Write-Host ""

function Test-Command {
    param($Command)
    $result = Get-Command $Command -ErrorAction SilentlyContinue
    return [bool]$result
}

function Start-PortForwardAndBrowser {
    param(
        [string]$Namespace,
        [int]$LocalPort = 8081,
        [int]$RemotePort = 8080,
        [string]$ServiceName = "mxd-service-local"
    )
    Write-Host "Setting up port forwarding..." -ForegroundColor Blue

    $portInUse = Get-NetTCPConnection -LocalPort $LocalPort -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Host "WARNING: Port $LocalPort is already in use" -ForegroundColor Yellow
        Write-Host "You can access via NodePort: http://localhost:30080/wallet" -ForegroundColor White
        return $false
    }

    $portForwardJob = Start-Job -Name "port-forward-$Namespace" -ScriptBlock {
        param($ns, $svc, $localPort, $remotePort)
        kubectl port-forward "svc/$svc" "$localPort`:$remotePort" -n $ns
    } -ArgumentList $Namespace, $ServiceName, $LocalPort, $RemotePort

    Start-Sleep -Seconds 5

    $maxAttempts = 6; $attempt = 0; $connected = $false
    while ($attempt -lt $maxAttempts -and -not $connected) {
        $attempt++
        try {
            $resp = Invoke-WebRequest -Uri "http://localhost:$LocalPort/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { $connected = $true }
        } catch { Start-Sleep -Seconds 3 }
    }

    if ($connected) {
        Write-Host "✓ Port forward established" -ForegroundColor Green
        Start-Process "http://localhost:$LocalPort/wallet"
        Write-Host "Health:  http://localhost:$LocalPort/health"  -ForegroundColor White
        Write-Host "Metrics: http://localhost:$LocalPort/metrics" -ForegroundColor White
        Write-Host "Stop PF:  Get-Job -Name port-forward-$Namespace | Stop-Job; Get-Job -Name port-forward-$Namespace | Remove-Job" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "WARNING: Could not establish port forward; use NodePort." -ForegroundColor Yellow
        Stop-Job $portForwardJob -ErrorAction SilentlyContinue
        Remove-Job $portForwardJob -ErrorAction SilentlyContinue
        return $false
    }
}

# Prereqs
Write-Host "Checking prerequisites..." -ForegroundColor Blue
if (-not $SkipDockerCheck) {
    if (-not (Test-Command "docker")) {
        Write-Host "ERROR: Docker not found in PATH" -ForegroundColor Red; exit 1
    }
    docker version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Docker not running" -ForegroundColor Red; exit 1 }
    kubectl version --client 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: kubectl not available" -ForegroundColor Red; exit 1 }
}
if (-not (Test-Command "kubectl")) { Write-Host "ERROR: kubectl not in PATH" -ForegroundColor Red; exit 1 }

Write-Host "Docker is available" -ForegroundColor Green
Write-Host "kubectl is available" -ForegroundColor Green

Write-Host "Checking Kubernetes cluster status..." -ForegroundColor Blue
kubectl cluster-info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Kubernetes cluster not accessible" -ForegroundColor Red; exit 1 }
Write-Host "Kubernetes cluster is running" -ForegroundColor Green

Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop | Out-Null

# Build image
Write-Host "Building MXD Docker image locally..." -ForegroundColor Blue
docker build -t "mxdlib:$ImageTag" .
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Docker build failed" -ForegroundColor Red; exit 1 }
Write-Host "Docker image built successfully" -ForegroundColor Green

# Namespace (idempotent)
kubectl create namespace "mxd-$Environment" 2>$null | Out-Null

# ===== Build YAML safely (single quotes everywhere; double quotes only where we interpolate) =====
$deploymentYaml = @()
$deploymentYaml += 'apiVersion: apps/v1'
$deploymentYaml += 'kind: Deployment'
$deploymentYaml += 'metadata:'
$deploymentYaml += '  name: mxd-enterprise-local'
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += '  labels:'
$deploymentYaml += '    app: mxd-enterprise-local'
$deploymentYaml += "    environment: $Environment"
$deploymentYaml += 'spec:'
$deploymentYaml += '  replicas: 1'
$deploymentYaml += '  selector:'
$deploymentYaml += '    matchLabels:'
$deploymentYaml += '      app: mxd-enterprise-local'
$deploymentYaml += '  template:'
$deploymentYaml += '    metadata:'
$deploymentYaml += '      labels:'
$deploymentYaml += '        app: mxd-enterprise-local'
$deploymentYaml += "        environment: $Environment"
$deploymentYaml += '      annotations:'
$deploymentYaml += '        prometheus.io/scrape: "true"'
$deploymentYaml += '        prometheus.io/port: "8080"'
$deploymentYaml += '        prometheus.io/path: "/metrics"'
$deploymentYaml += '    spec:'
$deploymentYaml += '      containers:'
$deploymentYaml += '      - name: mxd-node'
$deploymentYaml += "        image: mxdlib:$ImageTag"
$deploymentYaml += '        imagePullPolicy: IfNotPresent'
$deploymentYaml += '        ports:'
$deploymentYaml += '        - containerPort: 8000'
$deploymentYaml += '          name: p2p'
$deploymentYaml += '        - containerPort: 8080'
$deploymentYaml += '          name: metrics'
$deploymentYaml += '        env:'
$deploymentYaml += '        - name: MXD_NODE_ID'
$deploymentYaml += '          valueFrom:'
$deploymentYaml += '            fieldRef:'
$deploymentYaml += '              fieldPath: metadata.name'
$deploymentYaml += '        - name: MXD_NETWORK_MAGIC'
$deploymentYaml += '          value: "0x4D584431"'
$deploymentYaml += '        - name: MXD_LOG_LEVEL'
$deploymentYaml += '          value: "INFO"'
$deploymentYaml += '        - name: MXD_METRICS_PORT'
$deploymentYaml += '          value: "8080"'
$deploymentYaml += '        - name: MXD_DATA_DIR'
$deploymentYaml += '          value: "/opt/mxd/data"'
$deploymentYaml += '        - name: MXD_NETWORK_TYPE'
$deploymentYaml += '          value: "testnet"'
$deploymentYaml += '        resources:'
$deploymentYaml += '          requests:'
$deploymentYaml += '            memory: "512Mi"'
$deploymentYaml += '            cpu: "250m"'
$deploymentYaml += '          limits:'
$deploymentYaml += '            memory: "1Gi"'
$deploymentYaml += '            cpu: "500m"'
$deploymentYaml += '        volumeMounts:'
$deploymentYaml += '        - name: data'
$deploymentYaml += '          mountPath: /opt/mxd/data'
$deploymentYaml += '        - name: config'
$deploymentYaml += '          mountPath: /opt/mxd/config'
$deploymentYaml += '        livenessProbe:'
$deploymentYaml += '          httpGet:'
$deploymentYaml += '            path: /health'
$deploymentYaml += '            port: 8080'
$deploymentYaml += '          initialDelaySeconds: 60'
$deploymentYaml += '          periodSeconds: 30'
$deploymentYaml += '        readinessProbe:'
$deploymentYaml += '          httpGet:'
$deploymentYaml += '            path: /health'
$deploymentYaml += '            port: 8080'
$deploymentYaml += '          initialDelaySeconds: 30'
$deploymentYaml += '          periodSeconds: 15'
$deploymentYaml += '        startupProbe:'
$deploymentYaml += '          httpGet:'
$deploymentYaml += '            path: /health'
$deploymentYaml += '            port: 8080'
$deploymentYaml += '          initialDelaySeconds: 30'
$deploymentYaml += '          periodSeconds: 10'
$deploymentYaml += '          failureThreshold: 30'
$deploymentYaml += '      volumes:'
$deploymentYaml += '      - name: data'
$deploymentYaml += '        persistentVolumeClaim:'
$deploymentYaml += '          claimName: mxd-data-local'
$deploymentYaml += '      - name: config'
$deploymentYaml += '        configMap:'
$deploymentYaml += '          name: mxd-config-local'
$deploymentYaml += '---'
$deploymentYaml += 'apiVersion: v1'
$deploymentYaml += 'kind: Service'
$deploymentYaml += 'metadata:'
$deploymentYaml += '  name: mxd-service-local'
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += '  labels:'
$deploymentYaml += '    app: mxd-enterprise-local'
$deploymentYaml += 'spec:'
$deploymentYaml += '  selector:'
$deploymentYaml += '    app: mxd-enterprise-local'
$deploymentYaml += '  ports:'
$deploymentYaml += '  - name: p2p'
$deploymentYaml += '    port: 8000'
$deploymentYaml += '    targetPort: 8000'
$deploymentYaml += '    nodePort: 30000'
$deploymentYaml += '  - name: metrics'
$deploymentYaml += '    port: 8080'
$deploymentYaml += '    targetPort: 8080'
$deploymentYaml += '    nodePort: 30080'
$deploymentYaml += '  type: NodePort'
$deploymentYaml += '---'
$deploymentYaml += 'apiVersion: v1'
$deploymentYaml += 'kind: PersistentVolumeClaim'
$deploymentYaml += 'metadata:'
$deploymentYaml += '  name: mxd-data-local'
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += 'spec:'
$deploymentYaml += '  accessModes:'
$deploymentYaml += '    - ReadWriteOnce'
$deploymentYaml += '  resources:'
$deploymentYaml += '    requests:'
$deploymentYaml += '      storage: 20Gi'
$deploymentYaml += '  storageClassName: hostpath'
$deploymentYaml += '---'
$deploymentYaml += 'apiVersion: v1'
$deploymentYaml += 'kind: ConfigMap'
$deploymentYaml += 'metadata:'
$deploymentYaml += '  name: mxd-config-local'
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += 'data:'
$deploymentYaml += '  local.json: |'
$deploymentYaml += '    {'
$deploymentYaml += '      "port": 8000,'
$deploymentYaml += '      "data_dir": "/opt/mxd/data",'
$deploymentYaml += '      "network_type": "testnet",'
$deploymentYaml += '      "metrics_port": 8080,'
$deploymentYaml += '      "log_level": "INFO"'
$deploymentYaml += '    }'

$deploymentManifest = $deploymentYaml -join "`n"

Write-Host "Applying Kubernetes manifests..." -ForegroundColor Blue
$deploymentManifest | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Failed to apply manifests" -ForegroundColor Red; exit 1 }
Write-Host "Kubernetes manifests applied successfully" -ForegroundColor Green

Write-Host "Waiting for deployment to be ready..." -ForegroundColor Blue
kubectl wait --for=condition=available --timeout=300s deployment/mxd-enterprise-local -n "mxd-$Environment"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Deployment did not become ready within 5 minutes" -ForegroundColor Yellow
    Write-Host "Check: kubectl get pods -n mxd-$Environment" -ForegroundColor Yellow
    Write-Host "Logs:  kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor Yellow
} else {
    Write-Host "Deployment is ready" -ForegroundColor Green
}

Write-Host "Getting service information..." -ForegroundColor Blue
kubectl get services -n "mxd-$Environment" | Out-Host
Write-Host "Getting pod information..." -ForegroundColor Blue
kubectl get pods -n "mxd-$Environment" | Out-Host

Write-Host ""
Write-Host "=== Local Deployment Complete ===" -ForegroundColor Green

if (-not $SkipPortForward) {
    $ok = Start-PortForwardAndBrowser -Namespace "mxd-$Environment" -LocalPort 8081 -RemotePort 8080 -ServiceName "mxd-service-local"
    if (-not $ok) {
        Write-Host "Port forwarding failed, using NodePort access." -ForegroundColor Yellow
    }
} else {
    Write-Host "Port forwarding skipped. Access via NodePort:" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Access your MXD node:" -ForegroundColor Cyan
if (-not $SkipPortForward) {
    Write-Host "Preferred (Port Forward):" -ForegroundColor Green
    Write-Host "  Wallet:  http://localhost:8081/wallet"  -ForegroundColor White
    Write-Host "  Health:  http://localhost:8081/health"  -ForegroundColor White
    Write-Host "  Metrics: http://localhost:8081/metrics" -ForegroundColor White
    Write-Host "Alternative (NodePort):" -ForegroundColor Yellow
}
Write-Host "  Wallet:  http://localhost:30080/wallet"  -ForegroundColor White
Write-Host "  Health:  http://localhost:30080/health"  -ForegroundColor White
Write-Host "  Metrics: http://localhost:30080/metrics" -ForegroundColor White
Write-Host "  P2P:     localhost:30000"                -ForegroundColor White

Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "kubectl get pods -n mxd-$Environment" -ForegroundColor White
Write-Host "kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host "kubectl scale deployment mxd-enterprise-local --replicas=2 -n mxd-$Environment" -ForegroundColor White
Write-Host "kubectl delete namespace mxd-$Environment" -ForegroundColor White
Write-Host ""
Write-Host "Local deployment completed successfully!" -ForegroundColor Green
