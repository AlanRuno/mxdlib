# MXD Library Local Kubernetes Deployment for Windows
# This script sets up Kubernetes locally using Docker Desktop and deploys the MXD application

param(
    [Parameter(Mandatory=$true)]
    [string]$Environment = "local",
    
    [Parameter(Mandatory=$false)]
    [string]$ImageTag = "latest",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerCheck = $false
)

Write-Host "=== MXD Library Local Kubernetes Deployment (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "Image Tag: $ImageTag" -ForegroundColor Cyan
Write-Host "NOTE: This script requires Docker Desktop with Kubernetes enabled" -ForegroundColor Yellow
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

# Function to wait for user input
function Wait-UserInput {
    param($Message)
    Write-Host $Message -ForegroundColor Yellow
    Read-Host "Press Enter to continue or Ctrl+C to cancel"
}

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Blue

if (-not $SkipDockerCheck) {
    if (-not (Test-Command "docker")) {
        Write-Host "ERROR: Docker is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        Write-Host "Make sure to enable Kubernetes in Docker Desktop settings" -ForegroundColor Yellow
        exit 1
    }

    # Check if Docker is running
    docker version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
        exit 1
    }

    # Check if Kubernetes is enabled in Docker Desktop
    kubectl version --client 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: kubectl is not available" -ForegroundColor Red
        Write-Host "Please enable Kubernetes in Docker Desktop settings:" -ForegroundColor Yellow
        Write-Host "1. Open Docker Desktop" -ForegroundColor Yellow
        Write-Host "2. Go to Settings > Kubernetes" -ForegroundColor Yellow
        Write-Host "3. Check 'Enable Kubernetes'" -ForegroundColor Yellow
        Write-Host "4. Click 'Apply & Restart'" -ForegroundColor Yellow
        exit 1
    }
}

if (-not (Test-Command "kubectl")) {
    Write-Host "ERROR: kubectl is not installed or not in PATH" -ForegroundColor Red
    Write-Host "kubectl should be installed with Docker Desktop" -ForegroundColor Yellow
    Write-Host "If not available, download from: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Docker is available" -ForegroundColor Green
Write-Host "✓ kubectl is available" -ForegroundColor Green

# Check Kubernetes cluster status
Write-Host "Checking Kubernetes cluster status..." -ForegroundColor Blue
$clusterInfo = kubectl cluster-info 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Kubernetes cluster is running" -ForegroundColor Green
} else {
    Write-Host "ERROR: Kubernetes cluster is not accessible" -ForegroundColor Red
    Write-Host "Please ensure Kubernetes is enabled in Docker Desktop" -ForegroundColor Yellow
    exit 1
}

# Set kubectl context to docker-desktop
Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Could not set context to docker-desktop" -ForegroundColor Yellow
    Write-Host "Current context:" -ForegroundColor Yellow
    kubectl config current-context
}

# Build Docker image locally
Write-Host "Building MXD Docker image locally..." -ForegroundColor Blue
docker build -t "mxdlib:$ImageTag" .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Docker image" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Docker image built successfully" -ForegroundColor Green

# Create namespace
Write-Host "Creating Kubernetes namespace..." -ForegroundColor Blue
kubectl create namespace "mxd-$Environment" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Namespace mxd-$Environment created" -ForegroundColor Green
} else {
    Write-Host "✓ Namespace mxd-$Environment already exists" -ForegroundColor Yellow
}

# Create local storage class
Write-Host "Creating local storage class..." -ForegroundColor Blue
$storageClass = "apiVersion: storage.k8s.io/v1`nkind: StorageClass`nmetadata:`n  name: local-storage`nprovisioner: docker.io/hostpath`nparameters:`n  type: Directory`nreclaimPolicy: Delete`nvolumeBindingMode: Immediate"
$storageClass | kubectl apply -f -

# Create local deployment manifest
Write-Host "Creating local deployment manifest..." -ForegroundColor Blue

# Create deployment YAML without problematic here-strings
$deploymentYaml = @()
$deploymentYaml += "apiVersion: apps/v1"
$deploymentYaml += "kind: Deployment"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-enterprise-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "  labels:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "    environment: $Environment"
$deploymentYaml += "spec:"
$deploymentYaml += "  replicas: 1"
$deploymentYaml += "  selector:"
$deploymentYaml += "    matchLabels:"
$deploymentYaml += "      app: mxd-enterprise-local"
$deploymentYaml += "  template:"
$deploymentYaml += "    metadata:"
$deploymentYaml += "      labels:"
$deploymentYaml += "        app: mxd-enterprise-local"
$deploymentYaml += "        environment: $Environment"
$deploymentYaml += "      annotations:"
$deploymentYaml += "        prometheus.io/scrape: `"true`""
$deploymentYaml += "        prometheus.io/port: `"8080`""
$deploymentYaml += "        prometheus.io/path: `"/metrics`""
$deploymentYaml += "    spec:"
$deploymentYaml += "      containers:"
$deploymentYaml += "      - name: mxd-node"
$deploymentYaml += "        image: mxdlib:$ImageTag"
$deploymentYaml += "        imagePullPolicy: Never"
$deploymentYaml += "        ports:"
$deploymentYaml += "        - containerPort: 8000"
$deploymentYaml += "          name: p2p"
$deploymentYaml += "        - containerPort: 8080"
$deploymentYaml += "          name: metrics"
$deploymentYaml += "        env:"
$deploymentYaml += "        - name: MXD_NODE_ID"
$deploymentYaml += "          valueFrom:"
$deploymentYaml += "            fieldRef:"
$deploymentYaml += "              fieldPath: metadata.name"
$deploymentYaml += "        - name: MXD_NETWORK_MAGIC"
$deploymentYaml += "          value: `"0x4D584431`""
$deploymentYaml += "        - name: MXD_LOG_LEVEL"
$deploymentYaml += "          value: `"INFO`""
$deploymentYaml += "        - name: MXD_METRICS_PORT"
$deploymentYaml += "          value: `"8080`""
$deploymentYaml += "        - name: MXD_DATA_DIR"
$deploymentYaml += "          value: `"/opt/mxd/data`""
$deploymentYaml += "        - name: MXD_NETWORK_TYPE"
$deploymentYaml += "          value: `"testnet`""
$deploymentYaml += "        resources:"
$deploymentYaml += "          requests:"
$deploymentYaml += "            memory: `"512Mi`""
$deploymentYaml += "            cpu: `"250m`""
$deploymentYaml += "          limits:"
$deploymentYaml += "            memory: `"1Gi`""
$deploymentYaml += "            cpu: `"500m`""
$deploymentYaml += "        volumeMounts:"
$deploymentYaml += "        - name: data"
$deploymentYaml += "          mountPath: /opt/mxd/data"
$deploymentYaml += "        - name: config"
$deploymentYaml += "          mountPath: /opt/mxd/config"
$deploymentYaml += "        livenessProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 60"
$deploymentYaml += "          periodSeconds: 30"
$deploymentYaml += "        readinessProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 30"
$deploymentYaml += "          periodSeconds: 15"
$deploymentYaml += "        startupProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 30"
$deploymentYaml += "          periodSeconds: 10"
$deploymentYaml += "          failureThreshold: 30"
$deploymentYaml += "      volumes:"
$deploymentYaml += "      - name: data"
$deploymentYaml += "        persistentVolumeClaim:"
$deploymentYaml += "          claimName: mxd-data-local"
$deploymentYaml += "      - name: config"
$deploymentYaml += "        configMap:"
$deploymentYaml += "          name: mxd-config-local"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: Service"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-service-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "  labels:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "spec:"
$deploymentYaml += "  selector:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "  ports:"
$deploymentYaml += "  - name: p2p"
$deploymentYaml += "    port: 8000"
$deploymentYaml += "    targetPort: 8000"
$deploymentYaml += "    nodePort: 30000"
$deploymentYaml += "  - name: metrics"
$deploymentYaml += "    port: 8080"
$deploymentYaml += "    targetPort: 8080"
$deploymentYaml += "    nodePort: 30080"
$deploymentYaml += "  type: NodePort"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: PersistentVolumeClaim"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-data-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "spec:"
$deploymentYaml += "  accessModes:"
$deploymentYaml += "    - ReadWriteOnce"
$deploymentYaml += "  resources:"
$deploymentYaml += "    requests:"
$deploymentYaml += "      storage: 20Gi"
$deploymentYaml += "  storageClassName: hostpath"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: ConfigMap"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-config-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "data:"
$deploymentYaml += "  local.json: |"

# Create minimal JSON config to avoid parsing issues
$deploymentYaml += "    port: 8000"
$deploymentYaml += "    data_dir: /opt/mxd/data"
$deploymentYaml += "    network_type: testnet"
$deploymentYaml += "    metrics_port: 8080"
$deploymentYaml += "    log_level: INFO"

$deploymentManifest = $deploymentYaml -join "`n"

# Apply the deployment
Write-Host "Applying Kubernetes manifests..." -ForegroundColor Blue
$deploymentManifest | kubectl apply -f -
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to apply Kubernetes manifests" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Kubernetes manifests applied successfully" -ForegroundColor Green

# Wait for deployment to be ready
Write-Host "Waiting for deployment to be ready..." -ForegroundColor Blue
kubectl wait --for=condition=available --timeout=300s deployment/mxd-enterprise-local -n "mxd-$Environment"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Deployment did not become ready within 5 minutes" -ForegroundColor Yellow
    Write-Host "Check pod status with: kubectl get pods -n mxd-$Environment" -ForegroundColor Yellow
    Write-Host "Check pod logs with: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor Yellow
} else {
    Write-Host "✓ Deployment is ready" -ForegroundColor Green
}

# Get service information
Write-Host "Getting service information..." -ForegroundColor Blue
kubectl get services -n "mxd-$Environment"

# Get pod information
Write-Host "Getting pod information..." -ForegroundColor Blue
kubectl get pods -n "mxd-$Environment"

Write-Host ""
Write-Host "=== Local Deployment Complete ===" -ForegroundColor Green
Write-Host "Access your MXD node:" -ForegroundColor Cyan
Write-Host "Health endpoint: http://localhost:30080/health" -ForegroundColor White
Write-Host "Metrics endpoint: http://localhost:30080/metrics" -ForegroundColor White
Write-Host "P2P port: localhost:30000" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "Check pod status: kubectl get pods -n mxd-$Environment" -ForegroundColor White
Write-Host "View logs: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host "Scale deployment: kubectl scale deployment mxd-enterprise-local --replicas=2 -n mxd-$Environment" -ForegroundColor White
Write-Host "Delete deployment: kubectl delete namespace mxd-$Environment" -ForegroundColor White
Write-Host ""
Write-Host "Local deployment completed successfully!" -ForegroundColor Green
