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
    try {
        Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
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
    try {
        docker version | Out-Null
    }
    catch {
        Write-Host "ERROR: Docker is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
        exit 1
    }

    # Check if Kubernetes is enabled in Docker Desktop
    try {
        kubectl version --client | Out-Null
    }
    catch {
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
try {
    $clusterInfo = kubectl cluster-info 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Kubernetes cluster is running" -ForegroundColor Green
    } else {
        throw "Cluster not accessible"
    }
} catch {
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
@"
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: docker.io/hostpath
parameters:
  type: Directory
reclaimPolicy: Delete
volumeBindingMode: Immediate
"@ | kubectl apply -f -

# Create local deployment manifest
Write-Host "Creating local deployment manifest..." -ForegroundColor Blue
$deploymentManifest = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mxd-enterprise-local
  namespace: mxd-$Environment
  labels:
    app: mxd-enterprise-local
    environment: $Environment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mxd-enterprise-local
  template:
    metadata:
      labels:
        app: mxd-enterprise-local
        environment: $Environment
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: mxd-node
        image: mxdlib:$ImageTag
        imagePullPolicy: Never
        ports:
        - containerPort: 8000
          name: p2p
        - containerPort: 8080
          name: metrics
        env:
        - name: MXD_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: MXD_NETWORK_MAGIC
          value: "0x4D584431"
        - name: MXD_LOG_LEVEL
          value: "INFO"
        - name: MXD_METRICS_PORT
          value: "8080"
        - name: MXD_DATA_DIR
          value: "/opt/mxd/data"
        - name: MXD_NETWORK_TYPE
          value: "testnet"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        volumeMounts:
        - name: data
          mountPath: /opt/mxd/data
        - name: config
          mountPath: /opt/mxd/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 15
        startupProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 30
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: mxd-data-local
      - name: config
        configMap:
          name: mxd-config-local
---
apiVersion: v1
kind: Service
metadata:
  name: mxd-service-local
  namespace: mxd-$Environment
  labels:
    app: mxd-enterprise-local
spec:
  selector:
    app: mxd-enterprise-local
  ports:
  - name: p2p
    port: 8000
    targetPort: 8000
    nodePort: 30000
  - name: metrics
    port: 8080
    targetPort: 8080
    nodePort: 30080
  type: NodePort
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mxd-data-local
  namespace: mxd-$Environment
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
  storageClassName: hostpath
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mxd-config-local
  namespace: mxd-$Environment
data:
  local.json: |
    {
      "node": {
        "port": 8000,
        "data_dir": "/opt/mxd/data",
        "max_peers": 20,
        "enable_upnp": false
      },
      "network": {
        "type": "testnet",
        "bootstrap_nodes": [
          "node1.mxd.network:8000"
        ],
        "network_magic": "0x4D584431"
      },
      "monitoring": {
        "enabled": true,
        "metrics_port": 8080,
        "health_check_interval": 30,
        "prometheus_enabled": true
      },
      "logging": {
        "level": "INFO",
        "structured": true,
        "output": "stdout"
      },
      "performance": {
        "worker_threads": 2,
        "io_threads": 2,
        "cache_size_mb": 256
      }
    }
"@

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
