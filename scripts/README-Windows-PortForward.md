# Windows Port Forward Scripts for MXD Node

These scripts automatically set up port forwarding from your local Windows machine to the MXD node running in Kubernetes pods.

## Files

- `windows-port-forward.ps1` - PowerShell script (recommended)
- `windows-port-forward.bat` - Batch script (fallback)

## Prerequisites

1. **kubectl installed** and configured to connect to your cluster
2. **MXD node deployed** in Kubernetes with label `app=mxd-node`
3. **Port 8080 available** on your local machine

## Usage

### PowerShell Script (Recommended)

```powershell
# Basic usage
.\windows-port-forward.ps1

# Custom parameters
.\windows-port-forward.ps1 -Namespace "mxd-production" -LocalPort 8081
```

### Batch Script

```cmd
# Double-click the file or run from command prompt
windows-port-forward.bat
```

## Parameters (PowerShell only)

- `-Namespace` - Kubernetes namespace (default: "default")
- `-LocalPort` - Local port to forward to (default: 8080)
- `-RemotePort` - Remote pod port (default: 8080)
- `-ServiceName` - Service name to forward (default: "mxd-service")
- `-DeploymentName` - Deployment name fallback (default: "mxd-node")

## What the Scripts Do

1. **Check kubectl** - Verify kubectl is installed and connected
2. **Find MXD pods** - Locate running MXD node pods
3. **Check port availability** - Ensure local port is free
4. **Start port forwarding** - Create tunnel to pod
5. **Display URLs** - Show local access URLs

## Access URLs (after port forward starts)

- **Health Check**: `http://localhost:8080/health`
- **Wallet Interface**: `http://localhost:8080/wallet`
- **Metrics**: `http://localhost:8080/metrics`

## Troubleshooting

### "kubectl not found"
- Install kubectl: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
- Add kubectl to your PATH

### "Not connected to cluster"
- Configure kubectl: `kubectl config set-context`
- Verify connection: `kubectl get nodes`

### "No MXD pods found"
- Check namespace: `kubectl get pods -n <namespace>`
- Verify deployment: `kubectl get deployments`

### "Port already in use"
- Close application using port 8080
- Use different port: `-LocalPort 8081`

### "Service port-forward failed"
- Script automatically tries deployment fallback
- Check service exists: `kubectl get services`

## Manual Commands

If scripts fail, use these manual commands:

```cmd
# Port forward via service
kubectl port-forward service/mxd-service 8080:8080

# Port forward via deployment
kubectl port-forward deployment/mxd-node 8080:8080

# Port forward via specific pod
kubectl port-forward pod/<pod-name> 8080:8080
```

## Security Notes

- Port forwarding creates a local tunnel only
- No external access is exposed
- Stop with Ctrl+C when done
- Only forwards to your local machine
