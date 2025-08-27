@echo off
REM MXD Node Port Forward Script for Windows (Batch)
REM Automatically detects and forwards port 8080 from MXD pod to localhost

setlocal enabledelayedexpansion

set NAMESPACE=default
set LOCAL_PORT=8080
set REMOTE_PORT=8080
set SERVICE_NAME=mxd-service
set DEPLOYMENT_NAME=mxd-node

echo === MXD Node Port Forward Setup ===
echo Checking kubectl availability...

REM Check if kubectl is available
kubectl version --client --short >nul 2>&1
if errorlevel 1 (
    echo X kubectl not found. Please install kubectl and ensure it's in your PATH.
    pause
    exit /b 1
)
echo + kubectl found

REM Check if connected to cluster
echo Checking cluster connection...
kubectl config current-context >nul 2>&1
if errorlevel 1 (
    echo X Not connected to any Kubernetes cluster. Please configure kubectl.
    pause
    exit /b 1
)
echo + Connected to cluster

REM Check for MXD pods
echo Looking for MXD pods...
kubectl get pods -n %NAMESPACE% -l app=mxd-node --no-headers >nul 2>&1
if errorlevel 1 (
    echo X No MXD pods found in namespace '%NAMESPACE%'
    echo Available pods:
    kubectl get pods -n %NAMESPACE%
    pause
    exit /b 1
)
echo + Found MXD pods

REM Start port forwarding
echo.
echo Starting port forward...
echo Local URL: http://localhost:%LOCAL_PORT%
echo Wallet UI: http://localhost:%LOCAL_PORT%/wallet
echo.
echo Press Ctrl+C to stop port forwarding
echo =================================

REM Try service first, then deployment
echo Attempting service port-forward...
kubectl port-forward service/%SERVICE_NAME% %LOCAL_PORT%:%REMOTE_PORT% -n %NAMESPACE%
if errorlevel 1 (
    echo Service port-forward failed, trying deployment...
    kubectl port-forward deployment/%DEPLOYMENT_NAME% %LOCAL_PORT%:%REMOTE_PORT% -n %NAMESPACE%
)

pause
