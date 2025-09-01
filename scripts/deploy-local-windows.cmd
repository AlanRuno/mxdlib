@echo off
setlocal enabledelayedexpansion

REM MXD Library Local Kubernetes Deployment Script for Windows (CMD)
REM This script deploys MXD to a local Kubernetes cluster using Docker Desktop

REM Default parameters
set "Environment=local"
set "ImageTag=latest"
set "SkipDockerCheck=false"
set "Force=false"
set "SkipPortForward=false"

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="-Environment" (
    set "Environment=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-ImageTag" (
    set "ImageTag=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-SkipDockerCheck" (
    set "SkipDockerCheck=true"
    shift
    goto :parse_args
)
if /i "%~1"=="-Force" (
    set "Force=true"
    shift
    goto :parse_args
)
if /i "%~1"=="-SkipPortForward" (
    set "SkipPortForward=true"
    shift
    goto :parse_args
)
shift
goto :parse_args

:args_done
echo === MXD Library Local Kubernetes Deployment Script (Windows CMD) ===
echo Environment: %Environment%
echo Image Tag: %ImageTag%
if "%SkipPortForward%"=="true" (
    echo Port Forward: Disabled
) else (
    echo Port Forward: Enabled
)
echo.

REM Check prerequisites
echo Checking prerequisites...

if "%SkipDockerCheck%"=="false" (
    docker --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Docker is not installed or not in PATH
        echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/
        exit /b 1
    )

    REM Check if Docker is running
    docker version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Docker is not running
        echo Please start Docker Desktop and try again
        exit /b 1
    )
)

kubectl version --client >nul 2>&1
if errorlevel 1 (
    echo ERROR: kubectl is not installed or not in PATH
    echo kubectl should be installed with Docker Desktop
    exit /b 1
)

echo Docker is available
echo kubectl is available

REM Set kubectl context to docker-desktop
echo Setting kubectl context to docker-desktop...
kubectl config use-context docker-desktop
if errorlevel 1 (
    echo WARNING: Could not set context to docker-desktop
)

REM Check if deployment already exists
echo Checking for existing deployment...
kubectl get deployment mxd-enterprise-local -n mxd-%Environment% >nul 2>&1
if not errorlevel 1 (
    if "%Force%"=="false" (
        echo WARNING: Deployment mxd-enterprise-local already exists in namespace mxd-%Environment%
        echo Use -Force to redeploy or run update script instead
        set /p "confirmation=Continue with redeployment? (y/N): "
        if /i not "!confirmation!"=="y" (
            echo Deployment cancelled
            exit /b 0
        )
    )
    echo Removing existing deployment...
    kubectl delete deployment mxd-enterprise-local -n mxd-%Environment%
    kubectl delete service mxd-enterprise-local -n mxd-%Environment%
    kubectl delete configmap mxd-config-local -n mxd-%Environment%
)

REM Create namespace if it doesn't exist
echo Creating namespace mxd-%Environment%...
kubectl create namespace mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo Namespace mxd-%Environment% already exists
) else (
    echo Namespace mxd-%Environment% created
)

REM Build Docker image
echo.
echo Building MXD Docker image...
docker build -t mxdlib:%ImageTag% .
if errorlevel 1 (
    echo ERROR: Failed to build Docker image
    exit /b 1
)
echo Docker image built successfully

REM Create ConfigMap with correct filename
echo Creating ConfigMap...
kubectl create configmap mxd-config-local -n mxd-%Environment% --from-literal=default_config.json="{\"port\": 8000,\"data_dir\": \"/opt/mxd/data\",\"network_type\": \"testnet\",\"metrics_port\": 8080,\"log_level\": \"INFO\"}"
if errorlevel 1 (
    echo ERROR: Failed to create ConfigMap
    exit /b 1
)
echo ConfigMap created successfully

REM Create deployment YAML content
echo Creating deployment...
(
echo apiVersion: apps/v1
echo kind: Deployment
echo metadata:
echo   name: mxd-enterprise-local
echo   namespace: mxd-%Environment%
echo spec:
echo   replicas: 1
echo   selector:
echo     matchLabels:
echo       app: mxd-enterprise-local
echo   template:
echo     metadata:
echo       labels:
echo         app: mxd-enterprise-local
echo     spec:
echo       containers:
echo       - name: mxd-node
echo         image: mxdlib:%ImageTag%
echo         imagePullPolicy: Never
echo         ports:
echo         - containerPort: 8080
echo           name: metrics
echo         - containerPort: 8000
echo           name: p2p
echo         env:
echo         - name: MXD_METRICS_PORT
echo           value: "8080"
echo         volumeMounts:
echo         - name: config-volume
echo           mountPath: /opt/mxd/config
echo       volumes:
echo       - name: config-volume
echo         configMap:
echo           name: mxd-config-local
echo ---
echo apiVersion: v1
echo kind: Service
echo metadata:
echo   name: mxd-enterprise-local
echo   namespace: mxd-%Environment%
echo spec:
echo   type: NodePort
echo   ports:
echo   - port: 8080
echo     targetPort: 8080
echo     nodePort: 30080
echo     name: metrics
echo   - port: 8000
echo     targetPort: 8000
echo     nodePort: 30000
echo     name: p2p
echo   selector:
echo     app: mxd-enterprise-local
) > deployment-temp.yaml

kubectl apply -f deployment-temp.yaml
if errorlevel 1 (
    echo ERROR: Failed to create deployment
    del deployment-temp.yaml
    exit /b 1
)
del deployment-temp.yaml
echo Deployment created successfully

REM Wait for deployment to be ready
echo Waiting for deployment to be ready...
kubectl rollout status deployment/mxd-enterprise-local -n mxd-%Environment% --timeout=300s
if errorlevel 1 (
    echo WARNING: Deployment did not become ready within 5 minutes
    echo Check deployment status with: kubectl get pods -n mxd-%Environment%
) else (
    echo Deployment is ready
)

REM Get deployment information
echo.
echo Deployment status:
kubectl get deployment mxd-enterprise-local -n mxd-%Environment%
kubectl get pods -n mxd-%Environment%
kubectl get services -n mxd-%Environment%

REM Test health endpoint
echo.
echo Testing health endpoint...
timeout /t 10 /nobreak >nul
curl -s http://localhost:30080/health >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not reach health endpoint - service may still be starting
    echo Try accessing http://localhost:30080/health in a few minutes
) else (
    echo Health endpoint is responding
)

echo.
echo === Local Deployment Complete ===
echo Your MXD node is now running!
echo.
echo Access your MXD node:
echo   Health endpoint: http://localhost:30080/health
echo   Metrics endpoint: http://localhost:30080/metrics
echo   Wallet endpoint: http://localhost:30080/wallet
echo   P2P port: localhost:30000
echo.
echo Useful commands:
echo   Check pod status: kubectl get pods -n mxd-%Environment%
echo   View logs: kubectl logs -f deployment/mxd-enterprise-local -n mxd-%Environment%
echo   Port forward: kubectl port-forward deployment/mxd-enterprise-local 8081:8080 -n mxd-%Environment%
echo.
echo Local deployment completed successfully!
