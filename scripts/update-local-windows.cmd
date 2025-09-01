@echo off
setlocal enabledelayedexpansion

REM MXD Library Local Kubernetes Update Script for Windows (CMD)
REM This script updates an existing local MXD deployment to the latest runtime version

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
echo === MXD Library Local Kubernetes Update Script (Windows CMD) ===
echo Environment: %Environment%
echo Image Tag: %ImageTag%
if "%SkipPortForward%"=="true" (
    echo Port Forward: Disabled
) else (
    echo Port Forward: Enabled
)
echo NOTE: This script updates an existing deployment to the latest runtime version
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

REM Check if deployment exists
echo Checking existing deployment...
kubectl get deployment mxd-enterprise-local -n mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo ERROR: No existing deployment found in namespace mxd-%Environment%
    echo Please run the deploy script first:
    echo   scripts\deploy-local-windows.cmd -Environment %Environment%
    exit /b 1
)

echo Found existing deployment: mxd-enterprise-local

REM Get current deployment status
echo Current deployment status:
kubectl get deployment mxd-enterprise-local -n mxd-%Environment%
kubectl get pods -n mxd-%Environment%

if "%Force%"=="false" (
    echo.
    echo This will update the deployment to use the latest runtime version.
    echo The update process will:
    echo 1. Rebuild the Docker image with latest code
    echo 2. Update the Kubernetes deployment
    echo 3. Perform a rolling update of running pods
    echo 4. Wait for the new pods to be ready
    echo.
    set /p "confirmation=Continue with update? (y/N): "
    if /i not "!confirmation!"=="y" (
        echo Update cancelled
        exit /b 0
    )
)

REM Build updated Docker image
echo.
echo Building updated MXD Docker image...
docker build -t mxdlib:%ImageTag% .
if errorlevel 1 (
    echo ERROR: Failed to build updated Docker image
    exit /b 1
)
echo Docker image built successfully

REM Verify the updated image
echo Verifying updated Docker image...
docker images mxdlib:%ImageTag%
if errorlevel 1 (
    echo ERROR: Updated Docker image not found after build
    exit /b 1
)

REM Force Kubernetes to pull the updated image by restarting the deployment
echo Updating Kubernetes deployment...
kubectl rollout restart deployment/mxd-enterprise-local -n mxd-%Environment%
if errorlevel 1 (
    echo ERROR: Failed to restart deployment
    exit /b 1
)

echo Deployment restart initiated

REM Wait for rollout to complete
echo Waiting for rollout to complete...
kubectl rollout status deployment/mxd-enterprise-local -n mxd-%Environment% --timeout=300s
if errorlevel 1 (
    echo WARNING: Rollout did not complete within 5 minutes
    echo Check deployment status with: kubectl get pods -n mxd-%Environment%
    echo Check pod logs with: kubectl logs -f deployment/mxd-enterprise-local -n mxd-%Environment%
) else (
    echo Rollout completed successfully
)

REM Get updated deployment information
echo.
echo Updated deployment status:
kubectl get deployment mxd-enterprise-local -n mxd-%Environment%
kubectl get pods -n mxd-%Environment%

REM Get service information
echo.
echo Service endpoints:
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

REM Test wallet endpoint if available
echo Testing wallet endpoint...
curl -s http://localhost:30080/wallet >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not reach wallet endpoint - service may still be starting
    echo Try accessing http://localhost:30080/wallet in a few minutes
) else (
    echo Wallet endpoint is responding
)

echo.
echo === Local Update Complete ===
echo Your MXD deployment has been updated to the latest runtime version!
echo.
echo Access your updated MXD node:
echo   Health endpoint: http://localhost:30080/health
echo   Metrics endpoint: http://localhost:30080/metrics
echo   Wallet endpoint: http://localhost:30080/wallet
echo   P2P port: localhost:30000
echo.
echo Useful commands:
echo   Check pod status: kubectl get pods -n mxd-%Environment%
echo   View logs: kubectl logs -f deployment/mxd-enterprise-local -n mxd-%Environment%
echo   Check rollout history: kubectl rollout history deployment/mxd-enterprise-local -n mxd-%Environment%
echo   Rollback if needed: kubectl rollout undo deployment/mxd-enterprise-local -n mxd-%Environment%
echo   Port forward: kubectl port-forward deployment/mxd-enterprise-local 8081:8080 -n mxd-%Environment%
echo.
echo Local deployment update completed successfully!
