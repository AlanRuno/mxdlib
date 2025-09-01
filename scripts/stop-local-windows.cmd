@echo off
setlocal enabledelayedexpansion

REM MXD Library Local Kubernetes Stop Script for Windows (CMD)
REM This script stops the local MXD deployment by scaling to 0 replicas

REM Default parameters
set "Environment=local"
set "Force=false"

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="-Environment" (
    set "Environment=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-Force" (
    set "Force=true"
    shift
    goto :parse_args
)
shift
goto :parse_args

:args_done
echo === MXD Library Local Kubernetes Stop Script (Windows CMD) ===
echo Environment: %Environment%
echo.

REM Check prerequisites
echo Checking prerequisites...

kubectl version --client >nul 2>&1
if errorlevel 1 (
    echo ERROR: kubectl is not installed or not in PATH
    echo kubectl should be installed with Docker Desktop
    exit /b 1
)

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
    echo WARNING: No deployment found in namespace mxd-%Environment%
    echo Nothing to stop
    exit /b 0
)

echo Found deployment: mxd-enterprise-local

REM Get current deployment status
echo Current deployment status:
kubectl get deployment mxd-enterprise-local -n mxd-%Environment%
kubectl get pods -n mxd-%Environment%

if "%Force%"=="false" (
    echo.
    echo This will stop the MXD deployment by scaling to 0 replicas.
    echo The deployment and services will remain but no pods will be running.
    echo.
    set /p "confirmation=Continue with stop? (y/N): "
    if /i not "!confirmation!"=="y" (
        echo Stop cancelled
        exit /b 0
    )
)

REM Scale deployment to 0 replicas
echo.
echo Stopping MXD deployment...
kubectl scale deployment mxd-enterprise-local --replicas=0 -n mxd-%Environment%
if errorlevel 1 (
    echo ERROR: Failed to scale deployment to 0
    exit /b 1
)

echo Deployment scaled to 0 replicas

REM Wait for pods to terminate
echo Waiting for pods to terminate...
timeout /t 10 /nobreak >nul

REM Get final status
echo.
echo Final deployment status:
kubectl get deployment mxd-enterprise-local -n mxd-%Environment%
kubectl get pods -n mxd-%Environment%

echo.
echo === Local Stop Complete ===
echo Your MXD deployment has been stopped!
echo.
echo To restart the deployment:
echo   kubectl scale deployment mxd-enterprise-local --replicas=1 -n mxd-%Environment%
echo.
echo To completely remove the deployment:
echo   scripts\clean-local-windows.cmd -Environment %Environment%
echo.
echo Local deployment stopped successfully!
