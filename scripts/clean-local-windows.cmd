@echo off
setlocal enabledelayedexpansion

REM MXD Library Local Kubernetes Clean Script for Windows (CMD)
REM This script removes all MXD resources from the local Kubernetes cluster

REM Default parameters
set "Environment=local"
set "Force=false"
set "RemoveImages=false"

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
if /i "%~1"=="-RemoveImages" (
    set "RemoveImages=true"
    shift
    goto :parse_args
)
shift
goto :parse_args

:args_done
echo === MXD Library Local Kubernetes Clean Script (Windows CMD) ===
echo Environment: %Environment%
if "%RemoveImages%"=="true" (
    echo Remove Images: Yes
) else (
    echo Remove Images: No
)
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

REM Check what exists
echo Checking existing resources...
kubectl get namespace mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo No namespace mxd-%Environment% found
    if "%RemoveImages%"=="true" (
        goto :remove_images
    ) else (
        echo Nothing to clean
        exit /b 0
    )
)

echo Found namespace: mxd-%Environment%
kubectl get all -n mxd-%Environment%

if "%Force%"=="false" (
    echo.
    echo This will remove ALL MXD resources from the local cluster:
    echo - Deployment: mxd-enterprise-local
    echo - Service: mxd-enterprise-local
    echo - ConfigMap: mxd-config-local
    echo - Namespace: mxd-%Environment%
    if "%RemoveImages%"=="true" (
        echo - Docker images: mxdlib:*
    )
    echo.
    set /p "confirmation=Continue with cleanup? (y/N): "
    if /i not "!confirmation!"=="y" (
        echo Cleanup cancelled
        exit /b 0
    )
)

REM Remove deployment
echo.
echo Removing deployment...
kubectl delete deployment mxd-enterprise-local -n mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo No deployment to remove
) else (
    echo Deployment removed
)

REM Remove service
echo Removing service...
kubectl delete service mxd-enterprise-local -n mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo No service to remove
) else (
    echo Service removed
)

REM Remove configmap
echo Removing configmap...
kubectl delete configmap mxd-config-local -n mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo No configmap to remove
) else (
    echo ConfigMap removed
)

REM Remove namespace
echo Removing namespace...
kubectl delete namespace mxd-%Environment% >nul 2>&1
if errorlevel 1 (
    echo No namespace to remove
) else (
    echo Namespace removed
)

:remove_images
if "%RemoveImages%"=="true" (
    echo.
    echo Removing Docker images...
    docker images mxdlib --format "table {{.Repository}}:{{.Tag}}" | findstr /v "REPOSITORY" > temp_images.txt
    for /f "tokens=*" %%i in (temp_images.txt) do (
        echo Removing image: %%i
        docker rmi %%i >nul 2>&1
    )
    del temp_images.txt >nul 2>&1
    echo Docker images removed
)

echo.
echo === Local Cleanup Complete ===
echo All MXD resources have been removed from the local cluster!
echo.
echo To redeploy:
echo   scripts\deploy-local-windows.cmd -Environment %Environment%
echo.
echo Local cleanup completed successfully!
