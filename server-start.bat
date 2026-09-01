@echo off
setlocal enabledelayedexpansion

:: simtrace2-pysniff-server startup script for Windows
::
:: Usage: server-start.bat [--capture gsmtap|direct] [--port PORT] [--db PATH] [--gsmtap-port PORT]
::
:: Options set via environment variables act as defaults; CLI flags override them.

set "CAPTURE=%CAPTURE%"
if "%CAPTURE%"=="" set "CAPTURE=gsmtap"
set "PORT=%PORT%"
if "%PORT%"=="" set "PORT=8081"
set "DB=%DB%"
set "GSMTAP_PORT=%GSMTAP_PORT%"
if "%GSMTAP_PORT%"=="" set "GSMTAP_PORT=4729"
set "EXTRA_ARGS="

:parse_args
if "%~1"=="" goto :run
if "%~1"=="--capture" (
    set "CAPTURE=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--port" (
    set "PORT=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--db" (
    set "DB=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--gsmtap-port" (
    set "GSMTAP_PORT=%~2"
    shift
    shift
    goto :parse_args
)
set "EXTRA_ARGS=!EXTRA_ARGS! %~1"
shift
goto :parse_args

:run
echo Starting simtrace2-pysniff-server...
echo PWA (simtrace-analyser) will be served at http://127.0.0.1:%PORT%/

set "PYTHONPATH=%~dp0"
python -m simtrace2_pysniff.server --capture %CAPTURE% --port %PORT% --gsmtap-port %GSMTAP_PORT% %EXTRA_ARGS%
