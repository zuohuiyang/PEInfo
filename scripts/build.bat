@echo off
setlocal EnableExtensions

set ROOT=%~dp0..
pushd "%ROOT%" >nul
if %errorlevel% neq 0 exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
set EXITCODE=%errorlevel%

popd >nul
exit /b %EXITCODE%
