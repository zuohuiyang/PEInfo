@echo off
setlocal ENABLEDELAYEDEXPANSION

set VSENV="C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"
set SOLUTION=PEInfo.sln

set PLATFORM=%1
if "%PLATFORM%"=="" set PLATFORM=Win32

set CONFIG=%2
if "%CONFIG%"=="" set CONFIG=Release

if /I "%PLATFORM%"=="x64" set VSENV="C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
echo 初始化 VS2022 环境：%VSENV%
call %VSENV%
if %errorlevel% neq 0 (
    echo 初始化 VS 环境失败
    exit /b 1
)

echo 清理解决方案：%SOLUTION% [%CONFIG%|%PLATFORM%]
msbuild %SOLUTION% /t:Clean /p:Configuration=%CONFIG% /p:Platform=%PLATFORM%
if %errorlevel% neq 0 (
    echo Clean 失败
    exit /b 1
)

echo 构建解决方案：%SOLUTION% [%CONFIG%|%PLATFORM%]
msbuild %SOLUTION% /m /p:Configuration=%CONFIG% /p:Platform=%PLATFORM%
if %errorlevel% neq 0 (
    echo Build 失败
    exit /b 1
)

set OUTDIR=%CONFIG%
if /I "%PLATFORM%"=="x64" set OUTDIR=x64\%CONFIG%
if /I "%PLATFORM%"=="Win32" set OUTDIR=%CONFIG%

set EXE_PATH=%CD%\%OUTDIR%\PEInfo.exe
set PDB_PATH=%CD%\%OUTDIR%\PEInfo.pdb

echo 打包构建产物到 dist\PEInfo_%PLATFORM%_%CONFIG%.zip
if not exist dist mkdir dist
if not exist dist\%PLATFORM% mkdir dist\%PLATFORM%
if not exist dist\%PLATFORM%\%CONFIG% mkdir dist\%PLATFORM%\%CONFIG%

copy /Y "%EXE_PATH" "dist\%PLATFORM%\%CONFIG%\PEInfo.exe" >nul
if exist "%PDB_PATH" copy /Y "%PDB_PATH" "dist\%PLATFORM%\%CONFIG%\vc143.pdb" >nul

tar -a -c -f "dist\PEInfo_%PLATFORM%_%CONFIG%.zip" -C "dist\%PLATFORM%\%CONFIG%" . >nul
if %errorlevel% neq 0 (
    echo 打包失败
    exit /b 1
)

echo 完成：构建与打包成功
exit /b 0
