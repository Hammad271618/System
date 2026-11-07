@echo off
title AutoLogin Build ^& Export Standalone Package
chcp 65001 >nul
cd /d "%~dp0"

echo ================================================================
echo             AUTOLOGIN - PORTABLE EXPORT BUILDER       
echo ================================================================
echo.
echo Installing PyInstaller and compiling standalone binaries...
echo This will produce a portable .ZIP distribution in dist\
echo.

python build_package.py %*

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Opening output directory in Explorer...
    if exist "%~dp0dist\AutoLogin-v1.0.zip" (
        explorer.exe /select,"%~dp0dist\AutoLogin-v1.0.zip"
    ) else if exist "%~dp0dist\MCS-AutoLogin-v1.0.zip" (
        explorer.exe /select,"%~dp0dist\MCS-AutoLogin-v1.0.zip"
    ) else (
        explorer.exe "%~dp0dist"
    )
) else (
    echo.
    echo [ERROR] Build encountered an error. Check output above.
)

pause
