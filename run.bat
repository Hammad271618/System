@echo off
title AutoLogin
cd /d "%~dp0"
echo ========================================================
echo             AutoLogin ^& Quota Rotator
echo ========================================================
if exist "%~dp0AutoLogin.exe" (
    start "" "%~dp0AutoLogin.exe"
) else if exist "%~dp0MCS-AutoLogin.exe" (
    start "" "%~dp0MCS-AutoLogin.exe"
) else (
    python main.py
)
pause

