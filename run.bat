@echo off
title MCS Fortinet Auto-Login
cd /d "%~dp0"
echo ========================================================
echo        MCS Fortinet Auto-Login ^& Quota Rotator
echo ========================================================
if exist "%~dp0MCS-AutoLogin.exe" (
    start "" "%~dp0MCS-AutoLogin.exe"
) else (
    python main.py
)
pause

