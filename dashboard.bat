@echo off
title Live Dashboard
chcp 65001 >nul
cd /d "%~dp0"
if exist "%~dp0CommandCenter.exe" (
    "%~dp0CommandCenter.exe" dashboard
) else if exist "%~dp0MCS-CommandCenter.exe" (
    "%~dp0MCS-CommandCenter.exe" dashboard
) else (
    python dashboard.py
)
pause
