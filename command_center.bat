@echo off
title Command Centre
chcp 65001 >nul
cd /d "%~dp0"

if exist "%~dp0CommandCenter.exe" (
    "%~dp0CommandCenter.exe" %*
) else if exist "%~dp0MCS-CommandCenter.exe" (
    "%~dp0MCS-CommandCenter.exe" %*
) else (
    python command_center.py %*
)

if "%~1"=="" pause
