@echo off
title CyberShield IR - Live Forensic Triage Tool
color 0B
cls

:: Ensure script runs in its own directory
cd /d "%~dp0"

echo.
echo ======================================================================
echo   CYBERSHIELD LIVE FORENSIC TRIAGE ^& COMPLIANCE DEMO
echo   Demonstration for Project Viva / Laboratory Examination
echo ======================================================================
echo.

python triage_cli.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Trying with py launcher...
    py triage_cli.py
)

echo.
pause
