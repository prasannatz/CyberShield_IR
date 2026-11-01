@echo off
title CyberShield IR - Incident Response Platform
color 0A
cls

:: Ensure script runs in its own directory
cd /d "%~dp0"

echo.
echo ======================================================================
echo   CYBERSHIELD ENTERPRISE INCIDENT RESPONSE SYSTEM
echo   Corporate IT Edition
echo   Course Outcomes: CO2 (Triage) ^| CO4 (Containment) ^| CO5 (Forensics)
echo ======================================================================
echo.
echo  [1] Starting backend web and API server on port 8080...
echo  [2] Opening dashboard automatically in your browser...
echo.

:: Automatically open browser after 1 second
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8080/index.html"

:: Run Python server
python app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Python server could not start. Trying with py launcher...
    py app.py
)

pause
