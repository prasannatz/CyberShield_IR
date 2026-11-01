@echo off
title Push CyberShield IR to GitHub
color 0A
cls

cd /d "%~dp0"

echo ======================================================================
echo   CYBERSHIELD IR - GITHUB PUSH WIZARD
echo ======================================================================
echo.
echo Make sure you have created an empty repository on GitHub first!
echo (e.g. https://github.com/prasannatz/CyberShield_IR)
echo.
set /p REPO_URL="https://github.com/prasannatz/CyberShield_IR.git "

if "%REPO_URL%"=="" (
    echo [!] No URL provided. Aborted.
    pause
    exit /b
)

echo.
echo [*] Adding remote origin...
git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%

echo [*] Renaming branch to main...
git branch -M main

echo [*] Pushing to GitHub...
git push -u origin main

echo.
if %ERRORLEVEL% EQU 0 (
    echo [OK] Code successfully pushed to GitHub!
    echo.
    echo Next Steps to enable GitHub Pages:
    echo 1. Go to your repository on GitHub.com
    echo 2. Click "Settings" (top right of repo)
    echo 3. In left sidebar, click "Pages"
    echo 4. Under "Build and deployment" ^> Branch, select "main" and "/ (root)"
    echo 5. Click "Save"
    echo.
    echo Your dashboard will be live online in ~60 seconds!
) else (
    echo [!] Push failed. Please check your credentials or repo permissions.
)

echo.
pause

