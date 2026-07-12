@echo off
title NullByte Tool - Installer
color 04

echo.
echo  ============================================================
echo   NULLBYTE PENETRATION TESTING TOOL - Windows Installer
echo  ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo  [*] Installing Python dependencies...
pip install -r requirements.txt

echo.
echo  [*] Checking Nmap...
where nmap >nul 2>&1
if errorlevel 1 (
    echo  [WARN] Nmap not found. Download from: https://nmap.org/download.html
    echo         After installing Nmap, run this tool again.
    echo.
) else (
    echo  [OK] Nmap found.
)

echo.
echo  ============================================================
echo   Installation complete! Run with:  python main.py
echo  ============================================================
echo.
pause
