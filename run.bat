@echo off
title Network Packet Analyzer
cd /d "%~dp0"

echo ==========================================
echo       NETWORK PACKET ANALYZER
echo ==========================================
echo.
echo Starting application...
echo.

python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application failed to start.
    echo Check the error message above.
    pause
)