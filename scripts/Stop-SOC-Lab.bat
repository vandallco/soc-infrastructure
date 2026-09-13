@echo off
title SOC Lab Stopper
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Stop-SOC-Lab.ps1"
if %ERRORLEVEL% NEQ 0 pause
