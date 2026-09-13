@echo off
title Install SOC Lab Desktop Shortcuts
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Install-DesktopShortcut.ps1"
pause
