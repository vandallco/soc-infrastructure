@echo off
REM ============================================================
REM   SOC Lab — Launcher (Windows)
REM   Doble click aqui para arrancar el laboratorio completo.
REM ============================================================
title SOC Lab Launcher

REM Ir al directorio del .bat (donde vive el .ps1)
cd /d "%~dp0"

REM Ejecutar el script PowerShell saltando la execution policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Start-SOC-Lab.ps1"

REM Si PowerShell termino con error, dejar la ventana abierta
if %ERRORLEVEL% NEQ 0 (
  echo.
  echo El launcher termino con codigo %ERRORLEVEL%
  pause
)
