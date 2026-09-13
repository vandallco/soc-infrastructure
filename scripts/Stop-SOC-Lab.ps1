# ============================================================
#   SOC Lab - Stopper
#   Detiene todos los contenedores. Preserva volumenes (datos).
#   Usar -Nuke para borrarlos.
# ============================================================
param(
  [switch]$Nuke
)

$Host.UI.RawUI.WindowTitle = "SOC Lab Stopper"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DockerDir   = Join-Path $ProjectRoot 'docker'
$DockerExe   = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'

Clear-Host
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DETENIENDO SOC LAB" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $DockerDir

if ($Nuke) {
  Write-Host "  MODO NUKE - se borraran TODOS los volumenes (indices Splunk, DB TheHive/MISP, etc.)" -ForegroundColor Red
  $c = Read-Host "  Confirmar? Escribi 'BORRAR' para continuar"
  if ($c -ne 'BORRAR') { Write-Host "Cancelado"; exit }
  & $DockerExe compose down -v --remove-orphans
} else {
  Write-Host "  Deteniendo contenedores (los volumenes se preservan)..." -ForegroundColor White
  & $DockerExe compose down --remove-orphans
}

Write-Host ""
Write-Host "  [OK] SOC Lab detenido" -ForegroundColor Green
Write-Host ""
Write-Host "  Docker Desktop sigue corriendo. Para apagarlo tambien:" -ForegroundColor Gray
Write-Host "    click derecho en el icono de Docker en el system tray -> Quit Docker Desktop" -ForegroundColor Gray
Write-Host ""
Read-Host "  Enter para cerrar"
