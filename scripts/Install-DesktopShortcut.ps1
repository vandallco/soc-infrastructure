# ============================================================
#   Crea accesos directos en el Escritorio para el SOC Lab
#     - "SOC Lab (Start)"
#     - "SOC Lab (Stop)"
# ============================================================

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ScriptsDir  = Join-Path $ProjectRoot 'scripts'
$Desktop     = [Environment]::GetFolderPath('Desktop')

$shell = New-Object -ComObject WScript.Shell

function New-Shortcut($name, $target, $iconIndex) {
  $lnkPath = Join-Path $Desktop "$name.lnk"
  $lnk = $shell.CreateShortcut($lnkPath)
  $lnk.TargetPath       = $target
  $lnk.WorkingDirectory = $ScriptsDir
  $lnk.WindowStyle      = 1
  # Icon from imageres.dll (Windows built-in) — no external .ico needed
  $lnk.IconLocation     = "$env:SystemRoot\System32\imageres.dll,$iconIndex"
  $lnk.Description      = "SOC Lab - laboratorio de Security Operations Center"
  $lnk.Save()
  Write-Host "  [OK] Creado: $lnkPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Instalando accesos directos en el Escritorio..." -ForegroundColor Cyan
Write-Host ""

# Start icon
New-Shortcut -name "SOC Lab (Start)" -target (Join-Path $ScriptsDir 'Start-SOC-Lab.bat') -iconIndex 12
# Stop icon
New-Shortcut -name "SOC Lab (Stop)"  -target (Join-Path $ScriptsDir 'Stop-SOC-Lab.bat')  -iconIndex 100

Write-Host ""
Write-Host "Listo. Doble click en 'SOC Lab (Start)' desde el Escritorio." -ForegroundColor Green
Write-Host ""
