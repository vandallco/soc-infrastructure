# ============================================================
#   SOC Lab - Launcher
#   Arranca Docker Desktop y despliega el stack en un click.
#
#   Uso:
#     - Doble click en Start-SOC-Lab.bat
#     - o: powershell -ExecutionPolicy Bypass -File .\Start-SOC-Lab.ps1
# ============================================================

$ErrorActionPreference = 'Continue'
$Host.UI.RawUI.WindowTitle = "SOC Lab Launcher"

# --- Config -------------------------------------------------
$ProjectRoot  = Split-Path -Parent $PSScriptRoot
$DockerDir    = Join-Path $ProjectRoot 'docker'
$DockerExe    = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$DockerApp    = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
$MaxWaitDaemonSeconds = 300
$MaxWaitSplunkSeconds = 240

# --- Helpers ------------------------------------------------
function Write-Banner($text, $color = 'Cyan') {
  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor $color
  Write-Host "  $text" -ForegroundColor $color
  Write-Host ("=" * 60) -ForegroundColor $color
}
function Write-Step($t) { Write-Host "  -> $t" -ForegroundColor White }
function Write-Ok($t)   { Write-Host "  [OK] $t"   -ForegroundColor Green }
function Write-Warn($t) { Write-Host "  [!]  $t"   -ForegroundColor Yellow }
function Write-Fail($t) { Write-Host "  [X]  $t"   -ForegroundColor Red }

function Test-DaemonReady {
  try {
    $v = & $DockerExe info --format '{{.ServerVersion}}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $v) { return $v }
  } catch {}
  return $null
}

function Repair-DockerSockets {
  $localAppData = $env:LOCALAPPDATA
  $ts = Get-Date -Format 'yyyyMMddHHmmss'
  $dirs = @()
  Get-ChildItem -Path $localAppData -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like '*docker*' } |
    ForEach-Object { $dirs += $_.FullName }
  if (Test-Path "$localAppData\Docker\run")            { $dirs += "$localAppData\Docker\run" }
  if (Test-Path "$localAppData\docker-secrets-engine") { $dirs += "$localAppData\docker-secrets-engine" }
  $dirs = $dirs | Sort-Object -Unique

  foreach ($d in $dirs) {
    $socks = Get-ChildItem -Path $d -Recurse -Include '*.sock','*.sock.stale' -ErrorAction SilentlyContinue -Force
    foreach ($s in $socks) {
      try {
        Remove-Item $s.FullName -Force -ErrorAction Stop
        Write-Ok "socket removed: $($s.Name)"
      } catch {
        $parent = $s.Directory.FullName
        $backup = "$parent.stale.$ts"
        if (-not (Test-Path $backup)) {
          try {
            Rename-Item $parent $backup -ErrorAction Stop
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            Write-Ok "folder renamed: $parent -> .stale.$ts"
          } catch {
            Write-Warn "cant clean $parent - may need Windows restart"
          }
        }
      }
    }
  }
}

# --- 0. Welcome ---------------------------------------------
Clear-Host
Write-Banner "SOC LAB LAUNCHER" 'Cyan'
Write-Host "  Proyecto: $ProjectRoot" -ForegroundColor Gray
Write-Host "  Hora    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# --- 1. Docker installed? -----------------------------------
Write-Banner "1. Verificando Docker Desktop"
if (-not (Test-Path $DockerApp)) {
  Write-Fail "Docker Desktop no encontrado en $DockerApp"
  Write-Host "  Instala con: winget install Docker.DockerDesktop" -ForegroundColor Yellow
  Read-Host "Enter para salir"
  exit 1
}
Write-Ok "Docker Desktop instalado"

# --- 2. Daemon status ---------------------------------------
Write-Banner "2. Estado del daemon"
$serverVer = Test-DaemonReady
if ($serverVer) {
  Write-Ok "Daemon ya activo (server $serverVer) - omitiendo arranque"
} else {
  Write-Step "Daemon apagado - lanzando Docker Desktop..."

  $sockGarbage = @()
  foreach ($p in @("$env:LOCALAPPDATA\Docker\run","$env:LOCALAPPDATA\docker-secrets-engine")) {
    if (Test-Path $p) {
      $sockGarbage += Get-ChildItem -Path $p -Include '*.sock','*.sock.stale' -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  if ($sockGarbage.Count -gt 0) {
    Write-Warn "Sockets huerfanos detectados ($($sockGarbage.Count)) - limpiando..."
    Get-Process -ErrorAction SilentlyContinue |
      Where-Object { $_.ProcessName -like '*docker*' -or $_.ProcessName -like '*vpnkit*' -or $_.ProcessName -eq 'wslservice' } |
      Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    wsl --shutdown 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    Repair-DockerSockets
  }

  Start-Process $DockerApp
  Write-Step "Esperando al daemon (hasta $MaxWaitDaemonSeconds s)..."

  $elapsed = 0
  $ready = $false
  while ($elapsed -lt $MaxWaitDaemonSeconds) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    $v = Test-DaemonReady
    if ($v) {
      Write-Host ""
      Write-Ok "Daemon listo tras ${elapsed}s (server $v)"
      $ready = $true
      break
    }
    Write-Host "." -NoNewline -ForegroundColor DarkGray
    if ($elapsed % 30 -eq 0) { Write-Host " ${elapsed}s" -ForegroundColor DarkGray }
  }
  if (-not $ready) {
    Write-Host ""
    Write-Fail "Docker Desktop no arranco en $MaxWaitDaemonSeconds segundos"
    Write-Host "  Sugerencias:" -ForegroundColor Yellow
    Write-Host "   - Abrir Docker Desktop manualmente y revisar el error" -ForegroundColor Yellow
    Write-Host "   - Reiniciar Windows si persiste" -ForegroundColor Yellow
    Read-Host "Enter para salir"
    exit 2
  }
}

# --- 3. .env file -------------------------------------------
Write-Banner "3. Configuracion del proyecto"
$envFile = Join-Path $DockerDir '.env'
if (-not (Test-Path $envFile)) {
  Write-Warn ".env no existe - creando con secretos aleatorios"
  $splunkPw   = 'Splunk-' + -join ((1..8)|ForEach-Object {[char](Get-Random -Min 97 -Max 122)}) + (Get-Random -Min 100 -Max 999) + '!'
  $hecToken   = [guid]::NewGuid().ToString()
  $hiveSecret = -join ((1..64)|ForEach-Object {'{0:x}' -f (Get-Random -Min 0 -Max 16)})
  $mispKey    = -join ((1..40)|ForEach-Object {'{0:x}' -f (Get-Random -Min 0 -Max 16)})
  $mispRoot   = -join ((1..16)|ForEach-Object {[char](Get-Random -Min 65 -Max 90)}) + '!'
  $mispUser   = -join ((1..16)|ForEach-Object {[char](Get-Random -Min 65 -Max 90)}) + '!'
  $mispAdmin  = -join ((1..12)|ForEach-Object {[char](Get-Random -Min 65 -Max 90)}) + '!'

  @"
SPLUNK_PASSWORD=$splunkPw
SPLUNK_HEC_TOKEN=$hecToken
THEHIVE_SECRET=$hiveSecret
CORTEX_API_KEY=REPLACE_AFTER_FIRST_LOGIN
MISP_MYSQL_ROOT_PASSWORD=$mispRoot
MISP_MYSQL_PASSWORD=$mispUser
MISP_ADMIN_EMAIL=admin@soc.lab
MISP_ADMIN_PASSWORD=$mispAdmin
MISP_ADMIN_KEY=$mispKey
LAB_DOMAIN=soc.lab
TIMEZONE=America/Bogota
"@ | Set-Content -Path $envFile -Encoding utf8
  Write-Ok ".env generado"
  Write-Host ""
  Write-Host "  Credenciales generadas (guardalas):" -ForegroundColor Yellow
  Write-Host "    Splunk admin       : $splunkPw"  -ForegroundColor White
  Write-Host "    MISP admin password: $mispAdmin" -ForegroundColor White
  Write-Host "    MISP admin key     : $mispKey"   -ForegroundColor White
} else {
  Write-Ok ".env existe"
}

# --- 4. Compose up ------------------------------------------
Write-Banner "4. Levantando contenedores"
Set-Location $DockerDir
Write-Step "docker compose up -d ..."
& $DockerExe compose up -d 2>&1 | ForEach-Object {
  $line = "$_"
  if ($line -match 'Error|failed') { Write-Fail $line }
  elseif ($line -match 'Started')  { Write-Ok $line.Trim() }
  else                             { Write-Host "    $line" -ForegroundColor DarkGray }
}

# --- 5. Health-check ----------------------------------------
Write-Banner "5. Health-check"
Start-Sleep -Seconds 6
Write-Step "Estado de contenedores:"
& $DockerExe ps --format 'table {{.Names}}\t{{.Status}}'

Write-Host ""
Write-Step "Esperando a Splunk Web (hasta $MaxWaitSplunkSeconds s)..."
$elapsed = 0
$splunkOk = $false
while ($elapsed -lt $MaxWaitSplunkSeconds) {
  Start-Sleep -Seconds 5
  $elapsed += 5
  try {
    $r = Invoke-WebRequest -Uri 'http://localhost:8000' -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
    if ($r.StatusCode -eq 200) {
      Write-Host ""
      Write-Ok "Splunk Web listo tras ${elapsed}s"
      $splunkOk = $true
      break
    }
  } catch {}
  Write-Host "." -NoNewline -ForegroundColor DarkGray
}
if (-not $splunkOk) {
  Write-Host ""
  Write-Warn "Splunk aun no responde - probablemente sigue inicializando"
}

# --- 6. Info --------------------------------------------------
Write-Banner "SOC LAB LISTO" 'Green'

Write-Host ""
Write-Host "  URLs de acceso:" -ForegroundColor White
Write-Host "    Splunk    -> http://localhost:8000"   -ForegroundColor Cyan
Write-Host "    TheHive   -> http://localhost:9000"   -ForegroundColor Cyan
Write-Host "    Cortex    -> http://localhost:9001"   -ForegroundColor Cyan
Write-Host "    MISP      -> https://localhost:8443  (HTTPS, aceptar cert autofirmado)" -ForegroundColor Cyan
Write-Host "    DVWA      -> http://localhost:8080"   -ForegroundColor Cyan
Write-Host ""
Write-Host "  Credenciales en: $envFile" -ForegroundColor Gray

Write-Host ""
$openBrowser = Read-Host "  Abrir Splunk en el navegador ahora? [Y/n]"
if ($openBrowser -eq '' -or $openBrowser -match '^[yY]') {
  Start-Process 'http://localhost:8000'
}

Write-Host ""
Write-Host "  Para detener el lab: doble click en Stop-SOC-Lab.bat" -ForegroundColor Gray
Write-Host ""
Read-Host "  Enter para cerrar esta ventana"
