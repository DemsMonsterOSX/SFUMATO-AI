<#
  Sfumato Autonomous SOC - one-command start (Windows PowerShell 5.1+ / PowerShell 7)
    .\start.ps1           LITE mode (default)
    .\start.ps1 -Full     FULL mode with OpenCTI (needs ~12-16 GB RAM free)
    .\start.ps1 -Llm      also start a containerised Ollama with GPU (NVIDIA)
    .\start.ps1 -Stop     stop everything (data volumes are kept)
#>
param([switch]$Full, [switch]$Llm, [switch]$Stop)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker Desktop is required: https://docs.docker.com/desktop/setup/install/windows-install/" -ForegroundColor Red; exit 1
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Docker Desktop is not running. Start it and retry." -ForegroundColor Red; exit 1 }

if ($Stop) { docker compose -f docker-compose.yml -f docker-compose.full.yml --profile llm down; exit 0 }

function New-Secret([int]$Length = 32) {
  $chars = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  $bytes = New-Object byte[] $Length
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}
function New-Base64Key { $b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }

if (-not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host "Created .env from .env.example" }
$lines = [System.Collections.Generic.List[string]](Get-Content .env -Encoding UTF8)
function Set-EnvValue([string]$Key, [string]$Value) {
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^$Key=(.*)$") {
      $cur = $Matches[1]
      if ($cur -eq "" -or $cur -like "*change-me*" -or $cur -like "change-this*" -or $cur -eq "sfumato-db-password") { $lines[$i] = "$Key=$Value" }
      return
    }
  }
  $lines.Add("$Key=$Value")
}
function Force-EnvValue([string]$Key, [string]$Value) {
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^$Key=") { $lines[$i] = "$Key=$Value"; return } }
  $lines.Add("$Key=$Value")
}

Set-EnvValue "API_KEYS" ("sfumato-" + (New-Secret 32))
Set-EnvValue "SECRET_KEY" (New-Secret 48)
Set-EnvValue "POSTGRES_PASSWORD" (New-Secret 24)
Set-EnvValue "ARTIFACT_SIGNING_KEY" (New-Secret 48)

$files = @("-f", "docker-compose.yml")
if ($Full) {
  Set-EnvValue "OPENCTI_ADMIN_PASSWORD" (New-Secret 20)
  Set-EnvValue "OPENCTI_ADMIN_TOKEN" ([guid]::NewGuid().ToString())
  Set-EnvValue "OPENCTI_ENCRYPTION_KEY" (New-Base64Key)
  Set-EnvValue "OPENCTI_HEALTH_KEY" ([guid]::NewGuid().ToString())
  Set-EnvValue "MINIO_ROOT_PASSWORD" (New-Secret 24)
  Set-EnvValue "RABBITMQ_DEFAULT_PASS" (New-Secret 24)
  Set-EnvValue "CONNECTOR_MITRE_ID" ([guid]::NewGuid().ToString())
  Set-EnvValue "CONNECTOR_CISA_KEV_ID" ([guid]::NewGuid().ToString())
  $files += @("-f", "docker-compose.full.yml")
  Write-Host "FULL mode: OpenCTI will be available at http://localhost:8080 (first start can take 5-10 minutes)."
}
$profileArgs = @()
if ($Llm) { $profileArgs = @("--profile", "llm"); Force-EnvValue "OLLAMA_URL" "http://ollama:11434" }

# UTF-8 without BOM so docker compose reads the first key correctly
[System.IO.File]::WriteAllLines((Join-Path $PSScriptRoot ".env"), $lines, (New-Object System.Text.UTF8Encoding($false)))

docker compose @files @profileArgs up -d --build
if ($LASTEXITCODE -ne 0) { Write-Host "docker compose failed - see the output above and TROUBLESHOOTING.md" -ForegroundColor Red; exit 1 }

function Wait-Url([string]$Url, [string]$Label, [int]$Tries = 90) {
  Write-Host -NoNewline "Waiting for $Label"
  for ($i = 0; $i -lt $Tries; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3 | Out-Null; Write-Host " ok"; return } catch { Write-Host -NoNewline "."; Start-Sleep -Seconds 2 }
  }
  Write-Host " (still starting - check: docker compose ps)"
}
Wait-Url "http://localhost:8000/api/v1/health" "the API"
Wait-Url "http://localhost:3000/" "the dashboard" 60

$key = (($lines | Where-Object { $_ -like "API_KEYS=*" }) -replace "^API_KEYS=", "").Split(",")[0]
Write-Host ""
Write-Host "  Sfumato Autonomous SOC is running" -ForegroundColor Cyan
Write-Host "  Dashboard   http://localhost:3000"
Write-Host "  API docs    http://localhost:8000/docs"
Write-Host "  API key     $key   (header X-API-Key)"
Write-Host ""
