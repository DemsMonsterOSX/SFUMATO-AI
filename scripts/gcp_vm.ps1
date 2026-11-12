<#
 Sfumato on Google Cloud, plug and play: one free-tier VM (e2-micro by default) running the API, worker, dashboard and
 an HTTPS reverse proxy with a team login. Gemini is used for the AI report when a key is entered in Settings.
 Idempotent. ASCII only (PowerShell 5.1).

   .\scripts\gcp_vm.ps1 up                  create or update everything, then print the URL and the team password
   .\scripts\gcp_vm.ps1 update              rebuild the package and redeploy (data is kept)
   .\scripts\gcp_vm.ps1 status | url | logs
   .\scripts\gcp_vm.ps1 team-add -User bob  add a team account (password printed once); applies on next update
   .\scripts\gcp_vm.ps1 team-remove -User bob
   .\scripts\gcp_vm.ps1 teardown            delete VM, IP, firewall rule (the bucket is kept)
 Prerequisites: scripts\gcp_setup.ps1 already ran (bucket + sfumato-reader), gcloud logged in.
#>
param(
  [ValidateSet("up", "update", "status", "url", "logs", "team-add", "team-remove", "teardown")][string]$Action = "status",
  [string]$Project = "",
  [string]$Zone = "us-central1-a",
  [string]$MachineType = "e2-micro",
  [string]$User = "",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
$vm = "sfumato"; $ipName = "sfumato-ip"; $fw = "sfumato-web"
$region = $Zone.Substring(0, $Zone.LastIndexOf("-"))
$secretsDir = Join-Path $root "secrets"; New-Item -ItemType Directory -Force $secretsDir | Out-Null
$vmEnv = Join-Path $secretsDir "gcp-vm.env"
$teamFile = Join-Path $secretsDir "gcp-team.caddy"
$startup = Join-Path $root "deploy\gcp\vm-startup.sh"

function GCmd { $o = & gcloud @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }
function RandHex($n) { $b = New-Object byte[] $n; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }
function EnvGet($file, $k) { if (Test-Path $file) { foreach ($l in Get-Content $file) { if ($l -match "^$k=(.*)$") { return $Matches[1] } } }; return "" }

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"
  if (Test-Path $p) { $env:Path += ";$p" } else { Fail "gcloud not found" }
}
if (-not (GCmd auth list --filter=status:ACTIVE "--format=value(account)")) { Fail "Not logged in: gcloud auth login" }
if (-not $Project) { $Project = GCmd config get-value project }
if (-not $Project -or $Project -match "unset") { Fail "No project (gcloud config set project ID, or -Project)" }
$uri = EnvGet (Join-Path $root ".env") "ML_ARTIFACT_URI"
if ($uri -notmatch '^gs://([^/]+)') { Fail "ML_ARTIFACT_URI missing in .env: run scripts\gcp_setup.ps1 first" }
$bucket = $Matches[1]
$reader = "sfumato-reader@$Project.iam.gserviceaccount.com"

function Get-Ip { return (GCmd compute addresses describe $ipName "--region=$region" "--project=$Project" "--format=value(address)") }
function Get-Url { $ip = Get-Ip; if ($ip -match '^\d+\.\d+\.\d+\.\d+$') { return "https://" + ($ip -replace '\.', '-') + ".sslip.io" } else { return "(no IP yet)" } }
function Serial { return (GCmd compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project") }
function TeamPy { & $py (Join-Path $root "deploy\gcp\team.py") @args }

function Ensure-Team {
  $state = Join-Path $secretsDir "gcp-team.json"
  if (-not (Test-Path $state) -or ((Get-Content $state -Raw).Trim() -in @("", "{}"))) {
    $r = TeamPy add admin
    Add-Content -Path (Join-Path $secretsDir "gcp-team-credentials.txt") -Value $r -Encoding ASCII
    Write-Host "First team account created (also saved, git-ignored, in secrets\gcp-team-credentials.txt):" -ForegroundColor Yellow
    Write-Host "  user / password : $r" -ForegroundColor Yellow
  } else { $null = TeamPy list }
}

function Ensure-VmEnv {
  if (Test-Path $vmEnv) { return }
  $signing = EnvGet (Join-Path $root ".env") "ARTIFACT_SIGNING_KEY"
  @(
    "# Production settings of the GCP VM (git-ignored). Edit, then: .\scripts\gcp_vm.ps1 update",
    "ENVIRONMENT=production",
    "API_KEYS=$(RandHex 24)",
    "SECRET_KEY=$(RandHex 32)",
    "CTI_MODE=demo",
    "SEED_DEMO_INCIDENTS=true",
    "ML_ARTIFACT_URI=gs://$bucket/sfumato",
    "KB_ARTIFACT_URI=gs://$bucket/sfumato",
    "ARTIFACT_SIGNING_KEY=$signing",
    "# Gemini free tier through its OpenAI-compatible endpoint. Enter the key in the dashboard (Settings).",
    "# Until a key exists the report silently falls back to the deterministic investigator.",
    "# Free-tier prompts may be used by Google to improve its products: demo/synthetic incidents only.",
    "AI_PROVIDER=openai",
    "AI_ALLOW_EXTERNAL=true",
    "OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai",
    "OPENAI_MODEL=gemini-3.5-flash-lite"
  ) | Set-Content -Path $vmEnv -Encoding ASCII
  Write-Host "Created $vmEnv (fresh API key and secret, not the local ones)"
}

function Build-And-Upload {
  Step "Build the package"
  & $py (Join-Path $root "deploy\gcp\build_package.py")
  if ($LASTEXITCODE -ne 0) { Fail "package build failed" }
  $meta = Get-Content (Join-Path $root "dist\package.json") -Raw | ConvertFrom-Json
  $script:pkgSha = $meta.sha256
  $script:pkgObj = "deploy/sfumato-$($meta.sha256.Substring(0,12)).tar.gz"
  Step "Upload to gs://$bucket/$($script:pkgObj)"
  $o = GCmd storage cp (Join-Path $root "dist\sfumato-deploy.tar.gz") "gs://$bucket/$($script:pkgObj)" "--project=$Project"
  if ($rc -ne 0) { Fail "upload failed: $o" }
}

$script:rev = [string][int][double]::Parse((Get-Date -UFormat %s))
function MetaPlain { return "--metadata=sfumato-bucket=$bucket,sfumato-package=$($script:pkgObj),sfumato-package-sha256=$($script:pkgSha),sfumato-rev=$($script:rev)" }
function MetaFiles { return "--metadata-from-file=startup-script=$startup,sfumato-env=$vmEnv,sfumato-team=$teamFile" }

switch ($Action) {
  { $_ -in "up", "update" } {
    Ensure-VmEnv; Ensure-Team
    $null = GCmd compute instances describe $vm "--zone=$Zone" "--project=$Project"
    $vmExists = ($rc -eq 0)
    Write-Host "Project $Project | zone $Zone | $MachineType | bucket gs://$bucket | VM exists: $vmExists"
    if (-not $vmExists -and -not $Yes) { $a = Read-Host "Create the VM, a static IP and a firewall rule for 80/443? (y/N)"; if ($a -notmatch '^[yY]') { Fail "Cancelled." } }
    Build-And-Upload
    if (-not $vmExists) {
      Step "Static IP and firewall"
      $null = GCmd compute addresses describe $ipName "--region=$region" "--project=$Project"
      if ($rc -ne 0) { $o = GCmd compute addresses create $ipName "--region=$region" "--project=$Project"; if ($rc -ne 0) { Fail $o } }
      $null = GCmd compute firewall-rules describe $fw "--project=$Project"
      if ($rc -ne 0) {
        $o = GCmd compute firewall-rules create $fw "--project=$Project" --network=default --direction=INGRESS "--allow=tcp:80,tcp:443" "--target-tags=$fw" "--source-ranges=0.0.0.0/0"
        if ($rc -ne 0) { Fail $o }
      }
      Step "Create the VM"
      $o = GCmd compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" `
        --image-family=debian-13 --image-project=debian-cloud --boot-disk-size=30GB --boot-disk-type=pd-standard `
        "--service-account=$reader" --scopes=storage-ro "--tags=$fw" "--address=$ipName" --shielded-secure-boot `
        (MetaPlain) (MetaFiles)
      if ($rc -ne 0) { Fail "VM creation failed: $o" } else { Write-Host $o }
    } else {
      Step "Update the VM metadata and restart it (disk and data are kept)"
      $o = GCmd compute instances add-metadata $vm "--zone=$Zone" "--project=$Project" (MetaPlain) (MetaFiles)
      if ($rc -ne 0) { Fail $o }
      $null = GCmd compute instances reset $vm "--zone=$Zone" "--project=$Project"
    }
    Step "Waiting for the first boot (packages and Python dependencies: 5 to 15 minutes on an e2-micro)"
    $deadline = (Get-Date).AddMinutes(30); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial
      if ($s -match "SFUMATO_FAILED REV=$($script:rev)[^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; Write-Host "See: .\scripts\gcp_vm.ps1 logs"; exit 1 }
      if ($s -match "SFUMATO_READY REV=$($script:rev) ") { $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 30 minutes: .\scripts\gcp_vm.ps1 logs"; exit 1 }
    Write-Host "`n`nReady: $(Get-Url)" -ForegroundColor Green
    Write-Host "Login: a team account (secrets\gcp-team-credentials.txt for the first one). Then Settings > OpenAI-compatible key = your Gemini key."
  }
  "status" {
    Write-Host (GCmd compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(status,machineType.basename())")
    Write-Host "URL: $(Get-Url)"
    $s = Serial; if ($s -match "SFUMATO_READY[^\r\n]*") { Write-Host $Matches[0] } elseif ($s -match "SFUMATO_FAILED[^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red }
  }
  "url" { Write-Host (Get-Url) }
  "logs" { (Serial) -split "`n" | Select-String -Pattern "sfumato|SFUMATO|startup-script|rror" | Select-Object -Last 80 | ForEach-Object { $_.Line } }
  "team-add" {
    if (-not $User) { Fail "-User NAME required" }
    $r = TeamPy add $User
    Add-Content -Path (Join-Path $secretsDir "gcp-team-credentials.txt") -Value $r -Encoding ASCII
    Write-Host "user / password (shown once, also saved in secrets\gcp-team-credentials.txt): $r" -ForegroundColor Yellow
    Write-Host "Apply with: .\scripts\gcp_vm.ps1 update"
  }
  "team-remove" {
    if (-not $User) { Fail "-User NAME required" }
    TeamPy remove $User
    Write-Host "Apply with: .\scripts\gcp_vm.ps1 update"
  }
  "teardown" {
    Write-Host "This deletes the VM (its disk and database), the static IP and the firewall rule. The bucket is kept." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Type DELETE to confirm"; if ($a -ne "DELETE") { Fail "Cancelled." } }
    Write-Host (GCmd compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
    Write-Host (GCmd compute addresses delete $ipName "--region=$region" "--project=$Project" --quiet)
    Write-Host (GCmd compute firewall-rules delete $fw "--project=$Project" --quiet)
  }
}
