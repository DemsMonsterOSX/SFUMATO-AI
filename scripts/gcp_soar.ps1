<#
 SOAR VM: Shuffle (open-source SOAR) with Docker on one Spot VM (16 GB). On demand: it costs money while it runs. ASCII only (PS 5.1).

   .\scripts\gcp_soar.ps1 up         create the VM (secrets are generated into secrets\soar-secrets.txt), install and start Shuffle
   .\scripts\gcp_soar.ps1 status     VM state, address and markers
   .\scripts\gcp_soar.ps1 start|stop start or stop the VM (workflows are kept on the disk)
   .\scripts\gcp_soar.ps1 teardown   delete the VM and the firewall rule (type DELETE)
 The Shuffle UI is https://<external-ip>:3443 (self-signed certificate), opened only to the public address of the machine that ran "up"
 (override with -AllowFrom a.b.c.d/32). If your address changes, run: .\scripts\gcp_soar.ps1 allow
#>
param(
  [ValidateSet("up", "allow", "status", "start", "stop", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$MachineType = "e2-standard-4",
  [string]$AllowFrom = "",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$vm = "sfumato-soar"
$fw = "sfumato-soar-ui"
$secretFile = Join-Path $root "secrets\soar-secrets.txt"
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Serial { return (G compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project") }
function NewSecret { $b = New-Object byte[] 18; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }
function MyCidr { if ($AllowFrom) { return $AllowFrom }; $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 15).Trim(); return "$ip/32" }
function SetFirewall {
  $cidr = MyCidr
  $null = G compute firewall-rules describe $fw "--project=$Project"
  if ($rc -eq 0) { $o = G compute firewall-rules update $fw "--project=$Project" "--source-ranges=$cidr" }
  else { $o = G compute firewall-rules create $fw "--project=$Project" --network=default --direction=INGRESS "--allow=tcp:3443" "--target-tags=sfumato-soar" "--source-ranges=$cidr" }
  if ($rc -ne 0) { Write-Host "firewall failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "UI port 3443 open to $cidr only" }
}
function ExtIp { return (G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(networkInterfaces[0].accessConfigs[0].natIP)") }

switch ($Action) {
  "up" {
    Write-Host "Creates one Spot $MachineType VM (16 GB) with a 60 GB balanced disk. Estimate roughly 0.05-0.10 USD per hour while running (verify in Billing). Stop it when you are done." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    if (-not (Test-Path $secretFile)) {
      New-Item -ItemType Directory -Force (Split-Path $secretFile) | Out-Null
      Set-Content -Path $secretFile -Value @("shuffle_user=admin", "shuffle_password=$(NewSecret)", "shuffle_apikey=$(NewSecret)", "shuffle_secret=$(NewSecret)") -Encoding ASCII
    }
    $sec = @{}; Get-Content $secretFile | ForEach-Object { $k, $v = $_ -split "=", 2; $sec[$k] = $v }
    SetFirewall
    $null = G compute instances describe $vm "--zone=$Zone" "--project=$Project"
    if ($rc -eq 0) { Write-Host "$vm exists: use start / status" } else {
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-soar-meta"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $files = @()
      foreach ($pair in @(@("shuffle-password", $sec["shuffle_password"]), @("shuffle-apikey", $sec["shuffle_apikey"]), @("shuffle-secret", $sec["shuffle_secret"]))) {
        $f = Join-Path $mdir $pair[0]; [IO.File]::WriteAllText($f, [string]$pair[1]); $files += "$($pair[0])=$f"
      }
      $files += "startup-script=" + (Join-Path $root "deploy\soar\soar-startup.sh")
      $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
        --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=60GB --boot-disk-type=pd-balanced --no-service-account --no-scopes `
        --tags=sfumato-soar --shielded-secure-boot ("--metadata-from-file=" + ($files -join ","))
      if ($rc -ne 0) { Write-Host "creation failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$vm created" }
    }
    Write-Host "Waiting for Shuffle (first boot installs Docker and pulls about 3 GB of images: 8 to 20 minutes)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(40); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial
      if ($s -match "SOAR_FAILED: [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; exit 1 }
      if ($s -match "SOAR_READY [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Green; $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 40 minutes: .\scripts\gcp_soar.ps1 status"; exit 1 }
    Write-Host "`nUI: https://$(ExtIp):3443 (self-signed certificate, user admin, password in secrets\soar-secrets.txt). Internal: http://${vm}.${Zone}.c.${Project}.internal:5001" -ForegroundColor Green
  }
  "allow" { SetFirewall }
  "status" {
    Write-Host (G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(status,machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP)")
    Write-Host (([regex]::Matches((Serial), "(SOAR_READY[^\r\n]*|SOAR_FAILED[^\r\n]*)") | Select-Object -Last 3 | ForEach-Object { $_.Value }) -join "`n")
  }
  "start" { Write-Host (G compute instances start $vm "--zone=$Zone" "--project=$Project") }
  "stop" { Write-Host (G compute instances stop $vm "--zone=$Zone" "--project=$Project") }
  "teardown" {
    $a = Read-Host "Delete the SOAR VM, its disk and the firewall rule? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
    Write-Host (G compute firewall-rules delete $fw "--project=$Project" --quiet)
  }
}
