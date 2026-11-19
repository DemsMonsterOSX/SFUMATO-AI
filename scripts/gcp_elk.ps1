<#
 Log VM: Elasticsearch 8.x + Logstash on one Spot VM (8 GB). The applications push their logs over HTTP to Logstash; the web app's
 Logs tab queries Elasticsearch. On demand: it costs money while it runs. ASCII only (PS 5.1).

   .\scripts\gcp_elk.ps1 up         create the VM (passwords are generated into secrets\elk-secrets.txt), install and start the stack
   .\scripts\gcp_elk.ps1 status     VM state and markers
   .\scripts\gcp_elk.ps1 start|stop start or stop the VM (the indexed logs are kept on the disk)
   .\scripts\gcp_elk.ps1 teardown   delete the VM and its disk (type DELETE)
#>
param(
  [ValidateSet("up", "status", "start", "stop", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$MachineType = "e2-standard-2",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$vm = "sfumato-elk"
$secretFile = Join-Path $root "secrets\elk-secrets.txt"
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Serial { return (G compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project") }
function NewSecret { $b = New-Object byte[] 18; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }

switch ($Action) {
  "up" {
    Write-Host "Creates one Spot $MachineType VM (8 GB) with a 40 GB standard disk. Roughly 0.03-0.07 USD per hour while running (estimate, verify in the pricing calculator). Stop it when you are done." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    if (-not (Test-Path $secretFile)) {
      New-Item -ItemType Directory -Force (Split-Path $secretFile) | Out-Null
      Set-Content -Path $secretFile -Value @("elastic_password=$(NewSecret)", "logship_token=$(NewSecret)") -Encoding ASCII
    }
    $sec = @{}; Get-Content $secretFile | ForEach-Object { $k, $v = $_ -split "=", 2; $sec[$k] = $v }
    $null = G compute instances describe $vm "--zone=$Zone" "--project=$Project"
    if ($rc -eq 0) { Write-Host "$vm exists: use start / status" } else {
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-elk-meta"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $files = @()
      foreach ($pair in @(@("elastic-password", $sec["elastic_password"]), @("logship-token", $sec["logship_token"]))) {
        $f = Join-Path $mdir $pair[0]; [IO.File]::WriteAllText($f, [string]$pair[1]); $files += "$($pair[0])=$f"
      }
      $files += "startup-script=" + (Join-Path $root "deploy\elk\elk-startup.sh")
      $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
        --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=40GB --boot-disk-type=pd-standard --no-service-account --no-scopes `
        --tags=sfumato-elk --shielded-secure-boot ("--metadata-from-file=" + ($files -join ","))
      if ($rc -ne 0) { Write-Host "creation failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$vm created" }
    }
    Write-Host "Waiting for Elasticsearch and Logstash (first boot installs about 1.5 GB of packages: 6 to 15 minutes)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(35); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial
      if ($s -match "ELK_FAILED: [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; exit 1 }
      if ($s -match "ELK_READY [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Green; $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 35 minutes: .\scripts\gcp_elk.ps1 status"; exit 1 }
    Write-Host "`nInternal address: http://${vm}.${Zone}.c.${Project}.internal (Elasticsearch :9200, Logstash HTTP :8080). Passwords: secrets\elk-secrets.txt" -ForegroundColor Green
  }
  "status" {
    Write-Host (G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(status,machineType.basename(),networkInterfaces[0].networkIP)")
    Write-Host (([regex]::Matches((Serial), "(ELK_READY[^\r\n]*|ELK_FAILED[^\r\n]*)") | Select-Object -Last 3 | ForEach-Object { $_.Value }) -join "`n")
  }
  "start" { Write-Host (G compute instances start $vm "--zone=$Zone" "--project=$Project") }
  "stop" { Write-Host (G compute instances stop $vm "--zone=$Zone" "--project=$Project") }
  "teardown" {
    $a = Read-Host "Delete the log VM and its disk? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
  }
}
