<#
 Internal LLM VM: Ollama serving a Qwen model on a CPU VM, used by the Da Vinci AI agent through the existing Ollama provider.
 On demand: it costs money while it runs. ASCII only (PS 5.1).

   .\scripts\gcp_qwen.ps1 up          create the VM, install Ollama (sha256 verified), pull the model, measure the speed
   .\scripts\gcp_qwen.ps1 status      VM state and the markers from the serial console
   .\scripts\gcp_qwen.ps1 start|stop  start or stop the VM (the disk and the model are kept)
   .\scripts\gcp_qwen.ps1 teardown    delete the VM and its disk (type DELETE)
 Options: -MachineType e2-standard-4 (4 vCPU, 16 GB) | e2-standard-8 (8 vCPU, 32 GB), -Model qwen2.5:7b-instruct
          -Gpu  one NVIDIA T4 on an n1-standard-4 (standard, not Spot, so a demo is not preempted), Deep Learning VM image with the driver
                preinstalled, 100 GB balanced disk. Needs the GPUS_ALL_REGIONS and NVIDIA_T4_GPUS quotas. Same VM name, so nothing else changes.
#>
param(
  [ValidateSet("up", "status", "start", "stop", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$MachineType = "e2-standard-4",
  [string]$Model = "qwen2.5:7b-instruct",
  [switch]$Gpu,
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
if ($Gpu -and -not $PSBoundParameters.ContainsKey("Model")) { $Model = "qwen2.5:14b-instruct" }   # fits the 16 GB T4 entirely (9 GB), 17 tokens/s measured
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$vm = "sfumato-qwen"
$over = "0.40.16"
# SHA-256 of ollama-linux-amd64.tar.zst as published by GitHub for the release asset (api.github.com/repos/ollama/ollama/releases/tags/v0.40.16)
$osha = "87bfafb2acbc89b2e6a1be0a9043de6aa75fb450696f86bc426e65fc448f788d"
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Serial { return (G compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project") }

switch ($Action) {
  "up" {
    if ($Gpu) { Write-Host "Creates one n1-standard-4 VM with an NVIDIA T4 (standard provisioning). Cost not measured: read Billing." -ForegroundColor Yellow } else { Write-Host "Creates one Spot $MachineType VM with a 40 GB standard disk and no service account. Roughly 0.04-0.06 USD per hour while running (estimate, verify in the pricing calculator). Stop it when you are done." -ForegroundColor Yellow }
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    $null = G compute instances describe $vm "--zone=$Zone" "--project=$Project"
    if ($rc -eq 0) { Write-Host "$vm exists: use start / status" } else {
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-qwen-meta"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $pairs = @{ "ollama-version" = $over; "ollama-sha256" = $osha; "qwen-model" = $Model }
      $files = @()
      foreach ($k in $pairs.Keys) { $f = Join-Path $mdir $k; [IO.File]::WriteAllText($f, [string]$pairs[$k]); $files += "$k=$f" }
      $files += "startup-script=" + (Join-Path $root "deploy\qwen\qwen-startup.sh")
      $meta = "--metadata-from-file=" + ($files -join ",")
      if ($Gpu) {
        $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=n1-standard-4" "--accelerator=type=nvidia-tesla-t4,count=1" --maintenance-policy=TERMINATE `
          --image-family=common-cu129-ubuntu-2204-nvidia-580 --image-project=deeplearning-platform-release --boot-disk-size=100GB --boot-disk-type=pd-balanced `
          --no-service-account --no-scopes --tags=sfumato-qwen $meta
      } else {
        $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
          --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=40GB --boot-disk-type=pd-standard --no-service-account --no-scopes `
          --tags=sfumato-qwen --shielded-secure-boot $meta
      }
      if ($rc -ne 0) { Write-Host "creation failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$vm created" }
    }
    Write-Host "Waiting for Ollama and the model (first boot downloads about 1.5 GB of Ollama and 4.7 GB of model: 8 to 20 minutes)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(40); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial
      if ($s -match "QWEN_FAILED: [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; exit 1 }
      if ($s -match "QWEN_SPEED [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Green; $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 40 minutes: .\scripts\gcp_qwen.ps1 status"; exit 1 }
    $ip = G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(networkInterfaces[0].networkIP)"
    Write-Host "`nReady. Internal address: http://${vm}.${Zone}.c.${Project}.internal:11434 (internal IP $ip)" -ForegroundColor Green
  }
  "status" {
    Write-Host (G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(status,machineType.basename(),networkInterfaces[0].networkIP)")
    $m = [regex]::Matches((Serial), "(QWEN_READY[^\r\n]*|QWEN_SPEED[^\r\n]*|QWEN_FAILED[^\r\n]*)") | Select-Object -Last 3 | ForEach-Object { $_.Value }
    Write-Host ($m -join "`n")
  }
  "start" { Write-Host (G compute instances start $vm "--zone=$Zone" "--project=$Project") }
  "stop" { Write-Host (G compute instances stop $vm "--zone=$Zone" "--project=$Project") }
  "teardown" {
    $a = Read-Host "Delete the Qwen VM and its disk? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
  }
}
