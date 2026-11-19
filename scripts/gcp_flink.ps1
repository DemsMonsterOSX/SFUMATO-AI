<#
 Flink on GCP: one Spot VM running a standalone Flink (JobManager + TaskManager) and a Flink SQL job that reads the Kafka topic
 network-flows and writes 10-second window aggregates and rule alerts back to Kafka. On demand: it costs money while it runs.
 Needs the Kafka cluster running (scripts\gcp_stream.ps1 start) and the application code in the bucket (gcp_stream.ps1 deploy-app).
 ASCII only (PS 5.1).

   .\scripts\gcp_flink.ps1 up         create the VM, install Flink (checksums verified), submit the SQL job
   .\scripts\gcp_flink.ps1 status     VM state, markers and the job state from the serial console
   .\scripts\gcp_flink.ps1 start|stop start or stop the VM (the job is submitted again at each start)
   .\scripts\gcp_flink.ps1 teardown   delete the VM (type DELETE)
#>
param(
  [ValidateSet("up", "status", "start", "stop", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$MachineType = "e2-medium",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$vm = "sfumato-flink"
$sa = "sfumato-stream@$Project.iam.gserviceaccount.com"
$fver = "1.20.5"
# SHA-512 published next to the archive: https://downloads.apache.org/flink/flink-1.20.5/flink-1.20.5-bin-scala_2.12.tgz.sha512
$fsha = "c846ecbcc4a1705724832acdbad27538c31f17aa494e8b69ff5f92d724574be83d1dff0b363aa0570e5a448f529224705d967d0d14df3267143eec5064a52a1f"
$cver = "3.4.0-1.20"
# SHA-1 published by Maven Central next to flink-sql-connector-kafka-3.4.0-1.20.jar
$csha = "266330f8f26fec4957339b5ff31aa67b81c31462"
$boot = (1..3 | ForEach-Object { "sfumato-kafka-$_.$Zone.c.$Project.internal:9092" }) -join ","
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Serial { return (G compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project") }

switch ($Action) {
  "up" {
    Write-Host "Creates one Spot $MachineType VM (4 GB) with a 20 GB standard disk. Roughly 0.01-0.02 USD per hour while running (estimate, verify in the pricing calculator). Stop it when you are done." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    $null = G compute instances describe $vm "--zone=$Zone" "--project=$Project"
    if ($rc -eq 0) { Write-Host "$vm exists: use start / status" } else {
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-flink-meta"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $pairs = @{ "flink-version" = $fver; "flink-sha512" = $fsha; "kafka-connector-version" = $cver; "kafka-connector-sha1" = $csha; "kafka-bootstrap" = $boot; "stream-bucket" = $Bucket }
      $files = @()
      foreach ($k in $pairs.Keys) { $f = Join-Path $mdir $k; [IO.File]::WriteAllText($f, [string]$pairs[$k]); $files += "$k=$f" }
      $files += "flink-sql=" + (Join-Path $root "streaming\flink\job.sql")
      $files += "startup-script=" + (Join-Path $root "deploy\flink\flink-startup.sh")
      $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
        --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=20GB --boot-disk-type=pd-standard "--service-account=$sa" --scopes=cloud-platform `
        --tags=sfumato-flink --shielded-secure-boot ("--metadata-from-file=" + ($files -join ","))
      if ($rc -ne 0) { Write-Host "creation failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$vm created" }
    }
    Write-Host "Waiting for Flink and the job (first boot downloads about 490 MB: 5 to 12 minutes)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(30); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial
      if ($s -match "FLINK_FAILED: [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; exit 1 }
      if ($s -match "FLINK_ALL_DONE") { $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 30 minutes: .\scripts\gcp_flink.ps1 status"; exit 1 }
    Write-Host ("`n" + (([regex]::Matches((Serial), "(FLINK_READY[^\r\n]*|FLINK_JOB[^\r\n]*)") | Select-Object -Last 3 | ForEach-Object { $_.Value }) -join "`n")) -ForegroundColor Green
  }
  "status" {
    Write-Host (G compute instances describe $vm "--zone=$Zone" "--project=$Project" "--format=value(status,machineType.basename(),networkInterfaces[0].networkIP)")
    Write-Host (([regex]::Matches((Serial), "(FLINK_READY[^\r\n]*|FLINK_JOB[^\r\n]*|FLINK_FAILED[^\r\n]*|READER_STARTED)") | Select-Object -Last 5 | ForEach-Object { $_.Value }) -join "`n")
  }
  "start" { Write-Host (G compute instances start $vm "--zone=$Zone" "--project=$Project") }
  "stop" { Write-Host (G compute instances stop $vm "--zone=$Zone" "--project=$Project") }
  "teardown" {
    $a = Read-Host "Delete the Flink VM and its disk? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
  }
}
