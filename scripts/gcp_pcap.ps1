<#
 One day of CSE-CIC-IDS2018 raw traffic: pcap.zip -> Zeek (container) -> conn logs as Parquet in the bucket, on one Spot VM.

   .\scripts\gcp_pcap.ps1 up -Yes       create the VM (it downloads, unzips, runs Zeek, uploads, then powers off)
   .\scripts\gcp_pcap.ps1 status        VM state and the last progress markers from the serial console
   .\scripts\gcp_pcap.ps1 delete -Yes   delete the VM and its disk (do it as soon as the work is done)

 Source (public AWS bucket, about 39.9 GB): Original Network Traffic and Log data/Wednesday-14-02-2018/pcap.zip
 Result: gs://BUCKET/bigdata/pcap/2018-02-14/conn/*.parquet (Zeek conn.log, JSON, with source and destination addresses).
 Safety: the VM powers itself off after -MaxHours from its first boot (the disk is kept until `delete`). Cost: NOT measured: read Billing
 before and after; a stopped VM still pays for its disk. Uses 8 vCPU of the project's 32-vCPU global quota.
#>
param(
  [ValidateSet("up", "status", "delete")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$Day = "Wednesday-14-02-2018",
  [string]$Prefix = "bigdata/pcap/2018-02-14",
  [string]$MachineType = "e2-standard-8",
  [int]$DiskGb = 250,
  [int]$MaxHours = 8,
  [int]$Workers = 6,
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$g = (Get-Command gcloud.cmd).Source
$vm = "sfumato-pcap"
$sa = "sfumato-stream@$Project.iam.gserviceaccount.com"   # objectUser on the bucket (created by gcp_stream.ps1 up)
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }

switch ($Action) {
  "up" {
    $url = "https://cse-cic-ids2018.s3.amazonaws.com/" + [uri]::EscapeDataString("Original Network Traffic and Log data") + "/$Day/pcap.zip"
    Write-Host "Creates $vm ($MachineType Spot, $DiskGb GB pd-balanced), downloads about 39.9 GB from the public bucket, powers off after at most $MaxHours h. Cost not measured." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    $null = G compute instances describe $vm "--zone=$Zone" "--project=$Project"
    if ($rc -eq 0) { Write-Host "$vm already exists (use status or delete)"; exit 1 }
    $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-pcap-meta"; New-Item -ItemType Directory -Force $mdir | Out-Null
    $pairs = @{ "pcap-url" = $url; "pcap-bucket" = $Bucket; "pcap-prefix" = $Prefix; "pcap-max-hours" = "$MaxHours"; "pcap-workers" = "$Workers" }
    $files = @()
    foreach ($k in $pairs.Keys) { $f = Join-Path $mdir $k; [IO.File]::WriteAllText($f, [string]$pairs[$k]); $files += "$k=$f" }
    $startup = Join-Path $mdir "startup.sh"
    [IO.File]::WriteAllText($startup, ((Get-Content (Join-Path $root "deploy\pcap\pcap-startup.sh") -Raw) -replace "`r`n", "`n"))
    $files += "startup-script=$startup"
    $o = G compute instances create $vm "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
      --image-family=debian-12 --image-project=debian-cloud "--boot-disk-size=${DiskGb}GB" --boot-disk-type=pd-balanced "--service-account=$sa" --scopes=cloud-platform `
      --shielded-secure-boot ("--metadata-from-file=" + ($files -join ","))
    Write-Host $o
    if ($rc -ne 0) { exit 1 }
    Write-Host "Started. Follow it with: .\scripts\gcp_pcap.ps1 status" -ForegroundColor Green
  }
  "status" {
    Write-Host (G compute instances list "--project=$Project" "--filter=name=$vm" "--format=table(name,status,machineType.basename())")
    $s = G compute instances get-serial-port-output $vm "--zone=$Zone" "--project=$Project"
    [regex]::Matches($s, "(PCAP_[A-Z]+[^\r\n]*|pcap files:[^\r\n]*|zeek finished[^\r\n]*|downloaded [^\r\n]*)") | Select-Object -Last 8 | ForEach-Object { $_.Value }
  }
  "delete" {
    if (-not $Yes) { $a = Read-Host "Delete $vm and its disk? (y/N)"; if ($a -notmatch '^[yY]') { exit 1 } }
    Write-Host (G compute instances delete $vm "--zone=$Zone" "--project=$Project" --quiet)
  }
}
