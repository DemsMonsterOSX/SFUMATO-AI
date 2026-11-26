<#
 Autoscaled scorer workers: two extra VMs (sfumato-scorer-1, sfumato-scorer-2) that normally stay STOPPED. The streaming controller on
 kafka-1 starts one when the Kafka consumer lag stays high and stops it when the lag stays low (streaming/autoscaler.py).
 Each worker only runs the scorer; with the 3 scorers of the Kafka VMs that makes 3 to 5 members of the consumer group
 (network-flows has 6 partitions). ASCII only (PS 5.1).

   .\scripts\gcp_autoscale.ps1 up          create the 2 workers, grant the controller the right to start/stop them (only them), install, then stop them
   .\scripts\gcp_autoscale.ps1 status      state of the workers and of the autoscaler
   .\scripts\gcp_autoscale.ps1 start|stop  start or stop both workers by hand (the autoscaler does it by itself when enabled)
   .\scripts\gcp_autoscale.ps1 teardown    delete the workers (type DELETE); the IAM binding is removed too

 Security: the service account of the Kafka VMs (sfumato-stream) gets a custom role with three permissions (instances.get, start, stop),
 bound with an IAM condition on the instance name prefix, so it cannot touch any other VM.
 Run "gcp_stream.ps1 deploy-app" and "gcp_stream.ps1 run" afterwards so that the controller runs the new autoscaler.
#>
param(
  [ValidateSet("up", "status", "start", "stop", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$MachineType = "e2-standard-4",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$sa = "sfumato-stream@$Project.iam.gserviceaccount.com"
$role = "sfumatoScorerScaler"
$workers = "sfumato-scorer-1", "sfumato-scorer-2"
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }

switch ($Action) {
  "up" {
    Write-Host "Creates 2 Spot $MachineType VMs (20 GB disks, stopped after installation). They cost money only while the autoscaler runs them." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    $null = G iam roles describe $role "--project=$Project"
    if ($rc -ne 0) {
      $o = G iam roles create $role "--project=$Project" "--title=Sfumato scorer scaler" "--permissions=compute.instances.get,compute.instances.start,compute.instances.stop" --stage=GA
      if ($rc -ne 0) { Write-Host "role creation failed: $o" -ForegroundColor Red; exit 1 }
    }
    $cond = "expression=resource.name.startsWith('projects/$Project/zones/$Zone/instances/sfumato-scorer-'),title=scorer-workers-only"   # single quotes: PS 5.1 drops embedded double quotes
    $o = G projects add-iam-policy-binding $Project "--member=serviceAccount:$sa" "--role=projects/$Project/roles/$role" "--condition=$cond"
    if ($rc -ne 0) { Write-Host "binding failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "controller may start/stop sfumato-scorer-* only" }
    $voters = G compute instances describe sfumato-kafka-1 "--zone=$Zone" "--project=$Project" "--format=value(metadata.items.kafka-voters)"
    if (-not $voters) { Write-Host "cannot read kafka-voters from sfumato-kafka-1" -ForegroundColor Red; exit 1 }
    $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-scale-meta"; New-Item -ItemType Directory -Force $mdir | Out-Null
    [IO.File]::WriteAllText((Join-Path $mdir "kafka-voters"), $voters)
    [IO.File]::WriteAllText((Join-Path $mdir "stream-bucket"), $Bucket)
    [IO.File]::WriteAllText((Join-Path $mdir "stream-roles"), "")
    [IO.File]::WriteAllText((Join-Path $mdir "stream-env"), "SCENARIO=known`nRATE=300`nTHRESHOLD=0.5")
    foreach ($n in $workers) {
      $null = G compute instances describe $n "--zone=$Zone" "--project=$Project"
      if ($rc -eq 0) { Write-Host "$n exists"; continue }
      $o = G compute instances create $n "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
        --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=20GB --boot-disk-type=pd-standard "--service-account=$sa" --scopes=cloud-platform `
        "--metadata-from-file=startup-script=$(Join-Path $root 'deploy\stream\scorer-startup.sh'),kafka-voters=$(Join-Path $mdir 'kafka-voters'),stream-bucket=$(Join-Path $mdir 'stream-bucket'),stream-roles=$(Join-Path $mdir 'stream-roles'),stream-env=$(Join-Path $mdir 'stream-env')"
      if ($rc -ne 0) { Write-Host "creation of $n failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$n created" }
    }
    Write-Host "Installing the application on the workers (first boot: packages, then the sync timer installs Python dependencies)" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(12); $ready = @{}
    while ((Get-Date) -lt $deadline -and $ready.Count -lt $workers.Count) {
      Start-Sleep -Seconds 20
      foreach ($n in $workers) {
        if ($ready[$n]) { continue }
        $s = G compute instances get-serial-port-output $n "--zone=$Zone" "--project=$Project"
        if ($s -match "SCORER_WORKER_FAILED") { Write-Host "$n failed" -ForegroundColor Red; exit 1 }
        if ($s -match "SCORER_WORKER_READY") { $ready[$n] = $true; Write-Host "$n ready" -ForegroundColor Green }
      }
    }
    if ($ready.Count -lt $workers.Count) { Write-Host "not ready after 12 minutes: check the serial console" -ForegroundColor Red; exit 1 }
    Write-Host "Waiting 4 minutes for the sync timer to install the Python dependencies, then stopping the workers" -ForegroundColor Cyan
    Start-Sleep -Seconds 240
    foreach ($n in $workers) { Write-Host (G compute instances stop $n "--zone=$Zone" "--project=$Project") }
    Write-Host "Done. Next: gcp_stream.ps1 deploy-app, then gcp_stream.ps1 run (it enables the autoscaler on kafka-1)." -ForegroundColor Green
  }
  "status" {
    Write-Host (G compute instances list "--project=$Project" "--filter=name~sfumato-scorer" "--format=table(name,machineType.basename(),status,scheduling.provisioningModel)")
    $j = G storage cat "gs://$Bucket/stream/state/autoscale.json"
    if ($rc -eq 0) { Write-Host $j.Substring(0, [Math]::Min(900, $j.Length)) } else { Write-Host "no autoscaler state yet (gcp_stream.ps1 run starts it)" }
  }
  "start" { foreach ($n in $workers) { Write-Host (G compute instances start $n "--zone=$Zone" "--project=$Project") } }
  "stop" { foreach ($n in $workers) { Write-Host (G compute instances stop $n "--zone=$Zone" "--project=$Project") } }
  "teardown" {
    $a = Read-Host "Delete the 2 scorer workers and the IAM binding? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete $workers "--zone=$Zone" "--project=$Project" --quiet)
    $cond = "expression=resource.name.startsWith('projects/$Project/zones/$Zone/instances/sfumato-scorer-'),title=scorer-workers-only"
    Write-Host (G projects remove-iam-policy-binding $Project "--member=serviceAccount:$sa" "--role=projects/$Project/roles/$role" "--condition=$cond")
  }
}
