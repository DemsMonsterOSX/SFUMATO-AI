<#
 Kafka streaming cluster on GCP: 3 Spot VMs (e2-small), one KRaft broker+controller each, replication factor 3.
 Meant to run ON DEMAND (tests and demos), not 24/7: a Spot VM costs money while it runs and Google may reclaim it.
 ASCII only (PS 5.1). Every step that creates billable resources asks for confirmation (-Yes to skip).

   .\scripts\gcp_stream.ps1 up         create service account, 3 VMs, wait for the brokers and the topics
   .\scripts\gcp_stream.ps1 refresh    re-apply the startup script and Kafka version to the existing VMs and reboot them one by one
   .\scripts\gcp_stream.ps1 deploy-app upload the streaming code, models and replay data to the bucket (the VMs sync within a minute)
   .\scripts\gcp_stream.ps1 run -Scenario known|unseen -Rate 300   start producer, 3 scorers and the CVE bridge/consumer
   .\scripts\gcp_stream.ps1 halt        stop all streaming applications (the Kafka brokers keep running)
   .\scripts\gcp_stream.ps1 status     VM states and broker/topic markers from the serial console
   .\scripts\gcp_stream.ps1 stop       stop the VMs (disks kept, compute and IP no longer billed)
   .\scripts\gcp_stream.ps1 start      start them again (the startup script restarts Kafka by itself)
   .\scripts\gcp_stream.ps1 teardown   delete the VMs and their disks (type DELETE)
#>
param(
  [ValidateSet("up", "refresh", "deploy-app", "run", "halt", "status", "stop", "start", "teardown")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$MachineType = "e2-small",
  [ValidateSet("known", "unseen")][string]$Scenario = "known",
  [int]$Rate = 300,
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$names = 1..3 | ForEach-Object { "sfumato-kafka-$_" }
$sa = "sfumato-stream@$Project.iam.gserviceaccount.com"
$kver = "4.1.2"
# SHA-512 published by Apache next to the archive (https://downloads.apache.org/kafka/4.1.2/kafka_2.13-4.1.2.tgz.sha512)
$ksha = "78AC6E488B1071122F9608DFDB363F6FE50E1DBBC492347002C0398DFBF77E0D8CAA5BF794C5937379721004DFE92025937D238B0FAF4EB715529417FD43B491".ToLower()
$clusterFile = Join-Path $root "secrets\kafka-cluster-id.txt"

function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
function Confirm-Cost($msg) { Write-Host $msg -ForegroundColor Yellow; if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } } }
function Serial($n) { return (G compute instances get-serial-port-output $n "--zone=$Zone" "--project=$Project") }

switch ($Action) {
  "up" {
    Confirm-Cost "Creates 3 Spot $MachineType VMs ($($names -join ', ')) with a 20 GB standard disk each, plus the service account sfumato-stream (objectUser on the bucket). Roughly 0.02-0.03 USD per hour for the three while running (estimate, verify in the pricing calculator). Stop them when you are done."
    Step "Service account"
    $null = G iam service-accounts describe $sa "--project=$Project"
    if ($rc -ne 0) { $o = G iam service-accounts create sfumato-stream "--project=$Project" "--display-name=sfumato-stream"; if ($rc -ne 0) { Write-Host $o -ForegroundColor Red; exit 1 } }
    $null = G storage buckets add-iam-policy-binding "gs://$Bucket" "--member=serviceAccount:$sa" --role=roles/storage.objectUser "--project=$Project"
    Step "Cluster id"
    if (-not (Test-Path $clusterFile)) {
      $cid = python -c "import uuid,base64;print(base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip('='))"
      New-Item -ItemType Directory -Force (Split-Path $clusterFile) | Out-Null
      Set-Content -Path $clusterFile -Value $cid -Encoding ASCII
    }
    $cid = (Get-Content $clusterFile -Raw).Trim()
    $voters = (1..3 | ForEach-Object { "$_@sfumato-kafka-$_.$Zone.c.$Project.internal:9093" }) -join ","
    $startup = Join-Path $root "deploy\stream\kafka-startup.sh"
    Step "VMs"
    foreach ($i in 1..3) {
      $n = "sfumato-kafka-$i"
      $null = G compute instances describe $n "--zone=$Zone" "--project=$Project"
      if ($rc -eq 0) { Write-Host "$n exists"; continue }
      # values go through temporary files: commas, pipes and colons in them break --metadata under cmd.exe
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-kafka-meta-$i"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $pairs = @{ "kafka-node-id" = "$i"; "kafka-cluster-id" = $cid; "kafka-voters" = $voters; "kafka-version" = $kver; "kafka-sha512" = $ksha; "kafka-heap" = "700m"; "stream-bucket" = $Bucket }
      $files = @()
      foreach ($k in $pairs.Keys) { $f = Join-Path $mdir $k; [IO.File]::WriteAllText($f, [string]$pairs[$k]); $files += "$k=$f" }
      $files += "startup-script=$startup"
      $o = G compute instances create $n "--project=$Project" "--zone=$Zone" "--machine-type=$MachineType" --provisioning-model=SPOT --instance-termination-action=STOP `
        --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=20GB --boot-disk-type=pd-standard "--service-account=$sa" --scopes=cloud-platform `
        --tags=sfumato-kafka --shielded-secure-boot ("--metadata-from-file=" + ($files -join ","))
      if ($rc -ne 0) { Write-Host "creation of $n failed: $o" -ForegroundColor Red; exit 1 } else { Write-Host "$n created" }
    }
    Step "Waiting for the brokers and the topics (first boot: apt + Kafka download, 3 to 6 minutes)"
    $deadline = (Get-Date).AddMinutes(25); $ok = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      $s = Serial "sfumato-kafka-1"
      if ($s -match "KAFKA_FAILED: [^\r\n]*") { Write-Host $Matches[0] -ForegroundColor Red; exit 1 }
      if ($s -match "TOPICS_READY brokers=(\d)") { $ok = $true; break }
      Write-Host -NoNewline "."
    }
    if (-not $ok) { Write-Host "`nNot ready after 25 minutes: .\scripts\gcp_stream.ps1 status"; exit 1 }
    Write-Host "`n`nKafka cluster ready: brokers on $($names -join ', ') (internal DNS, port 9092)" -ForegroundColor Green
  }
  "refresh" {
    $startup = Join-Path $root "deploy\stream\kafka-startup.sh"
    foreach ($i in 1..3) {
      $n = "sfumato-kafka-$i"
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-kafka-meta-$i"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $pairs = @{ "kafka-version" = $kver; "kafka-sha512" = $ksha; "stream-bucket" = $Bucket }
      $files = @()
      foreach ($k in $pairs.Keys) { $f = Join-Path $mdir $k; [IO.File]::WriteAllText($f, [string]$pairs[$k]); $files += "$k=$f" }
      $files += "startup-script=$startup"
      Write-Host (G compute instances add-metadata $n "--zone=$Zone" "--project=$Project" ("--metadata-from-file=" + ($files -join ",")))
      $st = G compute instances describe $n "--zone=$Zone" "--project=$Project" "--format=value(status)"
      if ($st -eq "RUNNING") {
        Write-Host (G compute instances reset $n "--zone=$Zone" "--project=$Project")
        if ($i -lt 3) { Start-Sleep -Seconds 45 }   # keep a quorum while the next node reboots
      } else { Write-Host "$n is ${st}: metadata updated, the new startup script runs at the next start" }
    }
    Write-Host "Rebooting; check progress with: .\scripts\gcp_stream.ps1 status" -ForegroundColor Green
  }
  "deploy-app" {
    $stage = Join-Path ([IO.Path]::GetTempPath()) "sfumato-stream-app"
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory $stage | Out-Null
    $tgz = Join-Path $stage "app.tgz"
    $src = Join-Path $root "streaming"
    tar -czf $tgz -C $src common.py producer.py scorer.py cve_bridge.py cve_consumer.py controller.py stress_producer.py flink_state.py logship.py requirements.txt
    $sha = (Get-FileHash $tgz -Algorithm SHA256).Hash.ToLower()
    $req = (Get-FileHash (Join-Path $src "requirements.txt") -Algorithm SHA256).Hash.ToLower()
    $man = Join-Path $stage "manifest.json"
    [IO.File]::WriteAllText($man, ('{"sha256":"' + $sha + '","requirements_sha256":"' + $req + '","built_at":"' + (Get-Date).ToUniversalTime().ToString("o") + '"}'))
    Step "Upload code, models and replay data"
    Write-Host (G storage cp $tgz $man "gs://$Bucket/stream/code/" "--project=$Project" --quiet)
    foreach ($s in "known", "unseen") {
      Write-Host (G storage cp (Join-Path $src "model\model_$s.joblib") "gs://$Bucket/stream/model/" "--project=$Project" --quiet)
      Write-Host (G storage cp (Join-Path $src "model\replay_$s.parquet") "gs://$Bucket/stream/replay/" "--project=$Project" --quiet)
    }
    Write-Host (G storage cp (Join-Path $src "model\metrics.json") "gs://$Bucket/stream/model/" "--project=$Project" --quiet)
    Write-Host "App version $sha uploaded. The VMs install it within a minute (first install: pip, 2 to 4 minutes)." -ForegroundColor Green
  }
  { $_ -in "run", "halt" } {
    $roles = if ($Action -eq "run") { @{ 1 = "producer,scorer,cve-bridge,controller"; 2 = "scorer,cve-consumer"; 3 = "scorer" } } else { @{ 1 = ""; 2 = ""; 3 = "" } }
    # shared secret between the dashboard backend and the stress controller (internal network only); kept in secrets/, git-ignored
    $tokFile = Join-Path $root "secrets\stream-control-token.txt"
    if (-not (Test-Path $tokFile)) {
      New-Item -ItemType Directory -Force (Split-Path $tokFile) | Out-Null
      $bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
      Set-Content -Path $tokFile -Value (($bytes | ForEach-Object { $_.ToString("x2") }) -join "") -Encoding ASCII
    }
    $ctoken = (Get-Content $tokFile -Raw).Trim()
    $lines = @("SCENARIO=$Scenario", "RATE=$Rate", "THRESHOLD=0.5", "CONTROL_TOKEN=$ctoken")
    $elk = Join-Path $root "secrets\elk-secrets.txt"
    if (Test-Path $elk) {   # ship the application logs to Logstash when the log VM has been created
      $es = @{}; Get-Content $elk | ForEach-Object { $k, $v = $_ -split "=", 2; $es[$k] = $v }
      $lines += "LOGSTASH_URL=http://sfumato-elk.$Zone.c.$Project.internal:8080"
      $lines += "LOGSTASH_TOKEN=$($es['logship_token'])"
    }
    $envText = ($lines -join "`n")
    foreach ($i in 1..3) {
      $n = "sfumato-kafka-$i"
      $mdir = Join-Path ([IO.Path]::GetTempPath()) "sfumato-kafka-meta-$i"
      New-Item -ItemType Directory -Force $mdir | Out-Null
      $fr = Join-Path $mdir "stream-roles"; [IO.File]::WriteAllText($fr, $roles[$i])
      $fe = Join-Path $mdir "stream-env"; [IO.File]::WriteAllText($fe, $envText)
      Write-Host (G compute instances add-metadata $n "--zone=$Zone" "--project=$Project" "--metadata-from-file=stream-roles=$fr,stream-env=$fe")
    }
    if ($Action -eq "run") { Write-Host "Streaming started: scenario=$Scenario, $Rate flows/s. The VMs apply it within a minute." -ForegroundColor Green } else { Write-Host "Streaming applications stopped." -ForegroundColor Green }
  }
  "status" {
    Write-Host (G compute instances list "--project=$Project" "--filter=name~sfumato-kafka" "--format=table(name,status,scheduling.provisioningModel,networkInterfaces[0].networkIP)")
    foreach ($n in $names) {
      $s = Serial $n
      $m = [regex]::Matches($s, "(KAFKA_READY[^\r\n]*|TOPICS_READY[^\r\n]*|KAFKA_FAILED[^\r\n]*)") | Select-Object -Last 2 | ForEach-Object { $_.Value }
      Write-Host "$n : $($m -join ' | ')"
    }
  }
  "stop" { foreach ($n in $names) { Write-Host (G compute instances stop $n "--zone=$Zone" "--project=$Project") } }
  "start" { foreach ($n in $names) { Write-Host (G compute instances start $n "--zone=$Zone" "--project=$Project") } }
  "teardown" {
    $a = Read-Host "Delete the 3 Kafka VMs and their disks? Type DELETE"
    if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
    Write-Host (G compute instances delete @names "--zone=$Zone" "--project=$Project" --quiet)
  }
}
