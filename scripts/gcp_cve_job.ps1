<#
 Hourly CVE ingestion on GCP: Cloud Run Job (container built by Cloud Build) triggered by Cloud Scheduler.
 Serverless: independent of the dashboard VM and of your PC. Free-tier friendly (one short run per hour).
 ASCII only (PS 5.1).

   .\scripts\gcp_cve_job.ps1 deploy    enable APIs, service account, build and deploy the job, create the hourly schedule
   .\scripts\gcp_cve_job.ps1 run       run the job now and wait for it
   .\scripts\gcp_cve_job.ps1 status    last executions and the schedule
   .\scripts\gcp_cve_job.ps1 pause     pause the hourly schedule (resume with: resume)
   .\scripts\gcp_cve_job.ps1 delete    delete the schedule and the job (the bucket data stays)
#>
param(
  [ValidateSet("deploy", "run", "status", "pause", "resume", "delete")][string]$Action = "status",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Region = "us-central1",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$Schedule = "5 * * * *",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gcloud.cmd -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"; if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$g = (Get-Command gcloud.cmd).Source
$job = "sfumato-cve"; $sched = "sfumato-cve-hourly"
$sa = "sfumato-ingest@$Project.iam.gserviceaccount.com"
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }

switch ($Action) {
  "deploy" {
    Write-Host "Builds a container with Cloud Build and deploys a Cloud Run Job plus an hourly Cloud Scheduler trigger. Expected cost: about zero (free tiers), not measured." -ForegroundColor Yellow
    if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
    Step "APIs"
    Write-Host (G services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com cloudscheduler.googleapis.com "--project=$Project")
    Step "Service account (write access to the bucket only)"
    $null = G iam service-accounts describe $sa "--project=$Project"
    if ($rc -ne 0) { Write-Host (G iam service-accounts create sfumato-ingest "--project=$Project" "--display-name=sfumato-ingest") }
    Write-Host (G storage buckets add-iam-policy-binding "gs://$Bucket" "--member=serviceAccount:$sa" --role=roles/storage.objectUser "--project=$Project") | Out-Null
    Step "Build and deploy the job"
    $stage = Join-Path ([IO.Path]::GetTempPath()) "sfumato-cve-job"
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory $stage | Out-Null
    Copy-Item (Join-Path $root "bigdata\cve_job\*") $stage
    Copy-Item (Join-Path $root "bigdata\cve_ingest.py") $stage
    $o = G run jobs deploy $job "--source=$stage" "--region=$Region" "--project=$Project" "--service-account=$sa" "--set-env-vars=BUCKET=$Bucket" `
      --tasks=1 --max-retries=1 --task-timeout=1800 --memory=1Gi --cpu=1
    Write-Host $o
    if ($rc -ne 0) { Write-Host "Job deployment failed" -ForegroundColor Red; exit 1 }
    $null = G run jobs add-iam-policy-binding $job "--region=$Region" "--project=$Project" "--member=serviceAccount:$sa" --role=roles/run.invoker
    Step "Hourly schedule ($Schedule)"
    $uri = "https://$Region-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/$Project/jobs/${job}:run"
    $null = G scheduler jobs describe $sched "--location=$Region" "--project=$Project"
    $verb = if ($rc -eq 0) { "update" } else { "create" }
    Write-Host (G scheduler jobs $verb http $sched "--location=$Region" "--project=$Project" "--schedule=$Schedule" "--uri=$uri" --http-method=POST `
      "--oauth-service-account-email=$sa" --oauth-token-scope=https://www.googleapis.com/auth/cloud-platform "--time-zone=Etc/UTC")
    Write-Host "`nDeployed. Run it now with: .\scripts\gcp_cve_job.ps1 run" -ForegroundColor Green
  }
  "run" {
    & $g run jobs execute $job "--region=$Region" "--project=$Project" --wait
  }
  "status" {
    Write-Host (G run jobs executions list "--job=$job" "--region=$Region" "--project=$Project" --limit=5 "--format=table(name.basename(),status.completionTime,status.succeededCount,status.failedCount)")
    Write-Host (G scheduler jobs describe $sched "--location=$Region" "--project=$Project" "--format=value(state,schedule,lastAttemptTime)")
  }
  "pause" { Write-Host (G scheduler jobs pause $sched "--location=$Region" "--project=$Project") }
  "resume" { Write-Host (G scheduler jobs resume $sched "--location=$Region" "--project=$Project") }
  "delete" {
    Write-Host (G scheduler jobs delete $sched "--location=$Region" "--project=$Project" --quiet)
    Write-Host (G run jobs delete $job "--region=$Region" "--project=$Project" --quiet)
  }
}
