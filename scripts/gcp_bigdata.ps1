<#
 Big Data pipeline on GCP (CSE-CIC-IDS2018, 6.9 GB): ingest -> Spark on Dataproc Serverless -> BigQuery -> HTML report.
 ASCII only (PS 5.1). Every step that creates cloud resources or costs money asks for confirmation (-Yes to skip).

   .\scripts\gcp_bigdata.ps1 setup    enable APIs, Private Google Access on the subnet, IAM for the Spark service account
   .\scripts\gcp_bigdata.ps1 ingest   copy the 6.9 GB public dataset into gs://BUCKET/bigdata/raw (streamed, no local disk)
   .\scripts\gcp_bigdata.ps1 smoke    run the Spark job on a 12k-row fake sample (a few minutes): validates the job end to end
   .\scripts\gcp_bigdata.ps1 run      run the Spark job on the full dataset (clean -> Parquet -> EDA -> Random Forest)
   .\scripts\gcp_bigdata.ps1 bq       load the clean Parquet into BigQuery and run bigdata\queries.sql
   .\scripts\gcp_bigdata.ps1 report   download results.json and build bigdata\report\index.html
   .\scripts\gcp_bigdata.ps1 cleanup  delete the BigQuery dataset (the bucket data stays)
#>
param(
  [ValidateSet("setup", "ingest", "smoke", "run", "bq", "report", "cleanup")][string]$Action = "setup",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [string]$Region = "us-central1",
  [int]$TrainRows = 2000000,
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$gc = "gcloud"
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
  $p = Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"
  if (Test-Path $p) { $env:Path += ";$p" } else { Write-Host "gcloud not found" -ForegroundColor Red; exit 1 }
}
$base = "gs://$Bucket/bigdata"
$ds = "sfumato_bigdata"
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Confirm-Cost($msg) {
  Write-Host $msg -ForegroundColor Yellow
  if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Write-Host "Cancelled."; exit 1 } }
}
function Submit-Spark($name, $inp, $out, $extra) {
  Step "Upload the job"
  & gcloud storage cp (Join-Path $root "bigdata\spark_pipeline.py") "$base/code/spark_pipeline.py" "--project=$Project" --quiet
  Step "Submit Dataproc Serverless batch $name (follow it in the console: Dataproc > Batches)"
  # gcloud.cmd (not gcloud.ps1): the PowerShell wrapper swallows the "--" that separates job arguments
  $cmd = (Get-Command gcloud.cmd).Source
  $a = @("dataproc", "batches", "submit", "pyspark", "$base/code/spark_pipeline.py", "--project=$Project", "--region=$Region",
         "--batch=$name", "--version=2.2",
         "--properties=spark.executor.cores=4,spark.dynamicAllocation.maxExecutors=8",
         "--", "--input", $inp, "--output", $out) + $extra
  & $cmd @a
}

switch ($Action) {
  "setup" {
    Confirm-Cost "Enables Dataproc/BigQuery/Compute APIs in $Project, turns on Private Google Access on the 'default' subnet of $Region and grants roles/dataproc.worker + bucket access to the default compute service account."
    & gcloud services enable dataproc.googleapis.com bigquery.googleapis.com compute.googleapis.com storage.googleapis.com "--project=$Project"
    & gcloud compute networks subnets update default "--region=$Region" --enable-private-ip-google-access "--project=$Project"
    $num = (& gcloud projects describe $Project "--format=value(projectNumber)").Trim()
    $sa = "$num-compute@developer.gserviceaccount.com"
    & gcloud projects add-iam-policy-binding $Project "--member=serviceAccount:$sa" --role=roles/dataproc.worker --condition=None | Out-Null
    & gcloud storage buckets add-iam-policy-binding "gs://$Bucket" "--member=serviceAccount:$sa" --role=roles/storage.objectAdmin | Out-Null
    Write-Host "setup done (service account $sa)" -ForegroundColor Green
  }
  "ingest" {
    Confirm-Cost "Copies 6.9 GB from the public AWS bucket cse-cic-ids2018 into gs://$Bucket/bigdata/raw. Storage is billed beyond the free 5 GB (Standard, us-central1); ingress is free."
    python (Join-Path $root "bigdata\ingest.py") --bucket $Bucket
  }
  "smoke" {
    Confirm-Cost "Runs a small Dataproc Serverless batch on fake data (a few minutes of a few vCPUs)."
    python (Join-Path $root "bigdata\make_sample.py") (Join-Path $root "bigdata\_sample")
    & gcloud storage cp --recursive (Join-Path $root "bigdata\_sample\*") "$base/sample/in/" "--project=$Project" --quiet
    Submit-Spark ("sfumato-smoke-" + (Get-Date -Format "MMddHHmm")) "$base/sample/in" "$base/sample/out" @("--train-rows", "20000")
  }
  "run" {
    Confirm-Cost "Runs the full Spark job on 6.9 GB (up to 8 executors x 4 vCPU, probably 20-60 minutes). Cost NOT measured: check Billing afterwards, and make sure the budget alert exists."
    Submit-Spark ("sfumato-full-" + (Get-Date -Format "MMddHHmm")) "$base/raw" "$base/out" @("--train-rows", "$TrainRows")
  }
  "bq" {
    Confirm-Cost "Creates BigQuery dataset $ds and loads the clean Parquet (a few GB; queries are billed per TB scanned, the first TB/month is free)."
    & gcloud config set project $Project | Out-Null
    & bq --location=US mk --dataset --force "${Project}:$ds"
    # column_name_character_map=V2: CICFlowMeter names such as "Flow Byts/s" are not valid with the default map
    & bq --location=US load --replace --source_format=PARQUET --column_name_character_map=V2 --hive_partitioning_mode=AUTO "--hive_partitioning_source_uri_prefix=$base/out/parquet/" `
      "${Project}:$ds.flows" "$base/out/parquet/*"
    if ($LASTEXITCODE -ne 0) { Write-Host "BigQuery load failed" -ForegroundColor Red; exit 1 }
    $lines = Get-Content (Join-Path $root "bigdata\queries.sql") | Where-Object { $_ -notmatch '^\s*--' }
    $sql = ($lines -join "`n").Replace("DATASET", "$Project.$ds")
    foreach ($q in ($sql -split ";\s*\r?\n" | Where-Object { $_.Trim() })) {
      $q = ($q -replace '\s*\r?\n\s*', ' ').Trim().TrimEnd(';')   # bq.cmd (cmd.exe) truncates arguments at a newline
      Write-Host "`n$q" -ForegroundColor DarkGray
      & bq --location=US query --use_legacy_sql=false --format=pretty $q
    }
  }
  "report" {
    $dir = Join-Path $root "bigdata\report"; New-Item -ItemType Directory -Force $dir | Out-Null
    & gcloud storage cp "$base/out/results_json/*.txt" (Join-Path $dir "results.json") "--project=$Project" --quiet
    python (Join-Path $root "bigdata\report.py") (Join-Path $dir "results.json") (Join-Path $dir "index.html")
  }
  "cleanup" {
    Confirm-Cost "Deletes the BigQuery dataset $ds (the bucket and its data stay)."
    & bq rm -r -f -d "${Project}:$ds"
  }
}
