<#
 Spark scalability experiment on Dataproc Serverless: the same data-preparation job (clean 6.9 GB of CSV, write Parquet, aggregate)
 with a FIXED number of executors (dynamic allocation off), one batch after the other so that the timings are comparable.

   .\scripts\gcp_spark_scale.ps1 -Executors 2,4,8 -Yes     run the batches, write ml/scale/spark_scale.json

 The ML part is skipped (--skip-ml) to keep the cost down: only the preparation (read, clean, Parquet, aggregates) is compared.
 Each executor has 4 vCPU; the driver is the Dataproc default. Output goes to gs://BUCKET/bigdata/scale/e<N> (the published results
 are never overwritten). Measured per run: prep_seconds written by the job, and the batch wall time (including the cluster start).
 The cost is NOT measured here: read Billing afterwards.
#>
param(
  [int[]]$Executors = @(2, 4, 8),
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Region = "us-central1",
  [string]$Bucket = "sfumato-soc-4ab8ab-artifacts",
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$cmd = (Get-Command gcloud.cmd).Source
$base = "gs://$Bucket/bigdata"
if (-not $Yes) { $a = Read-Host "Runs $($Executors.Count) Spark batches on 6.9 GB (executors: $($Executors -join ', ')). Cost not measured. Proceed? (y/N)"; if ($a -notmatch '^[yY]') { exit 1 } }
& $cmd storage cp (Join-Path $root "bigdata\spark_pipeline.py") "$base/code/spark_pipeline.py" "--project=$Project" --quiet
$rows = @()
foreach ($n in $Executors) {
  $name = "sfumato-scale-e$n-" + (Get-Date -Format "MMddHHmm")
  Write-Host "`n== $n executors ($($n * 4) vCPU): batch $name" -ForegroundColor Cyan
  $t0 = Get-Date
  & $cmd dataproc batches submit pyspark "$base/code/spark_pipeline.py" "--project=$Project" "--region=$Region" "--batch=$name" --version=2.2 `
    "--properties=spark.executor.cores=4,spark.dynamicAllocation.enabled=false,spark.executor.instances=$n" `
    -- --input "$base/raw" --output "$base/scale/e$n" --skip-ml
  $wall = [math]::Round(((Get-Date) - $t0).TotalSeconds)
  $state = (& $cmd dataproc batches describe $name "--project=$Project" "--region=$Region" "--format=value(state)").Trim()
  $tmp = Join-Path ([IO.Path]::GetTempPath()) "scale-e$n.json"
  & $cmd storage cp "$base/scale/e$n/results_json/*.txt" $tmp "--project=$Project" --quiet 2>$null
  $prep = $null; $total = $null
  if (Test-Path $tmp) { $j = Get-Content $tmp -Raw | ConvertFrom-Json; $prep = $j.prep_seconds; $total = $j.total_seconds }
  $rows += [pscustomobject]@{ executors = $n; vcpu = $n * 4; state = $state; prep_seconds = $prep; total_seconds = $total; batch_wall_seconds = $wall; batch = $name }
  Write-Host ("e{0}: state={1} prep={2}s wall={3}s" -f $n, $state, $prep, $wall) -ForegroundColor Green
}
$out = Join-Path $root "ml\scale\spark_scale.json"
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
@{ measured_at = (Get-Date).ToUniversalTime().ToString("o"); input_gb = 6.89; skip_ml = $true; runs = $rows } | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8
Write-Host "Saved $out" -ForegroundColor Green
