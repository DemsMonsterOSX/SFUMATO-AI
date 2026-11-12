<#
 Creates the Google Cloud side of Sfumato: bucket, two least-privilege service accounts, optional budget alert,
 and wires .env. Idempotent: re-running only creates what is missing. Nothing is deleted. ASCII only (PS 5.1).

 Prerequisites (done by you, once):  gcloud auth login   and   gcloud config set project <PROJECT_ID>
 Usage:  .\scripts\gcp_setup.ps1 -Bucket my-unique-bucket [-Project id] [-Region us-central1] [-BillingAccount 0X0X0X-...] [-BudgetAmount 20]
#>
param(
  [Parameter(Mandatory = $true)][string]$Bucket,
  [string]$Project = "",
  [string]$Region = "us-central1",
  [string]$BillingAccount = "",
  [int]$BudgetAmount = 20,   # in the billing account's own currency (read from the account)
  [switch]$Yes
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot

function GCmd {   # run gcloud, return trimmed text output, remember the exit code
  $out = & gcloud @args 2>&1 | ForEach-Object { "$_" } | Out-String
  $script:rc = $LASTEXITCODE
  return $out.Trim()
}
function Step($msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
  Fail "gcloud is not installed. Install the Google Cloud CLI (winget install Google.CloudSDK), reopen the terminal, then run: gcloud auth login"
}
$acct = GCmd auth list --filter=status:ACTIVE "--format=value(account)"
if (-not $acct) { Fail "Not logged in. Run: gcloud auth login" }
if (-not $Project) { $Project = GCmd config get-value project }
if (-not $Project -or $Project -match "unset") { Fail "No project. Run: gcloud config set project <PROJECT_ID> (or pass -Project)" }
if ($Bucket -notmatch '^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$') { Fail "Invalid bucket name '$Bucket' (lowercase letters, digits, - _ .)" }

$trainer = "sfumato-trainer@$Project.iam.gserviceaccount.com"
$reader  = "sfumato-reader@$Project.iam.gserviceaccount.com"
Write-Host "Account : $acct"
Write-Host "Project : $Project"
Write-Host "Bucket  : gs://$Bucket  ($Region, uniform access, public access prevention)"
Write-Host "Create  : service accounts sfumato-trainer (write) + sfumato-reader (read-only), bucket-scoped"
$cur = ""
if ($BillingAccount) {
  $cur = GCmd billing accounts describe $BillingAccount "--format=value(currencyCode)"
  if ($rc -ne 0 -or -not $cur) { Fail "Cannot read billing account $BillingAccount : $cur" }
  Write-Host "Budget  : $BudgetAmount $cur on billing account $BillingAccount (alerts 25/50/100 %; amount is in the account currency)"
}
if (-not $Yes) { $a = Read-Host "Proceed? (y/N)"; if ($a -notmatch '^[yY]') { Fail "Cancelled." } }

Step "Enable APIs"
$null = GCmd services enable storage.googleapis.com iam.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com "--project=$Project"
if ($rc -ne 0) { Fail "Could not enable APIs (is billing linked to the project?)" }

Step "Bucket"
$null = GCmd storage buckets describe "gs://$Bucket" "--project=$Project"
if ($rc -eq 0) { Write-Host "already exists" } else {
  $o = GCmd storage buckets create "gs://$Bucket" "--project=$Project" "--location=$Region" --uniform-bucket-level-access --public-access-prevention
  if ($rc -ne 0) { Fail "Bucket creation failed (name taken globally?): $o" } else { Write-Host "created" }
}

Step "Service accounts"
foreach ($n in @("sfumato-trainer", "sfumato-reader")) {
  $null = GCmd iam service-accounts describe "$n@$Project.iam.gserviceaccount.com" "--project=$Project"
  if ($rc -eq 0) { Write-Host "$n exists" } else {
    $o = GCmd iam service-accounts create $n "--project=$Project" "--display-name=$n"
    if ($rc -ne 0) { Fail "$n : $o" } else { Write-Host "$n created" }
  }
}
Step "IAM (bucket level only)"
$null = GCmd storage buckets add-iam-policy-binding "gs://$Bucket" "--member=serviceAccount:$trainer" --role=roles/storage.objectAdmin
if ($rc -ne 0) { Fail "binding trainer failed" }
$null = GCmd storage buckets add-iam-policy-binding "gs://$Bucket" "--member=serviceAccount:$reader" --role=roles/storage.objectViewer
if ($rc -ne 0) { Fail "binding reader failed" }
Write-Host "trainer = objectAdmin, reader = objectViewer on gs://$Bucket"

Step "Keys"
$secrets = Join-Path $root "secrets"; New-Item -ItemType Directory -Force $secrets | Out-Null
$readerKey = Join-Path $secrets "gcs-reader.json"
if (Test-Path $readerKey) { Write-Host "reader key already present, kept" } else {
  $o = GCmd iam service-accounts keys create $readerKey "--iam-account=$reader"
  if ($rc -ne 0) { Fail "reader key: $o (organisation policy may forbid key creation)" } else { Write-Host "reader key -> secrets\gcs-reader.json (git-ignored)" }
}
$trainerKey = Join-Path $HOME "sfumato-trainer.json"
if (Test-Path $trainerKey) { Write-Host "trainer key already at $trainerKey, kept" } else {
  $o = GCmd iam service-accounts keys create $trainerKey "--iam-account=$trainer"
  if ($rc -ne 0) { Fail "trainer key: $o" } else { Write-Host "trainer key -> $trainerKey (OUTSIDE the repo)" }
}

if ($BillingAccount) {
  Step "Budget alert"
  $existing = GCmd billing budgets list "--billing-account=$BillingAccount" "--format=value(displayName)"
  if ($existing -match "sfumato-budget") { Write-Host "budget already exists" } else {
    $o = GCmd billing budgets create "--billing-account=$BillingAccount" --display-name=sfumato-budget "--budget-amount=$BudgetAmount$cur" `
      --threshold-rule=percent=0.25 --threshold-rule=percent=0.5 --threshold-rule=percent=1.0
    if ($rc -ne 0) { Write-Host "Budget NOT created: $o`nCreate it in the console (Billing > Budgets & alerts)." -ForegroundColor Yellow } else { Write-Host "budget created (alerts by e-mail only: a budget does not stop spending)" }
  }
} else {
  Write-Host "`nNo -BillingAccount given: create the budget in the console (Billing > Budgets & alerts)." -ForegroundColor Yellow
}

Step "Wire .env"
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) { Copy-Item (Join-Path $root ".env.example") $envFile }
$lines = [System.Collections.ArrayList]@(Get-Content $envFile)
function SetEnv($k, $v) {
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^$k=") { $lines[$i] = "$k=$v"; return } }
  [void]$lines.Add("$k=$v")
}
function GetEnv($k) { foreach ($l in $lines) { if ($l -match "^$k=(.*)$") { return $Matches[1] } } return "" }
SetEnv "ML_ARTIFACT_URI" "gs://$Bucket/sfumato"
SetEnv "KB_ARTIFACT_URI" "gs://$Bucket/sfumato"
SetEnv "GOOGLE_APPLICATION_CREDENTIALS" "/run/secrets/gcs-reader.json"
if (-not (GetEnv "ARTIFACT_SIGNING_KEY")) {
  $b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  SetEnv "ARTIFACT_SIGNING_KEY" (($b | ForEach-Object { $_.ToString("x2") }) -join "")
  Write-Host "ARTIFACT_SIGNING_KEY generated"
}
Set-Content -Path $envFile -Value $lines -Encoding ASCII
Write-Host ".env updated (ML_ARTIFACT_URI, KB_ARTIFACT_URI, GOOGLE_APPLICATION_CREDENTIALS, ARTIFACT_SIGNING_KEY)"

Write-Host "`nDone. Next, on Kaggle (see ml\guide\README.md section 2):" -ForegroundColor Green
Write-Host "  1. Secret ARTIFACT_SIGNING_KEY = value from .env     2. Secret GCP_SA_JSON = content of $trainerKey"
Write-Host "  3. BUCKET_URI = gs://$Bucket/sfumato in both notebooks, run them"
Write-Host "  4. Delete $trainerKey once pasted into Kaggle.   5. Restart Sfumato, then check GET /api/v1/ml/guide"
