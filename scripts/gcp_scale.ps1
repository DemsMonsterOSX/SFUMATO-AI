<#
 Scalability test of the Kafka scoring pipeline: throughput the scorers sustain with 1, 2 and 3 scorer instances.

   .\scripts\gcp_scale.ps1 prepare    copy streaming/scale_test.py and the replay file to the load-generator VM (sfumato-qwen, 4 vCPU)
   .\scripts\gcp_scale.ps1 run        for 1, 2, 3 scorers: set the roles, wait for the rebalance, ramp the rate from the load generator,
                                      save ml/scale/kafka_scorers<k>.json (Kafka VMs and sfumato-qwen must be running)
   .\scripts\gcp_scale.ps1 restore    put the regular roles back (producer + 3 scorers + CVE bridge/consumer + controller)

 The load generator is a separate VM so that the producers do not compete with a broker or a scorer (the first stress test was
 limited by its own producer). Scorers log to Logstash as in normal operation. Cost: the VMs that are already running; nothing is created.
#>
param(
  [ValidateSet("prepare", "run", "restore")][string]$Action = "run",
  [string]$Project = "gen-lang-client-0426716352",
  [string]$Zone = "us-central1-a",
  [string]$Targets = "600,1200,2400,4800,7200,9600,12000",
  [int]$StepSeconds = 30,
  [string]$LoadGen = "sfumato-qwen",
  [int[]]$Scorers = @(1, 2, 3),
  [int]$Producers = 3,
  [string]$Tag = ""
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$g = (Get-Command gcloud.cmd).Source
function G { $o = & $g @args 2>&1 | ForEach-Object { "$_" } | Out-String; $script:rc = $LASTEXITCODE; return $o.Trim() }
$boot = (1..3 | ForEach-Object { "sfumato-kafka-$_.$Zone.c.$Project.internal:9092" }) -join ","

function Set-Roles($roles) {
  foreach ($i in 1..3) {
    $f = Join-Path ([IO.Path]::GetTempPath()) "sfumato-scale-roles-$i"; [IO.File]::WriteAllText($f, $roles[$i])
    $null = G compute instances add-metadata "sfumato-kafka-$i" "--zone=$Zone" "--project=$Project" "--metadata-from-file=stream-roles=$f"
  }
}

switch ($Action) {
  "prepare" {
    $s = Join-Path $root "streaming"
    Write-Host (G compute scp (Join-Path $s "scale_test.py") (Join-Path $s "model\replay_known.parquet") "${LoadGen}:/tmp/" "--zone=$Zone" "--project=$Project" --quiet)
    Write-Host "Copied. Python dependencies are installed with the one-time setup script (see docs/SCALABILITY.md)."
  }
  "run" {
    $null = & powershell -File (Join-Path $PSScriptRoot "gcp_stream.ps1") -Action run -Scenario known -Rate 1   # writes stream-env (scenario, token, Logstash); roles are overridden next
    New-Item -ItemType Directory -Force (Join-Path $root "ml\scale") | Out-Null
    foreach ($k in $Scorers) {
      $roles = @{ 1 = ""; 2 = ""; 3 = "" }
      $holders = @(3, 2, 1)[0..($k - 1)]
      foreach ($h in $holders) { $roles[$h] = "scorer" }
      Write-Host "`n== $k scorer(s) on kafka-$($holders -join ', kafka-')" -ForegroundColor Cyan
      Set-Roles $roles
      Start-Sleep -Seconds 100   # the sync timer applies roles within 30 s, the group rebalances, the old backlog drains
      $cmd = "~/lg/venv/bin/python ~/lg/scale_test.py --bootstrap $boot --parquet ~/lg/replay_known.parquet --label scorers=$k --targets $Targets --step-seconds $StepSeconds --producers $Producers --json /home/flori/lg/out_$k$Tag.json > /home/flori/lg/log_$k$Tag.txt 2>&1; tail -n 3 /home/flori/lg/log_$k$Tag.txt"
      Write-Host (G compute ssh $LoadGen "--zone=$Zone" "--project=$Project" --quiet "--command=$cmd")
      $dest = Join-Path $root "ml\scale\kafka_scorers$k$Tag.json"
      Write-Host (G compute scp "${LoadGen}:/home/flori/lg/out_$k$Tag.json" $dest "--zone=$Zone" "--project=$Project" --quiet)
    }
    Write-Host "`nDone. Results in ml/scale/kafka_scorers{1,2,3}.json. Restore the regular roles with: .\scripts\gcp_scale.ps1 restore" -ForegroundColor Green
  }
  "restore" {
    Set-Roles @{ 1 = "producer,scorer,cve-bridge,controller"; 2 = "scorer,cve-consumer"; 3 = "scorer" }
    Write-Host "Regular roles restored." -ForegroundColor Green
  }
}
