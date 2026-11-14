-- Phase 2/5 analytics in BigQuery over the clean Parquet (table DATASET.flows is partitioned by day). Replaced by gcp_bigdata.ps1.

-- 1. Volume and class balance
SELECT Label, COUNT(*) AS flows, ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 3) AS pct
FROM `DATASET.flows` GROUP BY Label ORDER BY flows DESC;

-- 2. Attack intensity per day (which days carry which attack families)
SELECT day, Label, COUNT(*) AS flows
FROM `DATASET.flows` WHERE is_attack = 1 GROUP BY day, Label ORDER BY day, flows DESC;

-- 3. Hours of the day with the highest share of malicious flows
SELECT hour, COUNT(*) AS flows, ROUND(100 * AVG(is_attack), 2) AS attack_pct
FROM `DATASET.flows` GROUP BY hour ORDER BY hour;

-- 4. Behavioural fingerprint of each class (medians): how attacks differ from benign traffic
SELECT Label,
       APPROX_QUANTILES(`Flow Duration`, 100)[OFFSET(50)] AS median_duration_us,
       APPROX_QUANTILES(`Tot Fwd Pkts`, 100)[OFFSET(50)] AS median_fwd_pkts,
       APPROX_QUANTILES(`Pkt Len Mean`, 100)[OFFSET(50)] AS median_pkt_len
FROM `DATASET.flows` GROUP BY Label ORDER BY Label;

-- 5. Destination ports most targeted by attacks
SELECT `Dst Port` AS port, COUNT(*) AS attack_flows
FROM `DATASET.flows` WHERE is_attack = 1 GROUP BY port ORDER BY attack_flows DESC LIMIT 10;
