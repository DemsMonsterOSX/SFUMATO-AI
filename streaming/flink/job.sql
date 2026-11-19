-- Flink SQL job: stateful windowed analytics over the network-flows topic (runs on the sfumato-flink VM).
-- The placeholder @BOOTSTRAP@ is replaced by the Kafka brokers when the VM installs the job.
-- Two outputs, both Kafka topics:
--   flow-aggregates : one row per 10-second event-time window (flows, attack flows from the replay labels, distinct destination
--                     ports, mean duration, SYN flows). Event time = the producer's sent_at, 5 seconds of lateness allowed.
--   rule-alerts     : per-port windows where a port receives a burst of very short flows (rate rules: brute force on 21/22, HTTP
--                     flood on 80/443/8080, other ports as high-rate). These rules need no model: they also flag attack families
--                     the model has never seen, which is the point of adding this stage next to the scorers.
-- The label field exists only because the traffic is a labelled replay: the rules never read it, it is used to measure them.

SET 'pipeline.name' = 'sfumato-flow-analytics';
SET 'parallelism.default' = '2';

CREATE TABLE flows (
  id STRING,
  sent_at DOUBLE,
  scenario STRING,
  label STRING,
  features MAP<STRING, DOUBLE>,
  ts AS TO_TIMESTAMP_LTZ(CAST(sent_at * 1000 AS BIGINT), 3),
  WATERMARK FOR ts AS ts - INTERVAL '5' SECOND
) WITH (
  'connector' = 'kafka',
  'topic' = 'network-flows',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'properties.group.id' = 'flink-analytics',
  'scan.startup.mode' = 'latest-offset',
  'format' = 'json',
  'json.ignore-parse-errors' = 'true'
);

CREATE TABLE flow_aggregates (
  window_start TIMESTAMP_LTZ(3),
  window_end TIMESTAMP_LTZ(3),
  flows BIGINT,
  attack_flows BIGINT,
  distinct_dst_ports BIGINT,
  avg_duration_us DOUBLE,
  syn_flows BIGINT
) WITH (
  'connector' = 'kafka',
  'topic' = 'flow-aggregates',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'format' = 'json'
);

CREATE TABLE rule_alerts (
  window_start TIMESTAMP_LTZ(3),
  window_end TIMESTAMP_LTZ(3),
  dst_port INT,
  flows BIGINT,
  attack_flows BIGINT,
  avg_duration_us DOUBLE,
  rule STRING
) WITH (
  'connector' = 'kafka',
  'topic' = 'rule-alerts',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'format' = 'json'
);

INSERT INTO flow_aggregates
SELECT window_start, window_end,
       COUNT(*) AS flows,
       SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END) AS attack_flows,
       COUNT(DISTINCT features['Dst Port']) AS distinct_dst_ports,
       AVG(features['Flow Duration']) AS avg_duration_us,
       SUM(CASE WHEN features['SYN Flag Cnt'] > 0 THEN 1 ELSE 0 END) AS syn_flows
FROM TABLE(TUMBLE(TABLE flows, DESCRIPTOR(ts), INTERVAL '10' SECOND))
GROUP BY window_start, window_end;

INSERT INTO rule_alerts
SELECT window_start, window_end,
       CAST(features['Dst Port'] AS INT) AS dst_port,
       COUNT(*) AS flows,
       SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END) AS attack_flows,
       AVG(features['Flow Duration']) AS avg_duration_us,
       CASE WHEN CAST(features['Dst Port'] AS INT) IN (21, 22) THEN 'bruteforce_burst'
            WHEN CAST(features['Dst Port'] AS INT) IN (80, 443, 8080) THEN 'http_flood_burst'
            ELSE 'high_rate_burst' END AS rule
FROM TABLE(TUMBLE(TABLE flows, DESCRIPTOR(ts), INTERVAL '10' SECOND))
GROUP BY window_start, window_end, features['Dst Port']
HAVING COUNT(*) >= 400 AND AVG(features['Flow Duration']) < 1000000;
