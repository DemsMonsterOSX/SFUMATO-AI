-- Flink SQL job: per-SOURCE behaviour over 60-second event-time windows, on Zeek connection records (topic conn-events).
-- The flow-level job (job.sql) sees no addresses. Here the key is the source address, so state is kept per source and the work
-- scales with the parallelism (records of one source always go to the same subtask).
-- Two rules in one job (STATEMENT SET: the topic is read once):
--   source-alerts / concentrated_source : at least 200 connections from one source in a minute, to at most 2 hosts and at most 2 ports
--                                         (brute force and floods concentrate on a target; scanners and busy hosts spread out)
--   naive-alerts  / volume_only         : at least 200 connections from one source in a minute (the flow-level rule moved to sources)
-- The family field exists because the replay is labelled: the rules never read it, it is only counted to measure them.
-- Placeholders: @BOOTSTRAP@ (Kafka brokers) and @PARALLELISM@ (set by the VM at submission).

SET 'pipeline.name' = 'sfumato-source-rules';
SET 'parallelism.default' = '@PARALLELISM@';

CREATE TABLE conns (
  src STRING,
  dst STRING,
  dport INT,
  ts_s DOUBLE,
  family STRING,
  ts AS TO_TIMESTAMP_LTZ(CAST(ts_s * 1000 AS BIGINT), 3),
  WATERMARK FOR ts AS ts - INTERVAL '30' SECOND
) WITH (
  'connector' = 'kafka',
  'topic' = 'conn-events',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'properties.group.id' = 'flink-source-rules',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.ignore-parse-errors' = 'true'
);

CREATE TABLE source_alerts (
  window_start TIMESTAMP_LTZ(3),
  window_end TIMESTAMP_LTZ(3),
  src STRING,
  conns BIGINT,
  dst_hosts BIGINT,
  dst_ports BIGINT,
  attack_conns BIGINT,
  rule STRING
) WITH (
  'connector' = 'kafka',
  'topic' = 'source-alerts',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'format' = 'json'
);

CREATE TABLE naive_alerts (
  window_start TIMESTAMP_LTZ(3),
  window_end TIMESTAMP_LTZ(3),
  src STRING,
  conns BIGINT,
  dst_hosts BIGINT,
  dst_ports BIGINT,
  attack_conns BIGINT,
  rule STRING
) WITH (
  'connector' = 'kafka',
  'topic' = 'naive-alerts',
  'properties.bootstrap.servers' = '@BOOTSTRAP@',
  'format' = 'json'
);

EXECUTE STATEMENT SET
BEGIN
INSERT INTO source_alerts
SELECT window_start, window_end, src,
       COUNT(*) AS conns, COUNT(DISTINCT dst) AS dst_hosts, COUNT(DISTINCT dport) AS dst_ports,
       SUM(CASE WHEN family <> 'benign' THEN 1 ELSE 0 END) AS attack_conns,
       'concentrated_source' AS rule
FROM TABLE(TUMBLE(TABLE conns, DESCRIPTOR(ts), INTERVAL '60' SECOND))
GROUP BY window_start, window_end, src
HAVING COUNT(*) >= 200 AND COUNT(DISTINCT dst) <= 2 AND COUNT(DISTINCT dport) <= 2;
INSERT INTO naive_alerts
SELECT window_start, window_end, src,
       COUNT(*) AS conns, COUNT(DISTINCT dst) AS dst_hosts, COUNT(DISTINCT dport) AS dst_ports,
       SUM(CASE WHEN family <> 'benign' THEN 1 ELSE 0 END) AS attack_conns,
       'volume_only' AS rule
FROM TABLE(TUMBLE(TABLE conns, DESCRIPTOR(ts), INTERVAL '60' SECOND))
GROUP BY window_start, window_end, src
HAVING COUNT(*) >= 200;
END;
