-- Stratified sample of the clean CIC-IDS2018 flows, exported to the bucket for the streaming replay and the compact model.
-- Up to 20,000 flows per attack family and 120,000 benign flows, 26 numeric features + label + timestamp + day.
-- Run by scripts/gcp_stream_data.ps1 (the DATASET and BUCKET placeholders are replaced).
EXPORT DATA OPTIONS (
  uri = 'gs://BUCKET/stream/sample/part-*.parquet',
  format = 'PARQUET',
  overwrite = true
) AS
SELECT * EXCEPT (rn) FROM (
  SELECT
    `Dst Port`, `Protocol`, `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts`,
    `Fwd Pkt Len Max`, `Fwd Pkt Len Mean`, `Bwd Pkt Len Max`, `Bwd Pkt Len Mean`, `Flow Byts_s`, `Flow Pkts_s`,
    `Flow IAT Mean`, `Flow IAT Max`, `Fwd IAT Tot`, `Fwd PSH Flags`, `SYN Flag Cnt`, `RST Flag Cnt`, `ACK Flag Cnt`,
    `Init Fwd Win Byts`, `Init Bwd Win Byts`, `Pkt Len Mean`, `Down_Up Ratio`, `Active Mean`, `Idle Mean`,
    `Label`, `ts`, `day`,
    ROW_NUMBER() OVER (PARTITION BY `Label` ORDER BY RAND()) AS rn
  FROM `DATASET.flows`
)
WHERE rn <= IF(`Label` = 'Benign', 120000, 20000);
