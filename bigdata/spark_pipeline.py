"""Phases 1-2-4 on Spark: batch cleaning, exploratory aggregates and distributed ML on CSE-CIC-IDS2018 (6.9 GB of labelled
network flows, 10 days of benign traffic + attack families: brute force, DoS, DDoS, botnet, web attacks, infiltration).

  Dataproc Serverless:  see scripts/gcp_bigdata.ps1
  local smoke test:     python bigdata/spark_pipeline.py --input bigdata/_sample --output bigdata/_out --train-rows 20000

Outputs (under --output): parquet/ (clean data partitioned by day) and results_json/ (all figures used by the report).
Design choices are explained in docs/BIGDATA_PROJECT.md.
"""
from __future__ import annotations

import argparse
import json
import time

from pyspark.ml import Pipeline
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.feature import VectorAssembler
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

NON_FEATURES = {"Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp", "Label", "source_file"}
TS_FORMATS = ["dd/MM/yyyy HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "dd/MM/yyyy HH:mm"]


def load_raw(spark: SparkSession, path: str) -> DataFrame:
    """Read every CSV as strings (headers differ between days: 80 vs 84 columns) and union them by column name."""
    files = [r.path for r in spark.read.format("binaryFile").option("pathGlobFilter", "*.csv").load(path).select("path").collect()]
    frames = [spark.read.option("header", True).option("inferSchema", False).csv(f).withColumn("source_file", F.lit(f.rsplit("/", 1)[-1]))
              for f in files]
    df = frames[0]
    for f in frames[1:]:
        df = df.unionByName(f, allowMissingColumns=True)
    return df


def clean(df: DataFrame) -> tuple[DataFrame, list[str]]:
    # repeated header lines are embedded in some files: they are data rows whose Label equals "Label"
    df = df.filter(F.col("Label") != "Label")
    feats = [c for c in df.columns if c not in NON_FEATURES]
    df = df.withColumn("ts", F.coalesce(*[F.to_timestamp("Timestamp", f) for f in TS_FORMATS]))
    for c in feats:   # strings -> double; "Infinity"/"NaN" become null
        col = F.col(f"`{c}`").cast("double")
        df = df.withColumn(c, F.when(F.isnan(col) | col.isin(float("inf"), float("-inf")), None).otherwise(col))
    df = df.dropna(subset=["ts", "Label"] + feats)
    df = df.filter(F.col("Flow Duration") >= 0)   # negative durations are capture artefacts
    df = (df.withColumn("is_attack", (F.col("Label") != "Benign").cast("int"))
            .withColumn("day", F.to_date("ts")).withColumn("hour", F.hour("ts")))
    return df, feats


def eda(df: DataFrame) -> dict:
    out: dict = {}
    out["label_counts"] = {r["Label"]: r["n"] for r in df.groupBy("Label").agg(F.count("*").alias("n")).collect()}
    out["per_day"] = [{"day": str(r["day"]), "flows": r["flows"], "attacks": r["attacks"]} for r in
                      df.groupBy("day").agg(F.count("*").alias("flows"), F.sum("is_attack").alias("attacks")).orderBy("day").collect()]
    out["attacks_by_hour"] = {int(r["hour"]): r["n"] for r in
                              df.filter("is_attack = 1").groupBy("hour").agg(F.count("*").alias("n")).collect()}
    out["top_attack_ports"] = [{"port": r["Dst Port"], "n": r["n"]} for r in df.filter("is_attack = 1").groupBy("Dst Port")
                               .agg(F.count("*").alias("n")).orderBy(F.desc("n")).limit(10).collect()]
    # per-class medians (approximate quantile: one cheap pass even on 16M rows)
    out["median_by_label"] = [{"label": r["Label"], "flow_duration_us": r["d"], "fwd_pkts": r["p"]} for r in
                              df.groupBy("Label").agg(F.expr("percentile_approx(`Flow Duration`, 0.5)").alias("d"),
                                                      F.expr("percentile_approx(`Tot Fwd Pkts`, 0.5)").alias("p")).collect()]
    return out


def train_eval(df: DataFrame, feats: list[str], train_rows: int, seed: int = 42) -> dict:
    """Random Forest, binary (attack vs benign). Two evaluations: random 80/20 split and a time hold-out
    (train on the earlier days, test on the last days: closer to deployment, since attack families differ per day)."""
    asm = VectorAssembler(inputCols=feats, outputCol="features", handleInvalid="skip")
    rf = RandomForestClassifier(labelCol="is_attack", featuresCol="features", numTrees=60, maxDepth=12, maxBins=64, seed=seed,
                                subsamplingRate=0.5)
    pipe = Pipeline(stages=[asm, rf])
    roc = BinaryClassificationEvaluator(labelCol="is_attack", metricName="areaUnderROC")
    pr = BinaryClassificationEvaluator(labelCol="is_attack", metricName="areaUnderPR")

    def metrics(pred: DataFrame) -> dict:
        cm = {(r["is_attack"], int(r["prediction"])): r["n"]
              for r in pred.groupBy("is_attack", "prediction").agg(F.count("*").alias("n")).collect()}
        tp, fp, fn, tn = cm.get((1, 1), 0), cm.get((0, 1), 0), cm.get((1, 0), 0), cm.get((0, 0), 0)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        return {"auc_roc": roc.evaluate(pred), "auc_pr": pr.evaluate(pred), "precision": prec, "recall": rec,
                "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
                "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "test_rows": tp + fp + fn + tn}

    def capped(train: DataFrame) -> DataFrame:
        n = train.count()
        return train.sample(False, min(1.0, train_rows / max(n, 1)), seed) if n > train_rows else train

    res: dict = {"features": len(feats), "train_rows_cap": train_rows}
    tr, te = df.randomSplit([0.8, 0.2], seed)
    model = pipe.fit(capped(tr))
    res["random_split"] = metrics(model.transform(te))
    imp = sorted(zip(feats, model.stages[-1].featureImportances.toArray()), key=lambda x: -x[1])[:15]
    res["feature_importances"] = [{"feature": f, "importance": float(v)} for f, v in imp]

    days = [r["day"] for r in df.select("day").distinct().orderBy("day").collect()]
    if len(days) >= 3:
        cut = days[int(len(days) * 0.7)]
        tr, te = df.filter(F.col("day") < cut), df.filter(F.col("day") >= cut)
        if tr.limit(1).count() and te.limit(1).count():
            res["time_holdout"] = {"cutoff_day": str(cut), **metrics(pipe.fit(capped(tr)).transform(te))}
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="folder with the raw CSV files (gs://... or local)")
    ap.add_argument("--output", required=True, help="output folder (gs://... or local)")
    ap.add_argument("--train-rows", type=int, default=2_000_000)
    ap.add_argument("--skip-ml", action="store_true")
    a = ap.parse_args()
    spark = SparkSession.builder.appName("sfumato-bigdata").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    t0 = time.time()
    raw = load_raw(spark, a.input)
    raw_count = raw.count()   # one pass over the raw data: this is the volume figure reported
    df, feats = clean(raw)
    out = a.output.rstrip("/")
    df.write.mode("overwrite").partitionBy("day").parquet(f"{out}/parquet")
    df = spark.read.parquet(f"{out}/parquet").cache()   # later steps use the compact columnar copy
    clean_count = df.count()
    results = {"raw_rows": raw_count, "clean_rows": clean_count, "dropped_rows": raw_count - clean_count,
               "prep_seconds": round(time.time() - t0), "eda": eda(df)}
    if not a.skip_ml:
        t1 = time.time()
        results["ml"] = train_eval(df, feats, a.train_rows)
        results["ml_seconds"] = round(time.time() - t1)
    results["total_seconds"] = round(time.time() - t0)
    spark.createDataFrame([(json.dumps(results, default=str),)], ["json"]).coalesce(1).write.mode("overwrite").text(f"{out}/results_json")
    print(json.dumps(results, indent=2, default=str))
    spark.stop()


if __name__ == "__main__":
    main()
