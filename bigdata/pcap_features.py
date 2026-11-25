"""Per-source behavioural features on Zeek conn logs of one day of CSE-CIC-IDS2018 (14 Feb 2018: FTP and SSH brute force).

  python bigdata/pcap_features.py --input <folder of conn-*.parquet> --output ml/bigdata/pcap_experiment.json

The processed CSV of the dataset has no addresses, so each flow is judged alone. With the raw capture (Zeek conn.log) we can describe
what one SOURCE did in one 60-second window (how many connections, to how many hosts and ports, how many failed ...) and ask the
question the flow-level model failed: does a detector trained on ONE attack family catch the OTHER one?

Labels: a window is an attack when its source is the attacker host of the day (FTP: 18.221.219.4, SSH: 13.58.98.64, from the dataset's
documentation: to be re-checked against the dataset page). Everything else is labelled benign, INCLUDING internet scanners that
also hit ports 21/22: the labels are therefore noisy on the benign side and the false-positive counts are an upper bound.
Only 1 attacker host per family exists: the windows of a family are not independent samples, so this is a worked example, not a
statistic. No raw port number or address is used as a feature (port 21 vs 22 would reveal the family).
"""
from __future__ import annotations

import argparse
import glob
import json
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

ATTACKERS = {"ftp": "18.221.219.4", "ssh": "13.58.98.64"}
FAILED = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"}
WIN = 60
FEATURES = ["log_n", "log_n_dst", "log_n_dport", "top_port_share", "conn_per_s", "dur_mean", "dur_std", "ob_mean", "ob_std", "rb_mean",
            "fail_frac", "tcp_frac", "short_frac"]


def windows(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={"id.orig_h": "src", "id.resp_h": "dst", "id.resp_p": "dport"})
    df["win"] = (df["ts"] // WIN).astype("int64")
    df["failed"] = df["conn_state"].isin(FAILED)
    df["dur"] = df["duration"].fillna(0.0)
    df["ob"] = df["orig_bytes"].fillna(0.0)
    df["rb"] = df["resp_bytes"].fillna(0.0)
    df["tcp"] = df["proto"].eq("tcp")
    df["short"] = df["dur"] < 1.0
    g = df.groupby(["src", "win"])
    out = g.agg(n=("uid", "size"), n_dst=("dst", "nunique"), n_dport=("dport", "nunique"), dur_mean=("dur", "mean"), dur_std=("dur", "std"),
                ob_mean=("ob", "mean"), ob_std=("ob", "std"), rb_mean=("rb", "mean"), fail_frac=("failed", "mean"), tcp_frac=("tcp", "mean"),
                short_frac=("short", "mean"))
    top = df.groupby(["src", "win", "dport"]).size().groupby(level=[0, 1]).max()
    out["top_port_share"] = top / out["n"]
    out = out.reset_index()
    out["log_n"] = np.log1p(out["n"]); out["log_n_dst"] = np.log1p(out["n_dst"]); out["log_n_dport"] = np.log1p(out["n_dport"])
    out["conn_per_s"] = out["n"] / WIN
    out[["dur_std", "ob_std"]] = out[["dur_std", "ob_std"]].fillna(0.0)
    out["family"] = out["src"].map({v: k for k, v in ATTACKERS.items()}).fillna("benign")
    out["t"] = out["win"] * WIN
    return out


def metrics(y_true: np.ndarray, pred: np.ndarray) -> dict:
    tp = int(((pred == 1) & (y_true == 1)).sum()); fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum()); tn = int(((pred == 0) & (y_true == 0)).sum())
    return {"attack_windows": int((y_true == 1).sum()), "benign_windows": int((y_true == 0).sum()), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": round(tp / max(1, tp + fn), 4), "precision": round(tp / max(1, tp + fp), 4), "false_positive_rate": round(fp / max(1, fp + tn), 5)}


def fit_eval(train: pd.DataFrame, test: pd.DataFrame, label: str) -> dict:
    w = np.where(train["y"] == 1, (train["y"] == 0).sum() / max(1, (train["y"] == 1).sum()), 1.0)
    m = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(train[FEATURES], train["y"], sample_weight=w)
    pred = m.predict(test[FEATURES])
    rule = (test["n"] >= 200).astype(int).to_numpy()   # the Flink-style rule: 200 or more connections from one source in a minute
    return {"experiment": label, "model": metrics(test["y"].to_numpy(), pred), "rule_200_conn_per_min": metrics(test["y"].to_numpy(), rule)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    t0 = time.time()
    df = pd.concat([pd.read_parquet(f, columns=["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state"])
                    for f in sorted(glob.glob(a.input.rstrip("/\\") + "/*.parquet"))], ignore_index=True)
    w = windows(df)
    w["y"] = (w["family"] != "benign").astype(int)
    cut = w.loc[w["family"] == "benign", "t"].quantile(0.6)           # benign: first 60 % of the day to train, the rest to test
    ben_tr, ben_te = w[(w["family"] == "benign") & (w["t"] <= cut)], w[(w["family"] == "benign") & (w["t"] > cut)]
    ftp, ssh = w[w["family"] == "ftp"], w[w["family"] == "ssh"]
    half = lambda d: (d[d["t"] <= d["t"].median()], d[d["t"] > d["t"].median()])  # noqa: E731
    f_tr, f_te = half(ftp); s_tr, s_te = half(ssh)
    res = {
        "input_connections": int(len(df)), "windows": int(len(w)), "window_seconds": WIN, "features": FEATURES, "benign_cut_ts": float(cut),
        "windows_by_family": w["family"].value_counts().to_dict(),
        "noise_note": "benign side includes unlabelled internet scanners; windows with >= 100 connections from non-attacker external hosts: "
                      + str(int(((w["family"] == "benign") & (w["n"] >= 100) & ~w["src"].astype(str).str.startswith("172.31")).sum())),
        "experiments": [
            fit_eval(pd.concat([ben_tr, f_tr]), pd.concat([ben_te, f_te]), "seen: train FTP (first half) -> test FTP (second half)"),
            fit_eval(pd.concat([ben_tr, ftp]), pd.concat([ben_te, ssh]), "unseen: train FTP -> test SSH"),
            fit_eval(pd.concat([ben_tr, s_tr]), pd.concat([ben_te, s_te]), "seen: train SSH (first half) -> test SSH (second half)"),
            fit_eval(pd.concat([ben_tr, ssh]), pd.concat([ben_te, ftp]), "unseen: train SSH -> test FTP"),
        ],
        "seconds": round(time.time() - t0, 1),
    }
    json.dump(res, open(a.output, "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
