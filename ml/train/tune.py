"""M2-04: hyper-parameter search for the binary RandomForest, on an objective that actually discriminates.

    python -m ml.train.tune [--configs 12] [--minutes 25]

In-distribution validation is saturated (every config scores ~100%), so tuning on it would be noise. Instead each
config is scored by TOOL-HOLDOUT detection: retrain without one attack tool, then measure recall on that tool at a
strict benign false-alarm budget (calibrated on validation benign flows). Objective = mean recall over the
tuning tools at 0.05% FPR (tie-break: at 0.01%).
Tuning tools: LOIC-HTTP, Hulk, GoldenEye, Slowloris. DDoS-HOIC is deliberately NOT used for selection, so the
headline demo tool is an untouched check. Random search (seeded), time-boxed, validation only.
Writes artifacts/experiments/tune/results.json.
"""

from __future__ import annotations

import argparse
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluate import metrics as M
from ml.train.common import SEED, dump_json, fit_transformer, is_attack, load_split, out_dir, timed

TUNE_TOOLS = ["DDoS-LOIC-HTTP", "DoS Hulk", "DoS GoldenEye", "DoS Slowloris"]
SPACE = {
    "max_depth": [10, 16, 24, None],
    "min_samples_leaf": [1, 2, 5, 20, 100],
    "max_features": ["sqrt", 0.2, 0.5],
    "class_weight": [None, "balanced_subsample"],
}
TRAIN_ROWS = 600_000
TREES = 60
BUDGETS = (0.0005, 0.0001)


def sample_config(rng: np.random.Generator) -> dict:
    return {k: v[rng.integers(len(v))] for k, v in SPACE.items()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--configs", type=int, default=12)
    ap.add_argument("--minutes", type=float, default=25)
    a = ap.parse_args()
    train, val = load_split("cic", "train"), load_split("cic", "val")
    tr = fit_transformer("cic", train)
    sub = train.sample(TRAIN_ROWS, random_state=SEED).reset_index(drop=True)
    Xs, Xv = tr.transform(sub), tr.transform(val)
    ys = is_attack(sub, "cic")
    benign_v = (val["tool"] == "BENIGN").to_numpy()
    rng = np.random.default_rng(SEED)
    default = {"max_depth": None, "min_samples_leaf": 2, "max_features": "sqrt", "class_weight": "balanced_subsample"}
    configs = [default] + [sample_config(rng) for _ in range(a.configs - 1)]
    deadline = time.time() + a.minutes * 60
    results = []
    for i, cfg in enumerate(configs):
        if time.time() > deadline:
            print("time box reached", flush=True)
            break
        per_tool: dict[str, dict] = {}
        with timed(f"config {i}: {cfg}"):
            for tool in TUNE_TOOLS:
                keep = (sub["tool"] != tool).to_numpy()
                rf = RandomForestClassifier(n_estimators=TREES, n_jobs=-1, random_state=SEED, **cfg)
                rf.fit(Xs[keep], ys[keep])
                p = rf.predict_proba(Xv)[:, 1]
                held = (val["tool"] == tool).to_numpy()
                per_tool[tool] = {}
                for b in BUDGETS:
                    thr = M.threshold_for_fpr(np.zeros(int(benign_v.sum()), int), p[benign_v], b)
                    per_tool[tool][str(b)] = float((p[held] >= thr).mean())
        score = {str(b): float(np.mean([per_tool[t][str(b)] for t in TUNE_TOOLS])) for b in BUDGETS}
        results.append({"config": cfg, "mean_recall": score, "per_tool": per_tool})
        print(f"    mean recall @0.05% = {score['0.0005']:.3f} | @0.01% = {score['0.0001']:.3f}  "
              + " ".join(f"{t.split()[-1]}={per_tool[t]['0.0005']:.2f}" for t in TUNE_TOOLS), flush=True)
    results.sort(key=lambda r: (r["mean_recall"]["0.0005"], r["mean_recall"]["0.0001"]), reverse=True)
    dump_json(out_dir("tune") / "results.json", {"tune_tools": TUNE_TOOLS, "budgets": BUDGETS, "ranked": results})
    best = results[0]
    print("\nBEST:", best["config"], best["mean_recall"])


if __name__ == "__main__":
    main()
