"""M2-03b: do shortcut features carry the model? (B12 and the TCP-window concern)

    python -m ml.train.feature_ablation

The corrected CIC data still comes from a lab where attackers are Kali Linux boxes and victims are Windows/Ubuntu
hosts, so TCP stack fingerprints (initial window sizes) can separate attack from benign without any attack behaviour.
The baseline's top features are exactly those. This script retrains the binary RF without feature groups and compares
validation recall / FPR / per-tool recall. If recall barely moves, the model is not leaning on the shortcut; if it
collapses for some tools, those tools are being recognised by host fingerprint.

Variants: all 46 | + dst_port (B12) | - init window bytes | - TCP flag counts | - both groups.
Trained on a 1M-row train subsample, validation only. Writes artifacts/experiments/feature_ablation/results.json.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluate import metrics as M
from ml.evaluate.weights import cic_weights
from ml.train.baseline import per_tool_recall
from ml.train.common import SEED, SPECS, dump_json, is_attack, load_split, out_dir, timed
from nscore.features.transform import FeatureSpec, FlowTransformer

TRAIN_ROWS = 1_000_000
WINDOW = ["fwd_init_win_bytes", "bwd_init_win_bytes"]
FLAGS = ["fin_flag_count", "syn_flag_count", "rst_flag_count", "cwr_flag_count", "fwd_psh_flags", "bwd_psh_flags",
         "fwd_urg_flags", "fwd_rst_flags", "bwd_rst_flags"]


def variant_spec(drop: list[str]) -> FeatureSpec:
    data = dict(FeatureSpec.load(SPECS["cic"]).data)
    data["features"] = [f for f in data["features"] if f["name"] not in drop]
    return FeatureSpec.from_dict(data)


def main() -> None:
    train, val = load_split("cic", "train").sample(TRAIN_ROWS, random_state=SEED), load_split("cic", "val")
    w, yv, tools = cic_weights(val, "val"), is_attack(val, "cic"), val["tool"].to_numpy()
    variants = {"all_46": ([], ()), "plus_dst_port": ([], ("dst_port",)), "minus_init_window": (WINDOW, ()),
                "minus_tcp_flags": (FLAGS, ()), "minus_window_and_flags": (WINDOW + FLAGS, ())}
    results = {}
    for name, (drop, opt) in variants.items():
        spec = variant_spec(drop)
        tr = FlowTransformer(spec, include_optional=opt).fit(train)
        with timed(f"{name} ({len(tr.feature_names)} features)"):
            rf = RandomForestClassifier(n_estimators=80, min_samples_leaf=2, class_weight="balanced_subsample",
                                        n_jobs=-1, random_state=SEED).fit(tr.transform(train), is_attack(train, "cic"))
            p = rf.predict_proba(tr.transform(val))[:, 1]
        thr = M.threshold_for_fpr(yv, p, 0.001)
        pt = per_tool_recall(tools, yv, p >= thr)
        results[name] = {
            "n_features": len(tr.feature_names), "at_0.5": M.binary_report(yv, p, 0.5, w),
            "at_fpr_0.1pct": M.binary_report(yv, p, thr, w), "per_tool_recall_at_fpr_0.1pct": pt,
            "worst_tool": min(((t, r["recall"]) for t, r in pt.items() if r["n"] >= 100), key=lambda kv: kv[1]),
            "top_features": [(n, round(float(v), 4)) for n, v in sorted(
                zip(tr.feature_names, rf.feature_importances_, strict=True), key=lambda kv: -kv[1])[:5]],
        }
        r = results[name]["at_fpr_0.1pct"]
        print(f"  {name:24s} recall@FPR0.1%={r['recall']:.4f} precision={r['precision']:.4f} "
              f"AUC={r['roc_auc']:.5f} worst tool={results[name]['worst_tool']}", flush=True)
    dump_json(out_dir("feature_ablation") / "results.json", results)
    np.save(out_dir("feature_ablation") / ".done.npy", np.zeros(1))


if __name__ == "__main__":
    main()
