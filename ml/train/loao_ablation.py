"""M2-08b: is the RF's generalisation to unseen families real, or a host-fingerprint shortcut?

    python -m ml.train.loao_ablation

Repeats the leave-one-family-out test (RF only, equal benign FPR = 0.5%, calibrated on validation, evaluated on
validation) with feature groups removed from BOTH training and scoring:
  all_46                  the production feature set
  minus_init_window       no TCP initial-window sizes (a Kali-vs-Windows OS fingerprint)
  minus_window_and_flags  also no TCP flag counts
  behavioural_core        only size / count / timing features (no window, flags, protocol, ICMP, header bytes)
If recall on held-out families survives, the model is recognising attack BEHAVIOUR, not who sent it.
Writes artifacts/experiments/loao_ablation/results.json.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluate import metrics as M
from ml.train.common import SEED, dump_json, is_attack, load_split, out_dir, timed
from ml.train.feature_ablation import FLAGS, WINDOW, variant_spec
from ml.train.holdouts import LOAO_FAMILIES, RF_TRAIN
from nscore.features.transform import FlowTransformer

BUDGET = 0.005
NON_BEHAVIOURAL = [*WINDOW, *FLAGS, "protocol", "icmp_code", "fwd_seg_size_min", "total_tcp_flow_time"]


def main() -> None:
    train, val = load_split("cic", "train"), load_split("cic", "val")
    sub = train.sample(RF_TRAIN, random_state=SEED)
    benign_v = (val["tool"] == "BENIGN").to_numpy()
    variants = {"all_46": [], "minus_init_window": WINDOW, "minus_window_and_flags": WINDOW + FLAGS,
                "behavioural_core": NON_BEHAVIOURAL}
    out: dict = {"budget": BUDGET}
    for name, drop in variants.items():
        tr = FlowTransformer(variant_spec(drop)).fit(train)
        Xv = tr.transform(val)
        out[name] = {"n_features": len(tr.feature_names)}
        for fam in LOAO_FAMILIES:
            with timed(f"{name} / hold out {fam}"):
                keep = sub[sub["family"] != fam]
                rf = RandomForestClassifier(n_estimators=60, min_samples_leaf=2, class_weight="balanced_subsample",
                                            n_jobs=-1, random_state=SEED)
                rf.fit(tr.transform(keep), is_attack(keep, "cic"))
                p = rf.predict_proba(Xv)[:, 1]
            t = M.threshold_for_fpr(np.zeros(int(benign_v.sum()), int), p[benign_v], BUDGET)
            held = (val["family"] == fam).to_numpy()
            k = int((p[held] >= t).sum())
            out[name][fam] = {"recall": k / int(held.sum()), "ci95": M.wilson(k, int(held.sum())), "n": int(held.sum())}
        print(f"== {name} ({out[name]['n_features']} features): "
              + "  ".join(f"{f}={out[name][f]['recall']:.3f}" for f in LOAO_FAMILIES), flush=True)
    dump_json(out_dir("loao_ablation") / "results.json", out)
    np.save(out_dir("loao_ablation") / ".done.npy", np.zeros(1))


if __name__ == "__main__":
    main()
