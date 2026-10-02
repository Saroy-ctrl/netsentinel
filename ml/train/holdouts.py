"""M2-08: leave-one-attack-family-out (LOAO) and tool-holdout experiments, the headline evidence for "catches what
signatures miss".

    python -m ml.train.holdouts                  # explore on the validation split
    python -m ml.train.holdouts --split test     # final numbers: run once, after the design is frozen

For each held-out unit (a whole FAMILY, or one TOOL that has sibling tools) both heads are retrained WITHOUT it, then:
  * detection recall of the held-out flows at several benign false-alarm budgets (calibrated on validation benign flows)
  * how many detected held-out flows are labelled NOVEL (unfamiliar) vs mislabelled as a known family
  * false "novel" rate on familiar attacks and on benign false alarms
  * precision of the NOVEL bucket at natural prevalence (benign and attacks re-weighted to the full split)
`seen` is the same model trained WITH the unit, i.e. the in-distribution ceiling.
With --seeds N the whole experiment is repeated with N different training subsamples / forest seeds; recall is
reported as mean with min and max (single runs are knife-edge at strict budgets: SSH brute force read 0.998 and
0.11 in two runs).
Writes artifacts/experiments/holdouts_<split>/results.json.
"""

from __future__ import annotations

import argparse

import numpy as np

from ml.evaluate import metrics as M
from ml.evaluate.weights import cic_weights
from ml.train import pipeline as P
from ml.train.common import SEED, dump_json, fit_transformer, load_split, out_dir, timed

LOAO_FAMILIES = ["DoS", "DDoS", "BruteForce", "Infiltration", "Botnet"]
TOOLS = {"DDoS-HOIC": "DDoS", "DDoS-LOIC-HTTP": "DDoS", "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
         "DoS Slowloris": "DoS"}
BUDGETS = [0.0001, 0.0005, 0.001, 0.005]
RF_TRAIN = 1_000_000
FALSE_NOVEL = 0.02


def run_unit(label: str, held_col: str, held_value: str, sub, Xv, Xe, val, ev, tr, w, full: P.Models,
             seed: int = SEED, params: dict | None = None) -> dict:
    mask = (sub[held_col] == held_value).to_numpy()
    m = P.fit_models(sub, tr, exclude=mask, seed=seed, **(params or {}))
    p_v, c_v, _ = P.scores(m, Xv)
    p_e, c_e, _ = P.scores(m, Xe)
    benign_v = (val["tool"] == "BENIGN").to_numpy()
    familiar_v = (val["family"] != "BENIGN").to_numpy() & (val[held_col] != held_value).to_numpy()
    held = (ev[held_col] == held_value).to_numpy()
    benign_e = (ev["tool"] == "BENIGN").to_numpy()
    familiar_e = (ev["family"] != "BENIGN").to_numpy() & ~held
    pf_v, _, _ = P.scores(full, Xv)
    pf_e, _, _ = P.scores(full, Xe)
    row = {"label": label, "n_held_out": int(held.sum()), "budgets": {}}
    for b in BUDGETS:
        tau = P.operating_point(p_v, c_v, benign_v, familiar_v, b, FALSE_NOVEL)
        flagged, novel = P.decide(p_e, c_e, tau)
        tau_full = M.threshold_for_fpr(np.zeros(int(benign_v.sum()), int), pf_v[benign_v], b)
        det = flagged & held
        k = int(det.sum())
        lo, hi = M.wilson(k, int(held.sum()))
        nov_w = float(w[novel].sum())
        row["budgets"][str(b)] = {
            "recall": k / max(int(held.sum()), 1), "recall_ci95": [round(lo, 4), round(hi, 4)],
            "recall_seen_ceiling": float(((pf_e >= tau_full) & held).sum() / max(int(held.sum()), 1)),
            "novel_share_of_detected": float((novel & held).sum() / max(k, 1)),
            "benign_fpr": float(flagged[benign_e].mean()),
            "benign_flagged_novel": float(novel[benign_e].mean()),
            "familiar_attack_recall": float(flagged[familiar_e].mean()),
            "familiar_false_novel": float(novel[familiar_e & flagged].mean()) if (familiar_e & flagged).any() else 0.0,
            "novel_bucket_precision_natural": float(w[novel & held].sum() / nov_w) if nov_w else None,
            "tau_binary": tau["tau_binary"], "tau_family": tau["tau_family"],
        }
    return row


def aggregate(runs: list[dict]) -> dict:
    """Mean / min / max over seeds for every numeric budget metric; counts are identical across seeds."""
    out = {"label": runs[0]["label"], "n_held_out": runs[0]["n_held_out"], "seeds": len(runs), "budgets": {}}
    for b in runs[0]["budgets"]:
        rows = [r["budgets"][b] for r in runs]
        agg = {}
        for k in rows[0]:
            vals = [r[k] for r in rows]
            if isinstance(vals[0], (int, float)) and not isinstance(vals[0], bool):
                agg[k] = float(np.mean(vals))
            elif k == "novel_bucket_precision_natural":
                v = [x for x in vals if x is not None]
                agg[k] = float(np.mean(v)) if v else None
        rec = [r["recall"] for r in rows]
        agg["recall_min"], agg["recall_max"] = float(min(rec)), float(max(rec))
        agg["recall_by_seed"] = [round(r["recall"], 4) for r in rows]
        out["budgets"][b] = agg
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", choices=["val", "test"], default="val")
    ap.add_argument("--seeds", type=int, default=1)
    ap.add_argument("--only", nargs="*", help="restrict to these units (family or tool names)")
    a = ap.parse_args()
    train, val = load_split("cic", "train"), load_split("cic", "val")
    ev = val if a.split == "val" else load_split("cic", a.split)
    tr = fit_transformer("cic", train)
    Xv, Xe = tr.transform(val), tr.transform(ev)
    w = cic_weights(ev, a.split)
    results = {"split": a.split, "budgets": BUDGETS, "false_novel": FALSE_NOVEL, "train_rows": RF_TRAIN,
               "seeds": a.seeds, "families": {}, "tools": {}}
    per_unit: dict[tuple[str, str], list[dict]] = {}
    for s in range(a.seeds):
        sub = train.sample(RF_TRAIN, random_state=SEED + s).reset_index(drop=True)
        with timed(f"seed {s}: reference model trained WITH every family"):
            full = P.fit_models(sub, tr, seed=SEED + s)
        for kind, units, col in (("families", LOAO_FAMILIES, "family"), ("tools", list(TOOLS), "tool")):
            for u in units:
                if a.only and u not in a.only:
                    continue
                with timed(f"seed {s}: hold out {col} {u}"):
                    row = run_unit(u, col, u, sub, Xv, Xe, val, ev, tr, w, full, seed=SEED + s)
                per_unit.setdefault((kind, u), []).append(row)
                r = row["budgets"]
                print(f"  s{s} {col[:4]} {u:15s} n={row['n_held_out']:>8,} recall@FPR "
                      + " ".join(f"{float(b) * 100:g}%={r[b]['recall']:.3f}" for b in r), flush=True)
    for (kind, u), runs in per_unit.items():
        results[kind][u] = aggregate(runs)
    dump_json(out_dir(f"holdouts_{a.split}") / "results.json", results)
    print("\n== mean [min-max] over seeds, recall at FPR budgets", BUDGETS)
    for kind in ("families", "tools"):
        for u, r in results[kind].items():
            print(f"  {u:15s} " + " | ".join(f"{b}: {v['recall']:.3f} [{v['recall_min']:.2f}-{v['recall_max']:.2f}]"
                                            for b, v in r["budgets"].items()))


if __name__ == "__main__":
    main()
