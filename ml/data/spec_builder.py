"""Dataset-agnostic feature-spec builder (M1-02 for CSE-CIC-IDS2018, reused by M1-09 for LUFlow).

Input: a TRAIN-ONLY sample frame. Output: a dict that is written to nscore/contracts/feature_spec*.json and read
back by nscore.features.FlowTransformer. All numbers (clip ranges, correlations, NaN rates) come from the sample,
never from val/test.

Steps: 1) drop constant features  2) greedy correlation pruning (|Spearman rho| > threshold, keep the more basic
feature)  3) per kept feature: clip range [q_lo, q_hi] and a log1p flag for non-negative heavy-tailed features.
Nothing is imputed here; the spec only records the policy (NaN -> train median, fitted by FlowTransformer).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

CORR_THRESHOLD = 0.95
CLIP_Q = (0.0001, 0.9999)
LOG1P_SKEW = 5.0


def column_stats(df: pd.DataFrame) -> pd.DataFrame:
    q = df.quantile([CLIP_Q[0], 0.5, CLIP_Q[1]])
    s = pd.DataFrame({
        "nan_rate": df.isna().mean(),
        "n_unique": df.nunique(dropna=True),
        "min": df.min(), "max": df.max(), "median": q.loc[0.5],
        "q_lo": q.loc[CLIP_Q[0]], "q_hi": q.loc[CLIP_Q[1]],
        "skew": df.skew(),
    })
    top = {c: df[c].value_counts(normalize=True, dropna=True).iloc[0] if df[c].notna().any() else 1.0 for c in df}
    s["top_value_share"] = pd.Series(top)
    return s


def prune_correlated(df: pd.DataFrame, order: list[str], threshold: float = CORR_THRESHOLD):
    """Greedy: walk features in preference order, keep one if it is not > threshold correlated with a kept one.
    Returns (kept, dropped) where dropped = {feature: (kept_partner, rho)}."""
    corr = df[order].corr(method="spearman").abs()
    kept: list[str] = []
    dropped: dict[str, tuple[str, float]] = {}
    for f in order:
        partner = next(((k, float(corr.at[f, k])) for k in kept if corr.at[f, k] > threshold), None)
        if partner:
            dropped[f] = partner
        else:
            kept.append(f)
    return kept, dropped


def build_spec(sample: pd.DataFrame, *, raw_names: dict[str, str], preference_key, dataset: str, schema: str,
               metadata: dict[str, str], optional: dict[str, str] | None = None,
               threshold: float = CORR_THRESHOLD) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    """sample: columns = candidate feature names (train only). Returns (spec, stats_df, corr_pairs_df)."""
    stats = column_stats(sample)
    dropped: list[dict] = []

    constant = [c for c in sample if stats.at[c, "n_unique"] <= 1]
    for c in constant:
        dropped.append({"name": c, "raw_name": raw_names[c], "reason": "constant in the training sample"})
    candidates = sorted((c for c in sample if c not in constant), key=preference_key)

    kept, corr_dropped = prune_correlated(sample, candidates, threshold)
    for c, (k, rho) in corr_dropped.items():
        dropped.append({"name": c, "raw_name": raw_names[c], "reason": f"|rho|>{threshold} with {k}",
                        "kept_partner": k, "rho": round(rho, 4)})

    features = []
    for c in sorted(kept, key=preference_key):
        s = stats.loc[c]
        lo, hi = float(s["q_lo"]), float(s["q_hi"])
        log1p = bool(lo >= 0 and s["skew"] > LOG1P_SKEW)
        features.append({"name": c, "raw_name": raw_names[c], "dtype": "float32", "clip": [lo, hi], "log1p": log1p,
                         "nan_rate": round(float(s["nan_rate"]), 6), "train_median": float(s["median"])})
    spec = {
        "version": "1", "schema": schema, "dataset": dataset,
        "sample": {"rows": int(len(sample)), "clip_quantiles": list(CLIP_Q), "corr_method": "spearman",
                   "corr_threshold": threshold, "log1p_if_skew_above": LOG1P_SKEW},
        "nan_policy": "median_train",
        "features": features,
        "optional": [{"name": n, "reason": r, "default": False} for n, r in (optional or {}).items()],
        "metadata": [{"name": n, "reason": r} for n, r in metadata.items()],
        "dropped": sorted(dropped, key=lambda d: d["name"]),
    }
    corr = sample[candidates].corr(method="spearman").abs()
    iu = np.triu_indices(len(candidates), 1)
    names = np.array(candidates)
    pairs = pd.DataFrame({"a": names[iu[0]], "b": names[iu[1]], "abs_rho": corr.to_numpy()[iu]})
    pairs = pairs[pairs.abs_rho > 0.8].sort_values("abs_rho", ascending=False).reset_index(drop=True)
    return spec, stats, pairs
