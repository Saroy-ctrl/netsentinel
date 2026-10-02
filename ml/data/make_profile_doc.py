"""M1-04: generate docs/data_profile.md from the pipeline's own reports (nothing typed by hand).

    python -m ml.data.make_profile_doc

Reads data/processed/{cic2018,luflow}/clean_report.json, data/splits/*_manifest.json and the two feature specs.
Prose that interprets the numbers lives in INSIGHTS below; every figure in a table comes from a file.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROC = ROOT / "data" / "processed"
SPLITS = ROOT / "data" / "splits"
CONTRACTS = ROOT / "nscore" / "contracts"


def load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def md_table(header: list[str], rows: list[list], align: str | None = None) -> str:
    align = align or ("|" + "---|" * len(header))
    lines = ["| " + " | ".join(header) + " |", align]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def n(x: int) -> str:
    return f"{x:,}"


def agg(days: dict, key: str) -> Counter:
    c: Counter = Counter()
    for d in days.values():
        c.update(d[key])
    return c


def cic_section() -> str:
    rep = load(PROC / "cic2018" / "clean_report.json")
    man = load(SPLITS / "split_manifest.json")
    spec = load(CONTRACTS / "feature_spec.json")
    t, days = rep["totals"], rep["days"]
    fam, dups = agg(days, "family_counts"), agg(days, "duplicates_by_family")
    clean_attacks = sum(v for k, v in fam.items() if k != "BENIGN")

    out = ["## 1. CSE-CIC-IDS2018 (corrected): train / validate / test", ""]
    out.append(md_table(["", "flows"], [
        ["raw (10 day files)", n(t["rows_in"])],
        ["exact duplicates removed", f"{n(t['duplicates_removed'])} ({100 * t['duplicates_removed'] / t['rows_in']:.1f}%)"],
        ["**clean flows**", f"**{n(t['rows_kept'])}**"],
        ["of which attacks", f"{n(clean_attacks)} ({100 * clean_attacks / t['rows_kept']:.2f}%)"],
        ["`Attempted Category != -1` relabelled benign", n(t["attempted_to_benign"])],
        ["rows with Infinity values (set to NaN)", n(t["rows_with_nonfinite"])],
    ], "|---|---:|"))
    out += ["", "### Families after cleaning", ""]
    rows = []
    for f, c in fam.most_common():
        rows.append([f, n(c), f"{100 * c / t['rows_kept']:.3f}%", n(dups.get(f, 0)),
                     f"{100 * dups.get(f, 0) / (c + dups.get(f, 0)):.1f}%" if c + dups.get(f, 0) else ""])
    out.append(md_table(["family", "flows", "share", "duplicates removed", "dup rate"], rows, "|---|---:|---:|---:|---:|"))

    out += ["", "### Per day file (timestamps in UTC)", ""]
    out.append(md_table(["file", "raw", "clean", "dup rate", "first flow", "last flow"], [
        [d, n(v["rows_in"]), n(v["rows_kept"]), f"{100 * v['duplicates_removed'] / v['rows_in']:.0f}%",
         v["ts_min"][:19], v["ts_max"][:19]] for d, v in days.items()], "|---|---:|---:|---:|---|---|"))

    out += ["", "### Split (time-ordered per day, family and tool; 70/15/15; boundary purge)", ""]
    rows = []
    for k, v in man["counts"].items():
        fam_, tool = k.split(" / ")
        if fam_ == "BENIGN" and tool != "BENIGN":
            continue  # tiny 'Attempted' groups
        rows.append([fam_, tool, n(v["train"]), n(v["val"]), n(v["test"]), n(v["purged"])])
    out.append(md_table(["family", "tool", "train", "val", "test", "purged"], rows, "|---|---|---:|---:|---:|---:|"))
    p = man["params"]
    out += ["", f"Working samples (fixed seed {p['seed']}): train = up to {n(p['cap_per_tool'])} flows per attack tool + "
            f"{n(p['benign_train'])} benign; val/test = every attack flow + {n(p['benign_eval'])} benign. "
            f"Totals: {', '.join(f'{k} {n(v)}' for k, v in man['sample_totals'].items())}.", ""]

    kept = spec["features"]
    out += [f"### Features: {len(kept)} kept of 82 candidates", "",
            f"Spearman |ρ| > {spec['sample']['corr_threshold']} pruning on a {n(spec['sample']['rows'])}-row train "
            f"sample (all benign + up to 40k per attack tool). Clip ranges are per class group "
            f"(`clip_per_group = {spec['sample']['clip_per_group']}`); {sum(f['log1p'] for f in kept)} features use log1p.",
            "", "**Kept:** " + ", ".join(f"`{f['name']}`" for f in kept), "", "**Dropped:**", ""]
    out.append(md_table(["feature", "reason", "kept partner", "ρ"], [
        [f"`{d['name']}`", "constant" if "constant" in d["reason"] else "correlated",
         f"`{d.get('kept_partner', '')}`" if d.get("kept_partner") else "", d.get("rho", "")] for d in spec["dropped"]]))
    out += ["", "**Not features (metadata):** " + "; ".join(f"`{m['name']}` ({m['reason']})" for m in spec["metadata"]),
            "", "**Optional (off by default):** " + "; ".join(f"`{o['name']}`: {o['reason']}" for o in spec["optional"]), ""]
    cols = {}
    for d in days.values():
        for c, v in d["columns"].items():
            a = cols.setdefault(c, {"inf": 0, "nan": 0, "neg": 0})
            for k in a:
                a[k] += v[k]
    out += ["### Non-finite and negative values (counts over all clean-pass input rows)", ""]
    out.append(md_table(["column", "Infinity", "NaN", "negative"], [
        [f"`{c}`", n(v["inf"]), n(v["nan"]), n(v["neg"])] for c, v in sorted(cols.items())], "|---|---:|---:|---:|"))
    return "\n".join(out)


def luflow_section() -> str:
    rep = load(PROC / "luflow" / "clean_report.json")
    man = load(SPLITS / "luflow_split_manifest.json")
    spec = load(CONTRACTS / "feature_spec.luflow.json")
    t = rep["totals"]
    out = ["## 2. LUFlow (real honeypot traffic): drift showcase", ""]
    out.append(md_table(["", "flows"], [
        ["raw (72 sampled days, 9 months)", n(t["rows_in"])],
        ["exact duplicates removed", f"{n(t['duplicates_removed'])} ({100 * t['duplicates_removed'] / t['rows_in']:.1f}%)"],
        ["`time_start` repaired (lost leading zeros)", f"{n(t['timestamps_repaired'])} ({100 * t['timestamps_repaired'] / t['rows_in']:.1f}%)"],
        ["dropped: timestamp > 2 days from the file date", n(t["timestamps_dropped"])],
        ["**clean flows**", f"**{n(t['rows_kept'])}**"],
        ["rows with Infinity / NaN", n(t["rows_with_nonfinite"])],
    ], "|---|---:|"))
    by: dict[str, Counter] = {}
    for k, v in man["counts"].items():
        period, fam_ = k.split(" / ")
        c = by.setdefault(period, Counter())
        c[fam_] += sum(v.values())
    out += ["", "### Flows per month and label (after cleaning)", ""]
    out.append(md_table(["month", "BENIGN", "Malicious", "Outlier", "total", "malicious share"], [
        [p, n(c["BENIGN"]), n(c["Malicious"]), n(c["Outlier"]), n(sum(c.values())),
         f"{100 * c['Malicious'] / sum(c.values()):.0f}%"] for p, c in sorted(by.items())], "|---|---:|---:|---:|---:|---:|"))
    out += ["", "### Split", "",
            f"Early months ({', '.join(man['params']['early_periods'])}) are time-ordered 70/15/15 per month and label "
            "(train / val / same-period test). Every later month is a drift test set: "
            f"`test` = everything after the first {int(man['params']['recal_frac'] * 100)}% of the month, "
            "`recal` = benign flows from that first 20% (label-free \"known-good\" traffic for refitting the "
            "IsolationForest + thresholds). 60 s purge at each boundary. `Outlier` is never in the supervised train sample.", ""]
    rows = [[s, n(v)] for s, v in man["totals"].items()]
    out.append(md_table(["split", "flows"], rows, "|---|---:|"))
    kept = spec["features"]
    out += ["", f"### Features: {len(kept)} kept of 9", "", "**Kept:** " + ", ".join(f"`{f['name']}`" for f in kept)]
    if spec["dropped"]:
        out += ["", "**Dropped:** " + "; ".join(f"`{d['name']}` ({d['reason']})" for d in spec["dropped"])]
    out += ["", "**Optional (off by default):** " + "; ".join(f"`{o['name']}`" for o in spec["optional"]), ""]
    return "\n".join(out)


INSIGHTS = """## 3. What the data told us (decisions and traps)

**2018**
1. **Attacks are under 8% of clean flows** (5.6% before deduplication, because the duplicates are benign). Accuracy is
   meaningless; report per-class precision, recall, FPR and PR-AUC.
2. **Deduplication matters, and unevenly.** 28% of flows are exact duplicates, almost all benign. The one attack
   family that shrinks is Infiltration: the Nmap port scan produces many identical flows, so the family loses
   over 40% of its raw count. We deduplicate before splitting so identical flows can't sit in both train and test.
3. **FTP-Patator has no attack flows left.** Every FTP-Patator flow is `Attempted` (the FTP port was closed), so
   `BruteForce` is SSH-Patator only. **DoS SlowHTTPTest is absent** from the corrected release.
4. **Infiltration is almost entirely an internal Nmap port scan** (99.7% of its raw flows). Treat it as
   "post-compromise internal scanning", not data theft.
5. **WebAttack is tiny** (a few hundred flows in total): it stays a named family with a low-support caveat,
   is excluded from the leave-one-family-out test, and its metrics need wide confidence intervals.
6. **Timestamps are UTC and 4 hours ahead of the times printed on the CIC dataset page.** Some day files hold flows
   from other dates (the `Friday-23` file starts on 21 Feb), and rows inside a file are not in time order. The split
   uses the timestamp, never the file name or the calendar date.
7. **ICMP Code / Type use -1 for "not ICMP"** (negative on almost every row) and a few thousand flows have negative
   header lengths. These are dataset conventions and bugs, not errors in our pipeline; the spec clips them.
8. **Clip ranges are computed per class group.** Pooled quantiles from a benign-dominated sample flattened up to 74%
   of one attack's values on a feature; per-group ranges keep each attack's own tail.

**LUFlow**
1. **About 10% of rows in every daily file have a broken `time_start`**: the source concatenated seconds and
   microseconds as text without zero-padding, so values came out 10x, 100x or 1000x too small (dates in 1970
   and 1975). It is exactly recoverable (first 10 digits = seconds, the rest = microseconds) and is repaired in the
   adapter; rows still more than 2 days from the file date are dropped.
2. **29% of flows are exact duplicates** (repeated scans) and are removed before splitting.
3. **`outlier` means "abnormal but not explained by threat intelligence"**, not "attack". It is never a training
   label; it is the showcase for the novelty detector.
4. **The malicious share swings a lot from month to month** (see the table above), which is the drift the
   monitor is meant to catch. It also means month-to-month recall comparisons must be read together with the
   changing class mix.
5. Only 8 sampled days per month; the CSV calls the inter-packet time `avg_ipt` (the repo README says `mean_ipt`).

## 4. Reproduce

```bash
python ml/data/download.py cic2018 && python ml/data/download.py luflow
python -m ml.data.adapters.cic2018 && python -m ml.data.split && python -m ml.data.make_feature_spec
python -m ml.data.adapters.luflow  && python -m ml.data.split_luflow && python -m ml.data.make_feature_spec_luflow
python -m ml.data.baseline_stats cic && python -m ml.data.baseline_stats luflow
python -m ml.data.make_replay && python -m ml.data.make_profile_doc
```
"""


def main() -> None:
    doc = ["# Data profile", "",
           "*Generated by `ml/data/make_profile_doc.py` from the pipeline reports; do not edit by hand. "
           "Dataset sources, checksums and download steps: [`data/README.md`](../data/README.md).*", "",
           cic_section(), "", luflow_section(), "", INSIGHTS]
    path = ROOT / "docs" / "data_profile.md"
    path.write_text("\n".join(doc) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path} ({path.stat().st_size / 1e3:.0f} KB)")


if __name__ == "__main__":
    main()
