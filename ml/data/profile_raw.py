"""M1-01: count flows per day and label straight out of the raw zips (no unzipping).

    python ml/data/profile_raw.py cic2018
    python ml/data/profile_raw.py luflow

Streams only the label (and time) columns with pyarrow, so 36 GB of CSV needs ~1 GB of RAM.
Writes data/raw/<dataset>/profile.json and prints a markdown table for data/README.md.
"""

from __future__ import annotations

import argparse
import json
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

SPECS = {
    "cic2018": {"glob": "cic2018/*.zip", "label": "Label", "time": "Timestamp", "extra": ["Attempted Category"]},
    "luflow": {"glob": "luflow/*/*/*.zip", "label": "label", "time": "time_start", "extra": []},
}


def stream_columns(zf: zipfile.ZipFile, member: str, cols: list[str]):
    with zf.open(member) as fh:
        reader = pacsv.open_csv(
            fh,
            read_options=pacsv.ReadOptions(block_size=64 << 20),
            convert_options=pacsv.ConvertOptions(include_columns=cols, strings_can_be_null=False,
                                                 column_types={c: pa.string() for c in cols}),
        )
        yield from reader


def profile(dataset: str) -> dict:
    spec = SPECS[dataset]
    cols = [spec["label"], spec["time"], *spec["extra"]]
    per_group: dict[str, Counter] = defaultdict(Counter)
    span: dict[str, list[str]] = {}
    t0 = time.time()
    for zpath in sorted(RAW.glob(spec["glob"])):
        with zipfile.ZipFile(zpath) as zf:
            for member in zf.namelist():
                if not member.endswith(".csv"):
                    continue
                group = member.removesuffix(".csv") if dataset == "cic2018" else "/".join(zpath.parts[-3:-1])
                t = time.time()
                n = 0
                for batch in stream_columns(zf, member, cols):
                    labels = batch.column(spec["label"])
                    if dataset == "cic2018":
                        # "X - Attempted" rows are tagged by Attempted Category != -1; count them separately
                        attempted = pc.not_equal(batch.column("Attempted Category"), "-1")
                        labels = pc.if_else(attempted, pc.binary_join_element_wise(labels, " [attempted]", ""), labels)
                    for v in pc.value_counts(labels).to_pylist():
                        per_group[group][v["values"]] += v["counts"]
                    times = batch.column(spec["time"])
                    lo, hi = pc.min(times).as_py(), pc.max(times).as_py()
                    cur = span.get(group, [lo, hi])
                    span[group] = [min(cur[0], lo), max(cur[1], hi)]
                    n += batch.num_rows
                print(f"  {group}: {n:,} rows in {time.time() - t:.0f}s")
    out = {
        "dataset": dataset,
        "seconds": round(time.time() - t0),
        "groups": {g: dict(sorted(c.items())) for g, c in sorted(per_group.items())},
        "time_span": span,
        "total_rows": sum(sum(c.values()) for c in per_group.values()),
    }
    (RAW / dataset / "profile.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def markdown(out: dict) -> str:
    labels = sorted({lab for c in out["groups"].values() for lab in c})
    lines = ["| Group | " + " | ".join(labels) + " | total |", "|---|" + "---:|" * (len(labels) + 1)]
    for g, c in out["groups"].items():
        lines.append(f"| {g} | " + " | ".join(f"{c.get(lab, 0):,}" for lab in labels) + f" | {sum(c.values()):,} |")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=sorted(SPECS))
    result = profile(ap.parse_args().dataset)
    print(f"\n{result['total_rows']:,} rows in {result['seconds']}s\n")
    print(markdown(result))
