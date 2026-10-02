"""Materialise the sampled train / val / test rows (split.py `in_sample` flags) into one parquet per split.

    python -m ml.data.working_set cic          # data/working/cic2018/{train,val,test}.parquet   (3.5M / 1.9M / 2.0M)
    python -m ml.data.working_set luflow       # data/working/luflow/{train,val,test,recal}.parquet

Columns: the spec's features (+ `dst_port` for the B12 experiment) and metadata (day, row, ts, family, tool [, period]).
Values are RAW (the FlowTransformer clips/imputes). Experiments then do `load("cic", "train")` and never touch the
45M-row processed parquet again.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed"
SPLITS = ROOT / "data" / "splits"
WORKING = ROOT / "data" / "working"

CFG = {
    "cic": {"dir": "cic2018", "split": "cic2018_split.parquet", "spec": "feature_spec.json",
            "names": {0: "train", 1: "val", 2: "test"}, "meta": ["day", "row", "ts", "family", "tool"]},
    "luflow": {"dir": "luflow", "split": "luflow_split.parquet", "spec": "feature_spec.luflow.json",
               "names": {0: "train", 1: "val", 2: "test", 3: "recal"},
               "meta": ["period", "day", "row", "ts", "family", "tool"]},
}


def _columns(schema: str) -> list[str]:
    spec = json.loads((ROOT / "nscore" / "contracts" / CFG[schema]["spec"]).read_text(encoding="utf-8"))
    feats = [f["name"] for f in spec["features"]]
    cols = [c for c in dict.fromkeys([*CFG[schema]["meta"], *feats, "protocol", "dst_port"])]  # noqa: C416
    return cols


def build(schema: str, out_root: Path = WORKING) -> dict[str, int]:
    cfg = CFG[schema]
    cols = _columns(schema)
    out = out_root / cfg["dir"]
    out.mkdir(parents=True, exist_ok=True)
    writers: dict[str, pq.ParquetWriter] = {}
    counts = {n: 0 for n in cfg["names"].values()}
    split_path = SPLITS / cfg["split"]
    for f in sorted((PROCESSED / cfg["dir"]).glob("*.parquet")):
        day = f.stem
        s = pq.read_table(split_path, filters=[("day", "=", day)], columns=["row", "split", "in_sample"]).to_pandas()
        if s.empty:
            continue
        # per-row lookup: split id (or -9 = not selected), indexed by the original row number
        lut = np.full(int(s["row"].max()) + 1, -9, dtype=np.int8)
        lut[s["row"].to_numpy()] = np.where(s["in_sample"].to_numpy(), s["split"].to_numpy(), -9)
        have = [c for c in cols if c != "day"]
        for batch in pq.ParquetFile(f).iter_batches(batch_size=500_000, columns=[c for c in have if c in
                                                                                  pq.ParquetFile(f).schema.names]):
            df = batch.to_pandas()
            df["day"] = day
            sid = lut[df["row"].to_numpy()]
            for k, name in cfg["names"].items():
                part = df[sid == k]
                if part.empty:
                    continue
                part = part[cols].copy()
                for c in ("family", "tool", "period", "day"):
                    if c in part:
                        part[c] = part[c].astype(str)
                tbl = pa.Table.from_pandas(part, preserve_index=False)
                if name not in writers:
                    writers[name] = pq.ParquetWriter(out / f"{name}.parquet", tbl.schema, compression="zstd")
                writers[name].write_table(tbl.cast(writers[name].schema))
                counts[name] += len(part)
        print(f"  {day}: {counts}", flush=True)
    for w in writers.values():
        w.close()
    (out / "counts.json").write_text(json.dumps(counts, indent=1) + "\n", encoding="utf-8")
    return counts


def load(schema: str, split: str, columns: list[str] | None = None, root: Path = WORKING) -> pd.DataFrame:
    return pd.read_parquet(root / CFG[schema]["dir"] / f"{split}.parquet", columns=columns)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("schema", choices=sorted(CFG))
    print(build(ap.parse_args().schema))
