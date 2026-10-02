"""Every committed replay file must be loadable exactly the way M5's replay engine and M3's API will use it."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from nscore.contracts.schemas import FlowBatch, FlowMeta, FlowRecord
from nscore.features.transform import FeatureSpec, FlowTransformer

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "replay" / "samples"
SPECS = {"cic": ROOT / "nscore/contracts/feature_spec.json",
         "luflow": ROOT / "nscore/contracts/feature_spec.luflow.json"}
META = {"flow_id", "observed_at", "t_rel_s", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "ground_truth", "tool"}

pytestmark = pytest.mark.skipif(not (SAMPLES / "manifest.json").exists(), reason="replay samples not generated")


def _files():
    return sorted(json.loads((SAMPLES / "manifest.json").read_text())["files"].items())


@pytest.mark.parametrize("name,info", _files())
def test_replay_file_is_contract_and_spec_compatible(name, info):
    spec = FeatureSpec.load(SPECS[info["schema"]])
    df = pd.read_csv(SAMPLES / f"{name}.csv.gz", dtype={"src_ip": str, "dst_ip": str})
    feat_cols = [c for c in df.columns if c not in META]

    assert len(df) == info["rows"] and 0 < len(df) <= 10_000
    assert set(feat_cols) == set(spec.names) - {"protocol"}  # protocol is the single shared meta/feature column
    assert not df.isna().any().any()
    assert df["observed_at"].is_monotonic_increasing and df["t_rel_s"].iloc[0] == 0
    assert ((df["src_port"] >= 0) & (df["dst_port"] >= 0)).all()

    recs = [
        FlowRecord(
            meta=FlowMeta(flow_id=r["flow_id"], observed_at=r["observed_at"], src_ip=r["src_ip"], dst_ip=r["dst_ip"],
                          src_port=int(r["src_port"]), dst_port=int(r["dst_port"]), protocol=int(r["protocol"])),
            features={c: float(r[c]) for c in feat_cols} | {"protocol": float(r["protocol"])},
            ground_truth=r["ground_truth"],
        )
        for r in df.head(500).to_dict("records")
    ]
    FlowBatch(flows=recs)
    feats = [x.features for x in recs]
    X = FlowTransformer(spec).fit(pd.DataFrame(feats)).transform_records(feats)
    assert X.shape == (len(recs), len(spec.names)) and np.isfinite(X).all()


def test_manifest_ground_truth_counts_match_files():
    for name, info in _files():
        df = pd.read_csv(SAMPLES / f"{name}.csv.gz", usecols=["ground_truth"])
        assert df["ground_truth"].value_counts().to_dict() == info["ground_truth"]
