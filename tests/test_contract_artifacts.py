"""The committed derived artifacts must agree with each other (spec <-> baselines), so consumers can trust them."""

import json
from pathlib import Path

import pytest

C = Path(__file__).resolve().parents[1] / "nscore" / "contracts"
PAIRS = [("feature_spec.json", "baselines/cic.json", "cic"),
         ("feature_spec.luflow.json", "baselines/luflow.json", "luflow")]


@pytest.mark.parametrize("spec_file,base_file,schema", PAIRS)
def test_spec_and_baseline_agree(spec_file, base_file, schema):
    spec = json.loads((C / spec_file).read_text(encoding="utf-8"))
    base = json.loads((C / base_file).read_text(encoding="utf-8"))
    names = [f["name"] for f in spec["features"]]
    assert spec["schema"] == base["schema"] == schema
    assert list(base["features"]) == names                      # same features, same order
    assert base["n_benign"] > 100_000
    for f in spec["features"]:
        lo, hi = f["clip"]
        assert lo <= hi
        s = base["features"][f["name"]]
        assert s["p05"] <= s["median"] <= s["p95"]
        assert f["log1p"] is False or lo >= 0                   # log1p only on non-negative features


@pytest.mark.parametrize("spec_file", ["feature_spec.json", "feature_spec.luflow.json"])
def test_spec_is_train_only_and_documents_every_decision(spec_file):
    spec = json.loads((C / spec_file).read_text(encoding="utf-8"))
    assert spec["nan_policy"] == "median_train" and spec["sample"]["clip_per_group"] is True
    kept, dropped = {f["name"] for f in spec["features"]}, {d["name"] for d in spec["dropped"]}
    assert not kept & dropped and all(d["reason"] for d in spec["dropped"])
    assert [o["name"] for o in spec["optional"]] == ["dst_port"]
    assert {m["name"] for m in spec["metadata"]} >= {"ts", "src_ip", "dst_ip", "src_port", "family", "tool"}
