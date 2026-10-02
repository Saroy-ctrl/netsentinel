"""Shared feature transform. Owner: M1 (tasks M1-02, M1-06).

The SAME object is fitted in ml/ and loaded in api/ - never re-implement it.

Contract:
  FeatureSpec.load(path) reads nscore/contracts/feature_spec.json:
    {"version": "1", "features": [{"name": "flow_duration", "raw_name": " Flow Duration",
      "dtype": "float", "clip": [0, 1.2e8], "log1p": true}, ...],
     "dropped": {"flow_id": "identifier", "src_ip": "leakage", ...}}
  FlowTransformer.fit(df_train) -> self        # fit on TRAIN split only
  FlowTransformer.transform(df) -> np.ndarray   # column order == spec order, always
  FlowTransformer.transform_records(list[dict]) # serving path, same code underneath
"""

from __future__ import annotations


class FeatureSpec:  # M1-02
    @classmethod
    def load(cls, path: str) -> FeatureSpec:
        raise NotImplementedError("M1-02")


class FlowTransformer:  # M1-06
    def __init__(self, spec: FeatureSpec):
        self.spec = spec

    def fit(self, df):
        raise NotImplementedError("M1-06")

    def transform(self, df):
        raise NotImplementedError("M1-06")

    def transform_records(self, records: list[dict]):
        raise NotImplementedError("M1-06")
