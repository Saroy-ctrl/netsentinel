"""Shared feature transform (M1-06). The SAME code path is used by training (ml/) and serving (api/).

    spec = FeatureSpec.load("nscore/contracts/feature_spec.json")
    tr = FlowTransformer(spec).fit(train_df)      # train split only
    X = tr.transform(df)                          # (n, F) float32: +/-inf->NaN, clip, NaN->train median, log1p
    X = tr.transform_records([{...}, ...])        # serving path: list of {feature_name: value}; same code underneath
    tr.raw(df)                                    # untouched values in spec order (for SHAP "value" and briefs)

Nothing is hardcoded about the dataset: the CIC (2018) and LUFlow bundles differ only in their spec file.
Column order is always the spec's order. Missing features raise MissingFeaturesError with the names (the API turns
that into a 422); extra keys are ignored.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

OPTIONAL_DEFS = {"dst_port": {"clip": (0.0, 65535.0), "log1p": False}}


class MissingFeaturesError(ValueError):
    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__(f"missing features: {', '.join(missing)}")


@dataclass(frozen=True)
class FeatureDef:
    name: str
    raw_name: str
    clip: tuple[float, float]
    log1p: bool


class FeatureSpec:
    def __init__(self, data: dict, sha256: str):
        self.data, self.sha256 = data, sha256
        self.schema: str = data["schema"]
        self.features = [FeatureDef(f["name"], f["raw_name"], tuple(f["clip"]), bool(f["log1p"]))
                         for f in data["features"]]
        self.optional = [o["name"] for o in data.get("optional", [])]

    @classmethod
    def load(cls, path: str | Path) -> FeatureSpec:
        raw = Path(path).read_bytes()
        return cls(json.loads(raw), hashlib.sha256(raw).hexdigest())

    @classmethod
    def from_dict(cls, data: dict) -> FeatureSpec:
        return cls(data, hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest())

    @property
    def names(self) -> list[str]:
        return [f.name for f in self.features]


class FlowTransformer:
    def __init__(self, spec: FeatureSpec, include_optional: tuple[str, ...] = ()):
        unknown = set(include_optional) - set(spec.optional)
        if unknown:
            raise ValueError(f"not optional features in this spec: {sorted(unknown)}")
        self.spec = spec
        self.include_optional = tuple(include_optional)
        self.defs = list(spec.features) + [
            FeatureDef(n, n, OPTIONAL_DEFS[n]["clip"], OPTIONAL_DEFS[n]["log1p"]) for n in self.include_optional
        ]
        self.medians_: np.ndarray | None = None
        self.mean_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None

    @property
    def feature_names(self) -> list[str]:
        return [d.name for d in self.defs]

    # ----------------------------------------------------------------- internals
    def _matrix(self, df: pd.DataFrame) -> np.ndarray:
        missing = [d.name for d in self.defs if d.name not in df.columns]
        if missing:
            raise MissingFeaturesError(missing)
        X = df[self.feature_names].to_numpy(dtype=np.float64, copy=True)
        X[~np.isfinite(X)] = np.nan
        return X

    def _clip(self, X: np.ndarray) -> np.ndarray:
        for j, d in enumerate(self.defs):
            np.clip(X[:, j], d.clip[0], d.clip[1], out=X[:, j])  # NaN stays NaN
        return X

    def _finish(self, X: np.ndarray) -> np.ndarray:
        for j, d in enumerate(self.defs):
            if d.log1p:
                X[:, j] = np.log1p(X[:, j])
        return X

    def _impute(self, X: np.ndarray, med: np.ndarray) -> np.ndarray:
        r, c = np.where(np.isnan(X))
        X[r, c] = med[c]
        return X

    # ----------------------------------------------------------------- public API
    def fit(self, df: pd.DataFrame) -> FlowTransformer:
        X = self._clip(self._matrix(df))
        self.medians_ = np.nanmedian(X, axis=0)
        self.medians_ = np.where(np.isnan(self.medians_), 0.0, self.medians_)  # all-NaN column: documented, rare
        Z = self._finish(self._impute(X, self.medians_))
        self.mean_, self.scale_ = Z.mean(0), Z.std(0)
        self.scale_[self.scale_ == 0] = 1.0
        return self

    def transform(self, df: pd.DataFrame, scaled: bool = False) -> np.ndarray:
        if self.medians_ is None:
            raise RuntimeError("FlowTransformer is not fitted")
        Z = self._finish(self._impute(self._clip(self._matrix(df)), self.medians_))
        if scaled:
            Z = (Z - self.mean_) / self.scale_
        return Z.astype(np.float32)

    def transform_records(self, records: list[dict], scaled: bool = False) -> np.ndarray:
        """Serving path. Same code as transform(): build a frame, then call it."""
        return self.transform(pd.DataFrame.from_records(records), scaled=scaled)

    def raw(self, df: pd.DataFrame) -> np.ndarray:
        missing = [d.name for d in self.defs if d.name not in df.columns]
        if missing:
            raise MissingFeaturesError(missing)
        return df[self.feature_names].to_numpy(dtype=np.float64)
