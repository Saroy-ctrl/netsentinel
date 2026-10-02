"""Drift math. Owner: M1 (task M1-07). Consumer: api drift monitor (M3-08).

Contract:
  build_reference(X_train: DataFrame, features: list[str], bins=10) -> dict
      quantile bin edges + expected proportions per feature -> saved as drift_reference.json in the bundle
  psi(reference_feature: dict, values: np.ndarray) -> float
      Population Stability Index, epsilon-smoothed. <0.10 ok, <0.25 watch, else alert.
"""

from __future__ import annotations


def build_reference(X_train, features: list[str], bins: int = 10) -> dict:
    raise NotImplementedError("M1-07")


def psi(reference_feature: dict, values) -> float:
    raise NotImplementedError("M1-07")
