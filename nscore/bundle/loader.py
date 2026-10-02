"""Model bundle loading. Owner: M2 (tasks M2-10, M2-12). Consumer: api startup (M3-03).

Contract:
  load_bundle(ref: str, cache_dir="artifacts/cache") -> Bundle
     ref = "azureml:netsentinel-bundle:3" | "azureml:netsentinel-luflow@latest" | "local:path/to/bundle"
     - azureml refs download into cache_dir; if Azure is unreachable and a cached copy
       with matching sha256s exists, use it and log a WARNING (demo must never die on Wi-Fi).
     - verifies every file hash in manifest.json; refuses to load on mismatch.
  Bundle exposes: manifest, spec, transformer, rf_binary, rf_multiclass, iforest,
     thresholds, label_map, explainer_for(verdict), drift_reference, baseline_stats,
     evaluation_report.
  SHAP TreeExplainers are rebuilt at load time from the models (cheap) rather than
  unpickled - pickled explainers break across shap versions.
"""

from __future__ import annotations


def load_bundle(ref: str, cache_dir: str = "artifacts/cache"):
    raise NotImplementedError("M2-10 / M2-12")
