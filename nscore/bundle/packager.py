"""Model bundle packager (M2-01 / M2-10): turn trained artifacts into one self-describing, hash-verified folder.

    bundle_vN/
      manifest.json            BundleManifest (contracts): version, dataset, split, spec sha256, every file's sha256
      feature_spec.json        copy of the spec the transformer was fitted with
      transformer.joblib       fitted FlowTransformer
      rf_binary.joblib         RandomForest, p(attack)
      rf_multiclass.joblib     RandomForest over attack families (ABSENT for binary-only bundles, e.g. LUFlow)
      iforest.joblib           OPTIONAL IsolationForest fitted on BENIGN train flows only (absent on CIC bundles: it
                               scored ~0 recall there, see docs/experiments.md)
      iforest_benign_val_scores.npy   OPTIONAL, sorted anomaly scores of benign validation flows (score -> percentile)
      thresholds.json          {"tau_binary", "tau_family", "operating_fpr"} (+ "tau_anomaly" with an IForest)
      label_map.json           {"classes": [family, ...]} in rf_multiclass.classes_ order ([] if no family head)
      drift_reference.json     nscore.drift.psi reference built on the TRANSFORMED train matrix
      baseline_stats.json      benign median / p05 / p95 per feature (RAW values)
      evaluation_report.json   EvaluationReport contract (optional but expected for real bundles)

The manifest is written last. Anything that loads a bundle must verify it (nscore.bundle.loader).
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import sklearn

from nscore.contracts.schemas import CONTRACT_VERSION, BundleManifest

MANIFEST = "manifest.json"
REQUIRED_THRESHOLDS = ("tau_binary", "tau_family", "operating_fpr")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8", newline="\n")


def build_bundle(out_dir: str | Path, *, version: str, spec_path: str | Path, transformer, rf_binary,
                 thresholds: dict, drift_reference: dict, baseline_stats: dict,
                 dataset: str, split_strategy: str, metrics_summary: dict[str, float], rf_multiclass=None,
                 iforest=None, benign_val_scores: np.ndarray | None = None,
                 evaluation_report: dict | None = None, tags: dict[str, str] | None = None,
                 extra_files: dict[str, Path] | None = None, overwrite: bool = False) -> BundleManifest:
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        if not overwrite:
            raise FileExistsError(f"{out} exists and is not empty (pass overwrite=True)")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    missing = [k for k in REQUIRED_THRESHOLDS if k not in thresholds]
    if missing:
        raise ValueError(f"thresholds missing: {missing}")
    if (iforest is None) != (benign_val_scores is None):
        raise ValueError("iforest and benign_val_scores go together (both or neither)")
    if iforest is not None:
        if "tau_anomaly" not in thresholds:
            raise ValueError("a bundled IsolationForest needs thresholds['tau_anomaly']")
        scores = np.sort(np.asarray(benign_val_scores, dtype=np.float64))
        if scores.ndim != 1 or len(scores) < 100:
            raise ValueError("benign_val_scores must be a 1-D array of at least 100 anomaly scores")

    spec_dst = out / "feature_spec.json"
    shutil.copyfile(spec_path, spec_dst)
    spec = json.loads(spec_dst.read_text(encoding="utf-8"))
    if transformer.spec.sha256 != sha256_file(spec_dst):
        raise ValueError("transformer was fitted with a different feature spec than the one being bundled")

    joblib.dump(transformer, out / "transformer.joblib", compress=3)
    joblib.dump(rf_binary, out / "rf_binary.joblib", compress=3)
    if iforest is not None:
        joblib.dump(iforest, out / "iforest.joblib", compress=3)
        np.save(out / "iforest_benign_val_scores.npy", scores)
    classes: list[str] = []
    if rf_multiclass is not None:
        joblib.dump(rf_multiclass, out / "rf_multiclass.joblib", compress=3)
        classes = [str(c) for c in rf_multiclass.classes_]
    _write_json(out / "thresholds.json", {k: float(v) for k, v in thresholds.items()})
    _write_json(out / "label_map.json", {"classes": classes})
    _write_json(out / "drift_reference.json", drift_reference)
    _write_json(out / "baseline_stats.json", baseline_stats)
    if evaluation_report is not None:
        _write_json(out / "evaluation_report.json", evaluation_report)
    for rel, src in (extra_files or {}).items():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    files = {p.relative_to(out).as_posix(): sha256_file(p) for p in sorted(out.rglob("*")) if p.is_file()}
    manifest = BundleManifest(
        bundle_version=version, created_at=datetime.now(UTC), contract_version=CONTRACT_VERSION, dataset=dataset,
        split_strategy=split_strategy, feature_spec_sha256=files["feature_spec.json"], files=files,
        metrics_summary={k: float(v) for k, v in metrics_summary.items()},
        tags={"feature_schema": spec["schema"], "family_head": str(rf_multiclass is not None).lower(),
              "sklearn_version": sklearn.__version__, "numpy_version": np.__version__,
              "python_version": platform.python_version(), **(tags or {})},
    )
    (out / MANIFEST).write_text(manifest.model_dump_json(indent=1) + "\n", encoding="utf-8")
    return manifest
