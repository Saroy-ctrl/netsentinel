"""Model bundle loading (M2-01 / M2-10 local, M2-12 Azure ML).

    bundle = load_bundle("local:artifacts/bundles/cic-v1")     # also accepts a bare path
    bundle = load_bundle("azureml:netsentinel-bundle@latest")  # M2-12: downloads to the cache, same verification

Verification (refuses to load on any failure, BundleIntegrityError):
  * every file listed in manifest.json exists and matches its sha256; no unlisted extra files
  * feature_spec.json matches manifest.feature_spec_sha256 and the transformer's spec
  * contract MAJOR version matches this code
Soft check: warns when the bundle was pickled with a different scikit-learn version (loading may still work).
"""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import sklearn

from nscore.bundle.packager import MANIFEST, sha256_file
from nscore.contracts.schemas import CONTRACT_VERSION, BundleManifest, ModelInfo
from nscore.features.transform import FeatureSpec


class BundleIntegrityError(RuntimeError):
    pass


@dataclass
class Bundle:
    path: Path
    ref: str
    manifest: BundleManifest
    spec: FeatureSpec
    transformer: object
    rf_binary: object
    rf_multiclass: object | None
    iforest: object | None
    benign_val_scores: np.ndarray | None
    thresholds: dict[str, float]
    label_map: dict
    drift_reference: dict
    baseline_stats: dict
    evaluation_report: dict | None
    registry: str = "local"
    extras: dict = field(default_factory=dict)

    @property
    def family_head(self) -> bool:
        return self.rf_multiclass is not None

    @property
    def feature_schema(self) -> str:
        return self.spec.schema

    @property
    def version(self) -> str:
        return self.manifest.bundle_version

    def model_info(self) -> ModelInfo:
        t = self.thresholds
        return ModelInfo(
            model_version=self.version, bundle_ref=self.ref, registry=self.registry,  # type: ignore[arg-type]
            trained_at=self.manifest.created_at, dataset=self.manifest.dataset,
            split_strategy=self.manifest.split_strategy, feature_schema=self.feature_schema,  # type: ignore[arg-type]
            family_head=self.family_head, feature_count=len(self.spec.names),
            thresholds={k: v for k, v in t.items() if k != "operating_fpr"},
            operating_fpr_target=t["operating_fpr"], metrics_summary=self.manifest.metrics_summary,
        )


def _verify(path: Path, manifest: BundleManifest) -> None:
    listed = set(manifest.files)
    present = {p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()} - {MANIFEST}
    if listed - present:
        raise BundleIntegrityError(f"missing files: {sorted(listed - present)}")
    if present - listed:
        raise BundleIntegrityError(f"unlisted files in bundle: {sorted(present - listed)}")
    bad = [rel for rel, h in manifest.files.items() if sha256_file(path / rel) != h]
    if bad:
        raise BundleIntegrityError(f"sha256 mismatch (corrupted or edited): {sorted(bad)}")
    if sha256_file(path / "feature_spec.json") != manifest.feature_spec_sha256:
        raise BundleIntegrityError("feature_spec.json does not match manifest.feature_spec_sha256")
    if manifest.contract_version.split(".")[0] != CONTRACT_VERSION.split(".")[0]:
        raise BundleIntegrityError(
            f"bundle contract {manifest.contract_version} is incompatible with code contract {CONTRACT_VERSION}")


def _read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def load_local(path: str | Path, ref: str | None = None, registry: str = "local") -> Bundle:
    path = Path(path)
    if not (path / MANIFEST).exists():
        raise BundleIntegrityError(f"{path} has no {MANIFEST}")
    manifest = BundleManifest.model_validate_json((path / MANIFEST).read_text(encoding="utf-8"))
    _verify(path, manifest)
    trained_with = manifest.tags.get("sklearn_version")
    if trained_with and trained_with != sklearn.__version__:
        warnings.warn(f"bundle trained with scikit-learn {trained_with}, running {sklearn.__version__}; "
                      "predictions may differ or loading may fail", stacklevel=2)
    spec = FeatureSpec.load(path / "feature_spec.json")
    transformer = joblib.load(path / "transformer.joblib")
    if transformer.spec.sha256 != spec.sha256:
        raise BundleIntegrityError("transformer was fitted with a different spec than feature_spec.json")
    multi, iso = path / "rf_multiclass.joblib", path / "iforest.joblib"
    return Bundle(
        path=path, ref=ref or f"local:{path.as_posix()}", manifest=manifest, spec=spec, transformer=transformer,
        rf_binary=joblib.load(path / "rf_binary.joblib"),
        rf_multiclass=joblib.load(multi) if multi.exists() else None,
        iforest=joblib.load(iso) if iso.exists() else None,
        benign_val_scores=np.load(path / "iforest_benign_val_scores.npy") if iso.exists() else None,
        thresholds=_read_json(path / "thresholds.json"), label_map=_read_json(path / "label_map.json"),
        drift_reference=_read_json(path / "drift_reference.json"),
        baseline_stats=_read_json(path / "baseline_stats.json"),
        evaluation_report=_read_json(path / "evaluation_report.json") if (path / "evaluation_report.json").exists()
        else None,
        registry=registry,
    )


def load_bundle(ref: str, cache_dir: str = "artifacts/cache") -> Bundle:
    scheme, sep, rest = ref.partition(":")
    if not sep or len(scheme) == 1:  # bare path (also Windows "C:\\...")
        return load_local(ref, ref=f"local:{ref}")
    if scheme == "local":
        return load_local(rest, ref=ref)
    if scheme == "azureml":
        raise NotImplementedError("azureml refs are implemented in M2-12 (nscore.bundle.azure)")
    raise ValueError(f"unknown bundle ref scheme {scheme!r}; use local:<path> or azureml:<name>[:<version>|@latest]")
