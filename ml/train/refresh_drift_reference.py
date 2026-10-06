"""Rebuild a bundle's drift_reference.json from BENIGN training flows only, without retraining.

    python -m ml.train.refresh_drift_reference artifacts/bundles/cic-v1 artifacts/bundles/luflow-v1 ...

Why: the API measures drift on traffic the model calls benign (api/app/services/drift.py). A reference that mixes in the
training attacks made even normal traffic read as ALERT (max PSI 1.36 on random benign validation flows; 0.02 against a
benign-only reference). Models, thresholds and every other file stay byte-identical; only drift_reference.json and the
manifest's hashes change. New bundles get the benign reference directly (build_bundles.py, luflow.py).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.data.working_set import load
from nscore.bundle.loader import load_bundle
from nscore.bundle.packager import MANIFEST, sha256_file
from nscore.contracts.schemas import BundleManifest
from nscore.drift.psi import build_reference

SEED = 42
MAX_ROWS = 1_000_000


def refresh(bundle_dir: Path) -> None:
    bundle = load_bundle(f"local:{bundle_dir}")  # verifies integrity first
    schema = bundle.manifest.tags.get("feature_schema", "cic")
    train = load(schema, "train")
    benign = train[train["family"] == "BENIGN"]
    benign = benign.sample(min(len(benign), MAX_ROWS), random_state=SEED)
    ref = build_reference(bundle.transformer.transform(benign), bundle.transformer.feature_names)
    (bundle_dir / "drift_reference.json").write_text(json.dumps(ref), encoding="utf-8")

    manifest = BundleManifest.model_validate_json((bundle_dir / MANIFEST).read_text(encoding="utf-8"))
    files = {p.relative_to(bundle_dir).as_posix(): sha256_file(p)
             for p in sorted(bundle_dir.rglob("*")) if p.is_file() and p.name != MANIFEST}
    manifest = manifest.model_copy(update={"files": files})
    (bundle_dir / MANIFEST).write_text(manifest.model_dump_json(indent=1) + "\n", encoding="utf-8")
    load_bundle(f"local:{bundle_dir}")  # must still verify
    print(f"{bundle_dir}: drift reference rebuilt from {len(benign):,} benign training flows ({schema})")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundles", nargs="+", type=Path)
    for b in ap.parse_args().bundles:
        refresh(b)


if __name__ == "__main__":
    main()
