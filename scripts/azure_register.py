"""Register a model bundle in the Azure ML workspace (M2-12).

    python scripts/azure_register.py artifacts/bundles/cic-v1 --name netsentinel-bundle
    python scripts/azure_register.py artifacts/bundles/cic-holdout-botnet --name netsentinel-demo-holdout-botnet
    python scripts/azure_register.py --verify netsentinel-bundle        # pull @latest into a CLEAN cache and load it

Needs AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZUREML_WORKSPACE and a login (az login). See docs/azure_setup.md.
`--verify` is the "works from a clean machine" proof for M2-12: it downloads into a temp cache and loads the bundle.
"""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from pathlib import Path

from nscore.bundle.azure import register_bundle
from nscore.bundle.loader import load_bundle


def _load_env() -> None:
    """Read .env (AZURE_* settings) and allow browser sign-in when there is no az login / service principal."""
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    except ImportError:
        pass
    os.environ.setdefault("NS_AZURE_INTERACTIVE", "1")


def main() -> None:
    _load_env()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", nargs="?", type=Path, help="bundle folder to register")
    ap.add_argument("--name", help="registry model name")
    ap.add_argument("--verify", metavar="NAME", help="download NAME@latest into an empty cache and load it")
    a = ap.parse_args()
    if a.verify:
        with tempfile.TemporaryDirectory() as cache:
            b = load_bundle(f"azureml:{a.verify}@latest", cache_dir=cache)
            print(f"OK: pulled {a.verify}@latest into an empty cache -> {b.version}, schema {b.feature_schema}, "
                  f"family_head={b.family_head}, {len(b.manifest.files)} files verified")
        return
    if not (a.bundle and a.name):
        ap.error("give a bundle folder and --name, or --verify NAME")
    print("registered version", register_bundle(a.bundle, a.name))


if __name__ == "__main__":
    main()
