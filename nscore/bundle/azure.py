"""Azure ML model registry for bundles (M2-12): register a bundle, and fetch one by name:version or @latest.

    register_bundle("artifacts/bundles/cic-v1", name="netsentinel-bundle")   -> "3"
    fetch_bundle("netsentinel-bundle", None)       -> artifacts/cache/azureml/netsentinel-bundle/3   (None = latest)
    load_bundle("azureml:netsentinel-bundle@latest")  (nscore.bundle.loader calls fetch_bundle)

Why it is built this way (demo-proof):
  * pinned versions (`name:3`) are served from the local cache with NO network call when a verified copy exists
  * `@latest` asks Azure for the newest version; if Azure is unreachable it falls back to the newest CACHED version and
    logs a WARNING instead of failing, so a dead Wi-Fi never kills the demo
  * every download is verified against manifest.json (sha256 of every file) before it is used or cached
  * the SDK client is injectable (`client=`), so tests run against a fake without credentials

Configuration (environment, never hard-coded): AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZUREML_WORKSPACE;
credentials via azure.identity.DefaultAzureCredential (az login, service principal env vars, managed identity ...;
browser sign-in only when NS_AZURE_INTERACTIVE=1, which scripts/azure_register.py sets).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from nscore.bundle.packager import MANIFEST
from nscore.contracts.schemas import BundleManifest

log = logging.getLogger("netsentinel.bundle.azure")
DEFAULT_CACHE = Path("artifacts/cache")
_REF = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:(?::(?P<version>[A-Za-z0-9._-]+))|(?:@(?P<label>latest)))?$")


def parse_ref(rest: str) -> tuple[str, str | None]:
    """'netsentinel-bundle:3' -> ('netsentinel-bundle', '3'); 'x@latest' or 'x' -> ('x', None)  (None = latest)."""
    m = _REF.match(rest)
    if not m:
        raise ValueError(f"bad azureml ref {rest!r}; use azureml:<name>[:<version>|@latest]")
    return m["name"], m["version"]


def get_client():
    """MLClient from environment variables. Imported lazily: only registry operations need the Azure SDK."""
    from azure.ai.ml import MLClient
    from azure.identity import DefaultAzureCredential

    needed = ("AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "AZUREML_WORKSPACE")
    missing = [k for k in needed if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"set {', '.join(missing)} (see .env.example and docs/azure_setup.md)")
    # NS_AZURE_INTERACTIVE=1 (set by scripts/azure_register.py) adds a browser sign-in as the last resort, for machines
    # without `az login` or a service principal. Never set for the API server: a server must not open browser windows.
    interactive = os.environ.get("NS_AZURE_INTERACTIVE") == "1"
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=not interactive)
    return MLClient(credential, os.environ["AZURE_SUBSCRIPTION_ID"], os.environ["AZURE_RESOURCE_GROUP"],
                    os.environ["AZUREML_WORKSPACE"])


def _tags(manifest: BundleManifest) -> dict[str, str]:
    t = {k: str(v)[:200] for k, v in manifest.tags.items() if k in ("feature_schema", "family_head", "held_out", "role",
                                                                      "recalibrated", "sklearn_version", "mock")}
    t.update({"dataset": manifest.dataset[:200], "split_strategy": manifest.split_strategy[:200],
              "contract_version": manifest.contract_version, "bundle_version": manifest.bundle_version})
    t.update({f"metric_{k}": f"{v:.5g}" for k, v in manifest.metrics_summary.items()})
    return t


def register_bundle(bundle_dir: str | Path, name: str, client=None, model_factory=None) -> str:
    """Upload a verified bundle as a new version of model `name`; returns the registry version string."""
    from nscore.bundle.loader import load_local  # verify integrity BEFORE uploading anything

    path = Path(bundle_dir)
    bundle = load_local(path)
    if model_factory is None:
        from azure.ai.ml.constants import AssetTypes
        from azure.ai.ml.entities import Model

        def model_factory(**kw):
            return Model(type=AssetTypes.CUSTOM_MODEL, **kw)

    client = client or get_client()
    m = bundle.manifest
    model = model_factory(path=str(path), name=name, tags=_tags(m),
                          description=f"NetSentinel bundle {m.bundle_version} ({m.dataset})")
    registered = client.models.create_or_update(model)
    log.info("registered %s version %s", name, registered.version)
    return str(registered.version)


def _find_bundle_root(folder: Path) -> Path:
    """models.download() may nest the files under a folder named after the model."""
    if (folder / MANIFEST).exists():
        return folder
    hits = list(folder.rglob(MANIFEST))
    if not hits:
        raise FileNotFoundError(f"no {MANIFEST} under {folder}")
    return hits[0].parent


def _verified(path: Path) -> bool:
    from nscore.bundle.loader import BundleIntegrityError, _verify

    try:
        _verify(path, BundleManifest.model_validate_json((path / MANIFEST).read_text(encoding="utf-8")))
        return True
    except (BundleIntegrityError, OSError, ValueError):
        return False


def _cached_versions(cache: Path, name: str) -> list[str]:
    base = cache / "azureml" / name
    if not base.exists():
        return []
    vs = [d.name for d in base.iterdir() if d.is_dir() and (d / MANIFEST).exists()]
    return sorted(vs, key=lambda v: (not v.isdigit(), int(v) if v.isdigit() else 0, v))


def fetch_bundle(name: str, version: str | None = None, cache_dir: str | Path = DEFAULT_CACHE, client=None) -> Path:
    """Return a local, verified copy of the bundle. version None = latest (fallback rules: module docstring)."""
    cache = Path(cache_dir)
    pinned = cache / "azureml" / name / version if version else None
    if pinned and (pinned / MANIFEST).exists() and _verified(pinned):
        log.info("serving %s:%s from the local cache (no network)", name, version)
        return pinned
    try:
        client = client or get_client()
        model = (client.models.get(name=name, version=version) if version
                 else client.models.get(name=name, label="latest"))
        resolved = str(model.version)
        target = cache / "azureml" / name / resolved
        if (target / MANIFEST).exists() and _verified(target):
            return target
        with tempfile.TemporaryDirectory() as tmp:
            client.models.download(name=name, version=resolved, download_path=tmp)
            root = _find_bundle_root(Path(tmp))
            if not _verified(root):
                raise RuntimeError(f"downloaded {name}:{resolved} failed sha256 verification; refusing to cache it")
            if target.exists():
                shutil.rmtree(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(root, target)
        return target
    except Exception as e:  # network, auth, or SDK problems: fall back to the newest verified cached copy
        cached = [v for v in _cached_versions(cache, name) if version in (None, v)]
        for v in reversed(cached):
            if _verified(cache / "azureml" / name / v):
                log.warning("Azure ML unavailable (%s: %s); using CACHED %s:%s", type(e).__name__, e, name, v)
                return cache / "azureml" / name / v
        raise
