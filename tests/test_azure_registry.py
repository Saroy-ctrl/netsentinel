"""Azure ML registry integration against a FAKE client that mirrors the SDK calls (no credentials needed)."""

import shutil
import types
from pathlib import Path

import pytest

import nscore.bundle.azure as az
from nscore.bundle.loader import load_bundle
from tests.test_bundle import bundles  # noqa: F401  (fixture: tiny real bundles)


class FakeModels:
    def __init__(self, store: Path, fail: bool = False):
        self.store, self.fail, self.versions, self.calls = store, fail, {}, []

    def create_or_update(self, model):
        self.calls.append("create")
        v = str(len(self.versions.setdefault(model.name, [])) + 1)
        dest = self.store / model.name / v
        shutil.copytree(model.path, dest)
        self.versions[model.name].append(v)
        return types.SimpleNamespace(version=v, name=model.name, tags=model.tags)

    def get(self, name, version=None, label=None):
        self.calls.append("get")
        if self.fail:
            raise ConnectionError("no network")
        v = version or self.versions[name][-1]
        return types.SimpleNamespace(version=v, name=name)

    def download(self, name, version, download_path):
        self.calls.append("download")
        shutil.copytree(self.store / name / version, Path(download_path) / name)  # nested, like the real SDK


class FakeClient:
    def __init__(self, store, fail=False):
        self.models = FakeModels(store, fail)


def factory(**kw):
    return types.SimpleNamespace(**kw)


def test_parse_ref():
    assert az.parse_ref("netsentinel-bundle:3") == ("netsentinel-bundle", "3")
    assert az.parse_ref("netsentinel-bundle@latest") == ("netsentinel-bundle", None)
    assert az.parse_ref("netsentinel-bundle") == ("netsentinel-bundle", None)
    with pytest.raises(ValueError):
        az.parse_ref("bad name")


def test_register_fetch_cache_and_offline_fallback(bundles, tmp_path):  # noqa: F811
    client = FakeClient(tmp_path / "registry")
    v1 = az.register_bundle(bundles["cic"], "nsb", client=client, model_factory=factory)
    v2 = az.register_bundle(bundles["cic"], "nsb", client=client, model_factory=factory)
    assert (v1, v2) == ("1", "2")

    cache = tmp_path / "cache"
    p = az.fetch_bundle("nsb", None, cache, client=client)  # latest -> v2, downloaded and cached
    assert p == cache / "azureml" / "nsb" / "2" and (p / "manifest.json").exists()
    n_calls = len(client.models.calls)
    assert az.fetch_bundle("nsb", "2", cache, client=client) == p
    assert len(client.models.calls) == n_calls  # pinned version: served from cache, no network call

    # Azure down: @latest falls back to the cached copy (and the bundle still loads and verifies)
    dead = FakeClient(tmp_path / "registry", fail=True)
    assert az.fetch_bundle("nsb", None, cache, client=dead) == p
    b = load_bundle("azureml:nsb@latest", cache_dir=str(cache))  # real client unavailable here -> cache fallback
    assert b.registry == "azureml" and b.ref == "azureml:nsb@latest" and b.family_head


def test_corrupted_download_is_refused_and_not_cached(bundles, tmp_path):  # noqa: F811
    client = FakeClient(tmp_path / "registry")
    az.register_bundle(bundles["cic"], "bad", client=client, model_factory=factory)
    (tmp_path / "registry" / "bad" / "1" / "thresholds.json").write_text('{"tau_binary": 0}')  # tamper in the registry
    with pytest.raises(RuntimeError, match="sha256"):
        az.fetch_bundle("bad", None, tmp_path / "cache", client=client)
    assert not (tmp_path / "cache" / "azureml" / "bad").exists()


def test_no_cache_and_no_network_raises(tmp_path):
    with pytest.raises(ConnectionError):
        az.fetch_bundle("nothing", None, tmp_path / "cache", client=FakeClient(tmp_path / "r", fail=True))


def test_register_refuses_a_tampered_local_bundle(bundles, tmp_path):  # noqa: F811
    d = tmp_path / "b"
    shutil.copytree(bundles["cic"], d)
    (d / "label_map.json").write_text('{"classes": []}')
    with pytest.raises(Exception, match="sha256"):
        az.register_bundle(d, "x", client=FakeClient(tmp_path / "r"), model_factory=factory)
