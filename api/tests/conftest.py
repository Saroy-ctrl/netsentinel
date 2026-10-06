"""Test isolation: every test starts with a clean API environment, so ordering never matters.

Several tests used to set NS_MOCK / NS_DB_PATH at import time or leave them behind; that made results depend on which
test file ran first. Tests that need mock mode or a DB path set them themselves (monkeypatch or their own fixture).
"""

import os

import pytest

os.environ["NS_LOAD_DOTENV"] = "0"  # runs before any test module imports the app: never read a developer's .env


@pytest.fixture(autouse=True)
def _isolated_api_env(monkeypatch):
    for name in ("NS_MOCK", "NS_DB_PATH", "MODEL_REF"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NS_API_KEY", "test_api_key")
    monkeypatch.setenv("NS_ADMIN_KEY", "admin_secret")
