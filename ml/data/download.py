"""M1-01: download the raw datasets reproducibly (resumable) and record a manifest.

    python ml/data/download.py cic2018                      # corrected CSE-CIC-IDS2018 (~10.4 GB zip)
    python ml/data/download.py luflow --days-per-month 8    # LUFlow daily zips, evenly spaced per month
    python ml/data/download.py manifest --of cic2018         # (re)hash one dataset folder

Files land in data/raw/<dataset>/ (gitignored). data/raw/<dataset>/MANIFEST.json records size + sha256
of every file so teammates can check they have exactly the same bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

CIC2018_URL = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip"
CIC2018_SIZE = 10_426_851_729  # Content-Length on 2026-10-02 (file last modified 2023-04-03)

LUFLOW_TREE = "https://api.github.com/repos/ruzzzzz/LUFlow/git/trees/HEAD?recursive=1"
LUFLOW_RAW = "https://raw.githubusercontent.com/ruzzzzz/LUFlow/HEAD/"
LUFLOW_MONTHS = [f"2020/{m:02d}" for m in range(6, 13)] + ["2021/01", "2021/02"]  # 2022/06 has only 3 days

CHUNK = 1 << 20


def fetch(url: str, dest: Path, expected_size: int | None = None, retries: int = 20) -> Path:
    """Resumable download via HTTP Range. Skips files that are already complete."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, retries + 1):
        have = dest.stat().st_size if dest.exists() else 0
        if expected_size is not None and have == expected_size:
            return dest
        headers = {"Range": f"bytes={have}-"} if have else {}
        try:
            with requests.get(url, headers=headers, stream=True, timeout=60) as r:
                if r.status_code == 416:  # already complete
                    return dest
                r.raise_for_status()
                mode = "ab" if have and r.status_code == 206 else "wb"
                total = expected_size or (have + int(r.headers.get("Content-Length", 0)))
                t0, done = time.time(), 0
                with open(dest, mode) as f:
                    for chunk in r.iter_content(CHUNK):
                        f.write(chunk)
                        done += len(chunk)
                        if total and done % (64 * CHUNK) < CHUNK:
                            pct = 100 * (have + done) / total
                            rate = done / max(time.time() - t0, 1e-6) / 1e6
                            print(f"\r  {dest.name}: {pct:5.1f}%  {rate:.1f} MB/s", end="", flush=True)
            print()
            if expected_size is None or dest.stat().st_size == expected_size:
                return dest
        except requests.RequestException as e:
            print(f"\n  attempt {attempt} failed: {e}; retrying in 10 s", file=sys.stderr)
            time.sleep(10)
    raise RuntimeError(f"could not download {url}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(16 * CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(dataset: str) -> Path:
    base = RAW / dataset
    entries = {}
    for p in sorted(base.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.json":
            rel = p.relative_to(base).as_posix()
            print(f"  hashing {rel}")
            entries[rel] = {"bytes": p.stat().st_size, "sha256": sha256(p)}
    out = base / "MANIFEST.json"
    out.write_text(json.dumps({"generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                               "files": entries}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(entries)} files)")
    return out


def luflow_selection(tree: list[dict], days_per_month: int) -> list[dict]:
    """Evenly spaced days within each month -> stable, reproducible subset."""
    by_month: dict[str, list[dict]] = defaultdict(list)
    for item in tree:
        if item["type"] == "blob" and item["path"].endswith(".zip"):
            month = "/".join(item["path"].split("/")[:2])
            if month in LUFLOW_MONTHS:
                by_month[month].append(item)
    picked = []
    for month in LUFLOW_MONTHS:
        days = sorted(by_month[month], key=lambda i: i["path"])
        if len(days) <= days_per_month:
            picked += days
            continue
        step = (len(days) - 1) / (days_per_month - 1)
        picked += [days[round(k * step)] for k in range(days_per_month)]
    return picked


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", choices=["cic2018", "luflow", "manifest"])
    ap.add_argument("--days-per-month", type=int, default=8, help="LUFlow days per month (0 = all)")
    ap.add_argument("--of", choices=["cic2018", "luflow"], help="dataset folder for the manifest command")
    a = ap.parse_args()
    if a.dataset == "manifest" and not a.of:
        ap.error("manifest needs --of cic2018|luflow")

    if a.dataset == "cic2018":
        fetch(CIC2018_URL, RAW / "cic2018" / "CSECICIDS2018_improved.zip", CIC2018_SIZE)
    elif a.dataset == "luflow":
        tree = requests.get(LUFLOW_TREE, timeout=60).json()["tree"]
        files = luflow_selection(tree, a.days_per_month or 10_000)
        print(f"LUFlow: {len(files)} daily files, {sum(f['size'] for f in files) / 1e6:.0f} MB")
        for f in files:
            fetch(LUFLOW_RAW + f["path"], RAW / "luflow" / f["path"], f["size"])
    write_manifest(a.of if a.dataset == "manifest" else a.dataset)


if __name__ == "__main__":
    main()
