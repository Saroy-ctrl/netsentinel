"""M1-03 adapter tests on a tiny synthetic zip (no real data needed)."""

import io
import json
import zipfile

import pandas as pd
import pyarrow.parquet as pq
import pytest

from ml.data.adapters import cic2018 as a


def _row(i, label="BENIGN", attempted=-1, **over):
    r = {c: 1 for c in a.RAW_COLUMNS}
    r.update({"id": i, "Flow ID": f"f{i}", "Src IP": "10.0.0.1", "Dst IP": "10.0.0.2", "Src Port": 1000 + i,
              "Dst Port": 80, "Protocol": 6, "Timestamp": f"2018-02-14 12:30:0{i}.123456", "Label": label,
              "Attempted Category": attempted, "Flow Duration": 100 + i})
    r.update(over)
    return r


def _zip(tmp_path, rows):
    csv = pd.DataFrame(rows)[a.RAW_COLUMNS].to_csv(index=False)
    p = tmp_path / "t.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Wednesday-14-02-2018.csv", csv)
    return p


def test_snake_case_names_unique_and_readable():
    assert len(a.FEATURES) == 81 == len(set(a.FEATURES))
    assert a.snake("Flow Bytes/s") == "flow_bytes_per_s"
    assert a.snake("FWD Init Win Bytes") == "fwd_init_win_bytes"
    assert a.snake("Fwd Packet/Bulk Avg") == "fwd_packet_per_bulk_avg"
    assert a.snake("Down/Up Ratio") == "down_per_up_ratio"


def test_end_to_end_cleaning(tmp_path):
    rows = [
        _row(0),
        _row(1, **{"Flow Bytes/s": "Infinity"}),
        _row(2, label="DoS Hulk"),
        _row(3, label="DoS GoldenEye - Attempted", attempted=2),
        # exact feature duplicate of row 0 (different id/ports/timestamp) -> removed
        _row(4, **{"Flow Duration": 100}),
    ]
    out = tmp_path / "out"
    rep = a.process(_zip(tmp_path, rows), out, None, chunk_mb=1, max_chunks=None)
    t = pq.read_table(out / "Wednesday-14-02-2018.parquet").to_pandas()

    assert rep["totals"]["rows_in"] == 5
    assert rep["totals"]["duplicates_removed"] == 1
    assert rep["totals"]["attempted_to_benign"] == 1
    assert len(t) == 4 and list(t["row"]) == [0, 1, 2, 3]
    assert t.loc[2, "family"] == "DoS" and t.loc[2, "tool"] == "DoS Hulk"
    assert t.loc[3, "family"] == "BENIGN" and bool(t.loc[3, "attempted"])  # Attempted -> benign, label kept
    assert pd.isna(t.loc[1, "flow_bytes_per_s"])  # Infinity -> NaN, not 0
    assert rep["days"]["Wednesday-14-02-2018"]["columns"]["flow_bytes_per_s"]["inf"] == 1
    assert str(t["ts"].dtype).startswith("datetime64[us]")
    assert t["flow_duration"].dtype == "float32"
    json.dumps(rep, default=dict)  # report must be serialisable


def test_duplicates_removed_across_days(tmp_path):
    csv = pd.DataFrame([_row(0)])[a.RAW_COLUMNS].to_csv(index=False)
    p = tmp_path / "t.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Wednesday-14-02-2018.csv", csv)
        z.writestr("Thursday-15-02-2018.csv", csv)  # same flow on another day
    rep = a.process(p, tmp_path / "o", None, 1, None)
    assert rep["totals"]["rows_kept"] == 1 and rep["totals"]["duplicates_removed"] == 1


def test_unmapped_label_fails_loudly(tmp_path):
    with pytest.raises(ValueError, match="unmapped labels"):
        a.process(_zip(tmp_path, [_row(0, label="Brand New Attack")]), tmp_path / "o", None, 1, None)


def test_header_change_fails_loudly():
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.csv", "a,b\n1,2\n")
    with zipfile.ZipFile(z) as zf, pytest.raises(ValueError, match="unexpected header"):
        next(a.iter_chunks(zf, "x.csv", 1 << 20))
