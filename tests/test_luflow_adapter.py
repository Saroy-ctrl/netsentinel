import zipfile

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.data.adapters import luflow as lu


def test_fix_timestamps_recovers_lost_leading_zeros_exactly():
    sec = 1_592_533_725
    cases = {  # true microsecond part -> what the buggy export wrote
        648_144: 1_592_533_725_648_144,   # 6 digits: already correct
        48_144: 159_253_372_548_144,      # leading zero lost (x10 too small)
        8_144: 15_925_337_258_144,        # two lost (x100)
        144: 1_592_533_725_144,           # three lost (x1000)
        0: 15_925_337_250,                # usec == 0 written as "0"
    }
    raw = np.array(list(cases.values()), dtype=np.int64)
    fixed = lu.fix_timestamps(raw)
    expected = np.array([sec * 1_000_000 + u for u in cases], dtype=np.int64)
    assert (fixed == expected).all()
    assert (lu.fix_timestamps(fixed) == fixed).all()  # idempotent on correct values


def _csv(rows):
    base = {"avg_ipt": 1.0, "bytes_in": 10, "bytes_out": 20, "dest_ip": 786, "dest_port": 80.0, "entropy": 3.0,
            "num_pkts_out": 2, "num_pkts_in": 2, "proto": 6, "src_ip": 5, "src_port": 1234.0, "time_end": 0,
            "total_entropy": 100.0, "label": "benign", "duration": 0.1}
    return pd.DataFrame([base | r for r in rows]).to_csv(index=False)


def test_adapter_repairs_dedupes_and_drops_garbage_timestamps(tmp_path):
    good = 1_592_533_725_648_144          # 2020-06-19
    lost = 159_253_372_548_144            # same day, usec lost a zero
    far = 1_700_000_000_000_000           # 2023: nowhere near the file date -> dropped
    rows = [
        {"time_start": good, "bytes_in": 1},
        {"time_start": lost, "bytes_in": 2},
        {"time_start": good, "bytes_in": 2},          # exact duplicate of the repaired row above -> removed
        {"time_start": far, "bytes_in": 3},
        {"time_start": good, "bytes_in": 4, "dest_port": np.nan, "label": "outlier"},
    ]
    raw = tmp_path / "2020" / "06"
    raw.mkdir(parents=True)
    with zipfile.ZipFile(raw / "2020.06.19.zip", "w") as z:
        z.writestr("2020.06.19.csv", _csv(rows))
    rep = lu.process(tmp_path, tmp_path / "out", None)
    t = pq.read_table(tmp_path / "out" / "2020.06.19.parquet").to_pandas()
    assert rep["totals"]["rows_in"] == 5
    assert rep["totals"]["duplicates_removed"] == 1
    assert rep["totals"]["timestamps_repaired"] == 1
    assert rep["totals"]["timestamps_dropped"] == 1
    assert len(t) == 3 and set(t.period) == {"2020-06"}
    assert t.ts.min().isoformat().startswith("2020-06-19T")
    assert t.loc[t.family == "Outlier", "dst_port"].iloc[0] == -1  # blank port -> -1, not NaN
    assert set(t.family) == {"BENIGN", "Outlier"}
