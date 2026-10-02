# data/ (gitignored except this file)

```
raw/        original downloads, untouched (+ MANIFEST.json per dataset: size + sha256)
processed/  cleaned parquet per dataset: cic2018 / luflow (M1-03, M1-09)
splits/     fixed split indices + split_manifest.json (M1-05)
replay/     demo replay CSVs (M1-10)
```

## Reproduce `raw/` (M1-01)

```bash
python ml/data/download.py cic2018                     # ~10.4 GB zip, resumable (~1 h at 3 MB/s)
python ml/data/download.py luflow --days-per-month 8   # 72 daily zips, 1.47 GB
```
Then compare your `data/raw/<dataset>/MANIFEST.json` with a teammate's: identical sha256 = identical data.
Keep everything on a drive with space (D:); the 2018 zip expands to much more than 10 GB.

---

## CSE-CIC-IDS2018, corrected (train / val / test)

| | |
|---|---|
| Source | https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip |
| Paper | Liu, Engelen, Lynar, Essam, Joosen, *Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS 2022 |
| Zip | 10,426,851,729 bytes, last modified 2023-04-03 · sha256 in `raw/cic2018/MANIFEST.json` |
| Labels | "Attempted" flows → relabel **BENIGN** (authors' advice: rows where `Attempted Category != -1`). Never a separate class. |

**Zip contents** (read from the archive's central directory): 10 day files, **36.0 GB uncompressed**. Don't unzip; stream each CSV out of the zip in chunks (M1-03).

| File | Uncompressed | | File | Uncompressed |
|---|---:|---|---|---:|
| Wednesday-14-02-2018.csv | 3.26 GB | | Thursday-22-02-2018.csv | 3.47 GB |
| Thursday-15-02-2018.csv | 2.99 GB | | Friday-23-02-2018.csv | 3.41 GB |
| Friday-16-02-2018.csv | 4.21 GB | | Wednesday-28-02-2018.csv | 3.81 GB |
| Tuesday-20-02-2018.csv | 3.43 GB | | Thursday-01-03-2018.csv | 3.81 GB |
| Wednesday-21-02-2018.csv | 3.95 GB | | Friday-02-03-2018.csv | 3.69 GB |

**Column check: PASSED.** 91 columns, including `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`,
`Timestamp` (e.g. `2018-02-14 12:30:07.258263`, µs precision), `Label` and `Attempted Category`. Also present vs the
original release: `id`, `Fwd/Bwd RST Flags`, `ICMP Code`, `ICMP Type`, `Total TCP Flow Time` (fixed-CICFlowMeter features).
Roughly 600 bytes per row → expect on the order of **60M flows** in total (exact counts below once streamed).

Row counts per day and label: _filled in by M1-01's counting pass after the download finishes._

## LUFlow (real-traffic showcase)

| | |
|---|---|
| Source | https://github.com/ruzzzzz/LUFlow (one zip per day, each holding one CSV) |
| Paper | *Practical Intrusion Detection of Emerging Threats*, IEEE TNSM (Lancaster University) |
| Coverage in repo | 2020-06 → 2021-02 (+3 days of 2022-06, not used) |
| Our subset | **8 evenly spaced days per month × 9 months = 72 files, 1.47 GB zipped, 63,011,836 flows** |

### Rows per month and label (our 72-day subset)

| Month | benign | malicious | outlier | total |
|---|---:|---:|---:|---:|
| 2020-06 | 6,349,370 | 2,014,977 | 1,421,569 | 9,785,916 |
| 2020-07 | 3,974,900 | 2,769,814 | 584,278 | 7,328,992 |
| 2020-08 | 2,827,372 | 2,701,067 | 545,647 | 6,074,086 |
| 2020-09 | 2,901,403 | 1,886,921 | 640,600 | 5,428,924 |
| 2020-10 | 4,256,611 | 3,341,321 | 746,633 | 8,344,565 |
| 2020-11 | 3,335,075 | 2,686,956 | 935,888 | 6,957,919 |
| 2020-12 | 4,349,343 | 1,291,211 | 883,005 | 6,523,559 |
| 2021-01 | 2,929,316 | 1,320,103 | 792,833 | 5,042,252 |
| 2021-02 | 3,679,380 | 2,141,864 | 1,704,379 | 7,525,623 |

### Schema (16 columns) and notes for `feature_spec.luflow.json` (M1-09)

| Column | Type | Role |
|---|---|---|
| `avg_ipt` | float | feature: mean inter-packet time (**the README calls it `mean_ipt`; the CSVs say `avg_ipt`**) |
| `bytes_in`, `bytes_out` | int | features: bytes src→dst / dst→src |
| `num_pkts_in`, `num_pkts_out` | int | features: packets src→dst / dst→src |
| `entropy`, `total_entropy` | float | features: payload entropy (bits/byte, 0–8) and total |
| `duration` | float | feature: seconds, µs precision |
| `proto` | int | feature (categorical: 6 TCP, 17 UDP, 1 ICMP …) |
| `dest_port`, `src_port` | **float, can be blank** | dest_port: feature candidate (same open question as B12) · src_port: metadata. Blank for port-less protocols → fill with -1 |
| `src_ip`, `dest_ip` | **int** | metadata only. Anonymised to the owning network (AS), so convert to string for `FlowMeta` |
| `time_start`, `time_end` | int | metadata: **microseconds** since epoch |
| `label` | str | `benign` / `malicious` / `outlier` |

Scale: ~5–10M flows per month even in the subset, so train and test on fixed-seed samples (e.g. 2M train rows, 500k per test month).
