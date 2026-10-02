# ml/ — offline pipeline (M1, M2)

Runs once per model version. Output is a **model bundle** (see docs/03_architecture.md §3.5).

| Folder | Owner | Tasks |
|---|---|---|
| `data/` | M1 | adapters/ (cic2018, luflow), split.py, baseline_stats.py (M1-03, M1-05, M1-08, M1-09) |
| `train/` | M2 | rf_binary, rf_multiclass, iforest, thresholds (M2-02…M2-07) |
| `evaluate/` | M2 | metrics harness, LOAO (M2-02, M2-08) |
| `explain/` | M2 | SHAP (M2-09) |
| `registry/` | M2 | package + Azure ML register (M2-10, M2-12) |
| `evaluate/` (external) | M2 | HOIC tool holdout (M2-08), LUFlow real-world + recalibration (M2-11) |

Rules: fit anything (scaler, SMOTE, thresholds) on **train or val only**, never test. Import feature code from `nscore.features`, never copy it.
