"""M3-08: Drift Monitor Service.

Maintains a rolling window of the last WINDOW_SIZE (2,000) transformed flow
vectors and computes PSI every SNAPSHOT_INTERVAL (500) accumulated flows
against the model bundle's drift_reference.json.

Design notes
------------
- The rolling window is a ``collections.deque(maxlen=2000)`` of 1-D numpy
  row vectors (one per flow).  Row order matches ``bundle.spec.names``.
- A separate deque tracks verdict strings in lock-step so we can compute
  ``prediction_attack_rate`` without needing a DB round-trip.
- PSI is triggered once per ``observe()`` call whenever a new 500-flow
  checkpoint is crossed.  Computation is synchronous (no background thread).
- Each snapshot is persisted to the ``drift_snapshots`` SQLite table and
  cached in-memory as ``self._latest`` for O(1) retrieval by the API.
- Cold-start recovery: ``__init__`` tries to load the most recent snapshot
  for this model version from the DB.  Failures are silently swallowed
  (the DB may not be initialised yet on first run).

Architecture reference: docs/03_architecture.md §4.6, M3-08 spec.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import numpy as np

from api.app.db import db_session
from nscore.contracts import schemas
from nscore.drift import psi as psi_module

if TYPE_CHECKING:
    from nscore.bundle.loader import Bundle

logger = logging.getLogger(__name__)

WINDOW_SIZE = 2_000
SNAPSHOT_INTERVAL = 500
MIN_WINDOW = 200  # benign flows needed before PSI is meaningful (10 bins per feature)


class DriftMonitor:
    """Rolling PSI drift monitor for one loaded model bundle.

    Constructed once per bundle load (inside the FastAPI lifespan) and
    attached to ``app.state.drift_monitor``.
    """

    def __init__(self, bundle: Bundle, db_path: str) -> None:
        self._model_version: str = bundle.version
        self._ref: dict = bundle.drift_reference          # drift_reference.json contents
        self._names: list[str] = list(self._ref["features"])  # feature order = spec.names order
        self._db_path: str = db_path

        # Rolling window: deque rows are 1-D float64 arrays, one per flow
        self._deque: deque[np.ndarray] = deque(maxlen=WINDOW_SIZE)
        # Parallel verdict deque to compute prediction_attack_rate
        self._verdict_deque: deque[str] = deque(maxlen=WINDOW_SIZE)

        # Cumulative count for checkpoint arithmetic (not reset when deque wraps)
        self._total_observed: int = 0

        # In-memory latest snapshot (None until first compute)
        self._latest: schemas.DriftReport | None = None

        # Cold-start: load most-recent snapshot for this model from DB
        self._load_latest_from_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, X_batch: np.ndarray, verdicts: list[str] | None = None) -> None:
        """Append a batch of transformed flow vectors into the rolling window.

        Args:
            X_batch:  2-D float64 array (n_flows, n_features) - the ``det.X``
                      output of ``DetectionEngine.detect()``.
            verdicts: Parallel list of verdict strings (``v.value``) for each
                      row in ``X_batch``.  If omitted, rows are counted as
                      benign for the attack-rate metric.
        """
        if X_batch is None or X_batch.ndim != 2 or X_batch.shape[0] == 0:
            return

        n = X_batch.shape[0]
        for i in range(n):
            v = verdicts[i] if (verdicts is not None and i < len(verdicts)) else "benign"
            self._verdict_deque.append(v)
            # PSI is measured on traffic the model calls benign, against the benign training reference: it answers
            # "does normal traffic still look like what the model learned?". Attacks are reported as incidents; with
            # them in the window every attack replay read as drift (max PSI 7-9) and even normal traffic as ALERT.
            if v == "benign":
                self._deque.append(X_batch[i])

        prev_total = self._total_observed
        self._total_observed += n

        # Trigger once per observe() call when a new 500-flow checkpoint is crossed
        prev_cp = prev_total // SNAPSHOT_INTERVAL
        curr_cp = self._total_observed // SNAPSHOT_INTERVAL
        if curr_cp > prev_cp and self._total_observed >= SNAPSHOT_INTERVAL:
            self._compute_and_persist()

    def get_latest_report(self) -> schemas.DriftReport | None:
        """Return the most recently computed DriftReport, or None."""
        return self._latest

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_and_persist(self) -> None:
        """Compute PSI from the current rolling window and persist a snapshot."""
        window = list(self._deque)
        verdicts = list(self._verdict_deque)
        if len(window) < MIN_WINDOW:  # too few benign flows yet (e.g. during an attack burst): keep the last report
            return

        X_window = np.stack(window, axis=0)   # (n, n_features)

        # -- PSI computation ---------------------------------------------------
        try:
            psi_scores: dict[str, float] = psi_module.psi_all(
                self._ref, X_window, self._names
            )
        except Exception as exc:
            logger.warning("M3-08: PSI computation failed: %s", exc)
            return

        max_psi = max(psi_scores.values()) if psi_scores else 0.0
        overall_status: schemas.DriftStatus = psi_module.status(max_psi)

        # Feature list sorted by PSI descending
        feature_drifts = [
            schemas.FeatureDrift(
                feature=name,
                psi=score,
                status=psi_module.status(score),
            )
            for name, score in sorted(psi_scores.items(), key=lambda kv: -kv[1])
        ]

        # -- Attack rates ------------------------------------------------------
        n_total = len(verdicts)
        n_attack = sum(1 for v in verdicts if v != "benign")
        prediction_attack_rate = n_attack / n_total if n_total > 0 else 0.0

        # Reference attack rate: not stored in drift_reference.json; use 0.0
        reference_attack_rate = 0.0

        # -- Build report ------------------------------------------------------
        computed_at = datetime.now(UTC)
        report = schemas.DriftReport(
            computed_at=computed_at,
            window_size=len(window),
            status=overall_status,
            max_psi=max_psi,
            features=feature_drifts,
            prediction_attack_rate=prediction_attack_rate,
            reference_attack_rate=reference_attack_rate,
        )

        # -- Persist to DB -----------------------------------------------------
        report_json_str = report.model_dump_json()
        status_str = overall_status.value  # DriftStatus is StrEnum
        try:
            with db_session(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO drift_snapshots
                        (computed_at, model_version, window_size, status, max_psi, report_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        computed_at.isoformat(),
                        self._model_version,
                        len(window),
                        status_str,
                        max_psi,
                        report_json_str,
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.warning("M3-08: Failed to persist drift snapshot: %s", exc)

        self._latest = report
        logger.info(
            "M3-08: PSI snapshot — max_psi=%.4f status=%s window=%d",
            max_psi, status_str, len(window),
        )

    def _load_latest_from_db(self) -> None:
        """Load the most recent snapshot for this model version from the DB.

        Silently ignores any error (DB may not be initialised yet on first run).
        """
        try:
            with db_session(self._db_path) as conn:
                row = conn.execute(
                    """
                    SELECT report_json FROM drift_snapshots
                    WHERE model_version = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (self._model_version,),
                ).fetchone()
            if row and row[0]:
                self._latest = schemas.DriftReport.model_validate_json(row[0])
        except Exception:
            pass  # DB not ready yet - not a fatal error
