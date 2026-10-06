"""NetSentinel Replay Engine (M5-05).

Streams flow records from replay CSVs (CSE-CIC-IDS2018 or LUFlow) into POST /v1/flows
with configurable pacing (--speed), batching, scenario support, and live ground-truth
scoring printed to the console.
Supports mock/offline mode for testing without requiring a live FastAPI server.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from nscore.contracts.schemas import (
    AttackFamily,
    FeatureContribution,
    FlowBatch,
    FlowMeta,
    FlowRecord,
    ScoreBatchResponse,
    ScoreResult,
    Verdict,
)

logger = logging.getLogger("replay")

META_COLS = {
    "flow_id",
    "observed_at",
    "t_rel_s",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "ground_truth",
    "tool",
}

DEFAULT_BATCH_SIZE = 250
MAX_BATCH_SIZE = 500


@dataclass
class ReplaySummary:
    scenario: str
    file_path: str
    bundle: str
    total_flows: int
    batches_sent: int
    elapsed_seconds: float
    throughput_fps: float
    detected_known: int
    detected_novel: int
    detected_benign: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    incidents_created: int
    incidents_updated: int
    gt_counts: dict[str, int] = field(default_factory=dict)


def load_scenario(scenario_path: Path) -> dict[str, Any]:
    """Load a scenario definition YAML file."""
    text = scenario_path.read_text(encoding="utf-8")
    try:
        import yaml

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except ImportError:
        pass

    # Simple fallback parser if PyYAML is not present
    data: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            try:
                if "." in v:
                    v_val: Any = float(v)
                else:
                    v_val = int(v)
            except ValueError:
                v_val = v
            data[k] = v_val
    return data


def load_flow_records(
    file_path: Path, max_flows: int | None = None
) -> tuple[list[FlowRecord], list[float]]:
    """Read flows from a CSV or CSV.gz file into FlowRecord contracts."""
    if not file_path.exists():
        raise FileNotFoundError(f"Replay file not found: {file_path}")

    # Read CSV
    df = pd.read_csv(file_path, dtype={"src_ip": str, "dst_ip": str})
    if max_flows is not None and max_flows > 0:
        df = df.head(max_flows)

    feat_cols = [c for c in df.columns if c not in META_COLS]
    has_t_rel = "t_rel_s" in df.columns

    records: list[FlowRecord] = []
    times: list[float] = []

    for _, r in df.iterrows():
        # Protocol is both FlowMeta.protocol and features["protocol"]
        feats = {c: float(r[c]) for c in feat_cols} | {"protocol": float(r["protocol"])}
        gt = str(r["ground_truth"]) if "ground_truth" in r and pd.notna(r["ground_truth"]) else None

        rec = FlowRecord(
            meta=FlowMeta(
                flow_id=str(r["flow_id"]),
                observed_at=pd.to_datetime(r["observed_at"]).to_pydatetime(),
                src_ip=str(r["src_ip"]),
                dst_ip=str(r["dst_ip"]),
                src_port=int(r["src_port"]) if int(r["src_port"]) >= 0 else 0,
                dst_port=int(r["dst_port"]) if int(r["dst_port"]) >= 0 else 0,
                protocol=int(r["protocol"]),
            ),
            features=feats,
            ground_truth=gt,
        )
        records.append(rec)
        times.append(float(r["t_rel_s"]) if has_t_rel else 0.0)

    return records, times


class ReplayError(RuntimeError):
    """The live API could not score a batch. Raised instead of silently substituting simulated results."""


SIMULATED_LABEL = "SIMULATED: verdicts copied from ground-truth labels, NOT model output"


def mock_score_batch(
    batch: FlowBatch, bundle: str = "netsentinel-bundle"
) -> ScoreBatchResponse:
    """Simulated scoring for --mock / --dry-run ONLY: verdicts are derived from ground truth, never shown as results."""
    results: list[ScoreResult] = []

    for flow in batch.flows:
        gt = (flow.ground_truth or "").strip()
        gt_lower = gt.lower()

        if gt_lower in ("benign", ""):
            verdict = Verdict.BENIGN
            p_attack = 0.015
            family = AttackFamily.BENIGN
            closest = None
            anomaly_pct = 15.0
        elif "holdout-botnet" in bundle and gt_lower == "botnet":
            # The headline novelty case: holdout botnet flagged as novel anomaly
            verdict = Verdict.NOVEL_ANOMALY
            p_attack = 0.89
            family = AttackFamily.UNKNOWN
            closest = AttackFamily.DDOS
            anomaly_pct = 99.8
        elif gt_lower in ("outlier", "unknown"):
            verdict = Verdict.NOVEL_ANOMALY
            p_attack = 0.78
            family = AttackFamily.UNKNOWN
            closest = AttackFamily.DOS
            anomaly_pct = 99.6
        elif gt_lower == "malicious":
            verdict = Verdict.KNOWN_ATTACK
            p_attack = 0.94
            family = AttackFamily.MALICIOUS
            closest = None
            anomaly_pct = 85.0
        else:
            verdict = Verdict.KNOWN_ATTACK
            p_attack = 0.97
            closest = None
            anomaly_pct = 95.0
            # Map canonical known families
            try:
                family = AttackFamily(gt)
            except ValueError:
                family = AttackFamily.RARE

        top_feats = [
            FeatureContribution(
                feature=k,
                value=float(v),
                shap_value=0.15 if i == 0 else 0.08,
                baseline_median=float(v) / 10.0 if float(v) > 0 else 0.0,
            )
            for i, (k, v) in enumerate(list(flow.features.items())[:3])
        ]

        results.append(
            ScoreResult(
                flow_id=flow.meta.flow_id,
                verdict=verdict,
                p_attack=p_attack,
                anomaly_percentile=anomaly_pct,
                attack_family=family,
                family_confidence=0.95 if verdict == Verdict.KNOWN_ATTACK else 0.45,
                closest_family=closest,
                top_features=top_feats,
                model_version=f"mock-{bundle}",
                latency_ms=1.2,
            )
        )

    return ScoreBatchResponse(
        received=len(batch.flows),
        results=results,
        incidents_created=1 if any(r.verdict != Verdict.BENIGN for r in results) else 0,
        incidents_updated=len(batch.flows) - 1 if len(batch.flows) > 1 else 0,
    )


class ReplayEngine:
    """Manages the replay of flow records with pacing and scoring evaluation."""

    def __init__(
        self,
        flows: list[FlowRecord],
        times: list[float],
        speed: float = 1.0,
        batch_size: int = DEFAULT_BATCH_SIZE,
        api_url: str = "http://127.0.0.1:8000",
        api_key: str = "change-me",
        scenario_name: str = "custom",
        file_path: str = "",
        bundle: str = "cic-v1",
        mock: bool = False,
        dry_run: bool = False,
        verbose: bool = True,
        admin_key: str | None = None,
    ):
        self.flows = flows
        self.times = times
        self.speed = max(0.0, speed)
        self.batch_size = min(max(1, batch_size), MAX_BATCH_SIZE)
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.scenario_name = scenario_name
        self.file_path = file_path
        self.bundle = bundle
        self.mock = mock
        self.dry_run = dry_run
        self.verbose = verbose
        self.admin_key = admin_key

        # Metrics
        self.total_flows = len(flows)
        self.batches_sent = 0
        self.detected_known = 0
        self.detected_novel = 0
        self.detected_benign = 0
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.incidents_created = 0
        self.incidents_updated = 0
        self.gt_counts: dict[str, int] = {}
        self.outliers = 0
        self.outliers_flagged = 0

    def _send_batch_http(self, batch: FlowBatch) -> ScoreBatchResponse:
        import httpx

        headers = {"X-API-Key": self.api_key}
        payload = batch.model_dump(mode="json")
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{self.api_url}/v1/flows", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return ScoreBatchResponse.model_validate(data)

    def send_batch(self, batch: FlowBatch) -> ScoreBatchResponse:
        """Send a batch over HTTP or score via in-process mock."""
        if self.dry_run:
            return mock_score_batch(batch, self.bundle)

        if self.mock:
            return mock_score_batch(batch, self.bundle)

        try:
            return self._send_batch_http(batch)
        except Exception as exc:
            hint = ""
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 403:
                hint = " The API rejected the key: set NS_API_KEY to the same value the API runs with."
            elif status is None:
                hint = f" Is the API running at {self.api_url}?"
            raise ReplayError(f"POST {self.api_url}/v1/flows failed ({type(exc).__name__}: {exc}).{hint} "
                              "No results were simulated; use --mock only for an explicitly simulated run.") from exc

    def ensure_bundle(self) -> str:
        """Make sure the API serves this scenario's model; switch it with the admin key if needed. Returns the version."""
        import httpx

        try:
            version = httpx.get(f"{self.api_url}/health", timeout=10.0).json().get("model_version", "")
        except Exception as exc:
            raise ReplayError(f"API not reachable at {self.api_url} ({type(exc).__name__}: {exc}).") from exc
        if version.startswith(self.bundle):
            return version
        if not self.admin_key:
            raise ReplayError(
                f"The API serves '{version}' but this scenario needs '{self.bundle}'. Restart the API with "
                f"MODEL_REF=local:artifacts/bundles/{self.bundle}, or set NS_ADMIN_KEY so replay can switch the model.")
        resp = httpx.post(f"{self.api_url}/v1/admin/reload-model", timeout=120.0,
                          json={"model_ref": f"local:artifacts/bundles/{self.bundle}"},
                          headers={"X-Admin-Key": self.admin_key})
        if resp.status_code != 200:
            raise ReplayError(f"Switching the API to '{self.bundle}' failed: HTTP {resp.status_code} {resp.text[:300]}")
        version = resp.json().get("model_version", "")
        if self.verbose:
            print(f"Switched the API model to {version}")
        return version

    def run(self) -> ReplaySummary:
        """Execute the replay run and return a ReplaySummary."""
        start_time = time.time()
        last_t_rel = self.times[0] if self.times else 0.0

        num_batches = (self.total_flows + self.batch_size - 1) // self.batch_size

        simulated = self.mock or self.dry_run
        model_version = SIMULATED_LABEL if simulated else self.ensure_bundle()

        if self.verbose:
            print("\n================================================================================")
            print(f"NETSENTINEL REPLAY: {self.scenario_name}")
            print(f"File: {self.file_path} | Bundle: {self.bundle} | Flows: {self.total_flows:,}")
            print(f"Speed: {self.speed}x | Batch size: {self.batch_size} | Mode: {'SIMULATED' if simulated else 'LIVE ' + self.api_url}")
            print(f"Model: {model_version}")
            print("================================================================================\n")

        for b_idx in range(num_batches):
            i_start = b_idx * self.batch_size
            i_end = min(i_start + self.batch_size, self.total_flows)
            batch_flows = self.flows[i_start:i_end]
            batch_times = self.times[i_start:i_end]

            # Pacing calculation
            if self.speed > 0.0 and len(batch_times) > 0 and not self.mock and not self.dry_run:
                batch_t = batch_times[-1]
                delta_t = batch_t - last_t_rel
                if delta_t > 0:
                    sleep_sec = delta_t / self.speed
                    time.sleep(min(sleep_sec, 2.0))
                last_t_rel = batch_t

            # Send batch
            batch_obj = FlowBatch(flows=batch_flows)
            resp = self.send_batch(batch_obj)
            self.batches_sent += 1
            self.incidents_created += resp.incidents_created
            self.incidents_updated += resp.incidents_updated

            # Update ground truth metrics
            for flow, res in zip(batch_flows, resp.results, strict=True):  # API must answer every flow
                gt = flow.ground_truth or "UNKNOWN"
                self.gt_counts[gt] = self.gt_counts.get(gt, 0) + 1

                is_gt_attack = gt.lower() not in ("benign", "unknown", "")
                is_pred_attack = res.verdict in (Verdict.KNOWN_ATTACK, Verdict.NOVEL_ANOMALY)

                if res.verdict == Verdict.KNOWN_ATTACK:
                    self.detected_known += 1
                elif res.verdict == Verdict.NOVEL_ANOMALY:
                    self.detected_novel += 1
                else:
                    self.detected_benign += 1

                if gt.lower() == "outlier":
                    # LUFlow "outlier" = unexplained, not a confirmed attack: kept out of precision / recall
                    self.outliers += 1
                    self.outliers_flagged += int(is_pred_attack)
                elif is_gt_attack and is_pred_attack:
                    self.tp += 1
                elif not is_gt_attack and is_pred_attack:
                    self.fp += 1
                elif not is_gt_attack and not is_pred_attack:
                    self.tn += 1
                elif is_gt_attack and not is_pred_attack:
                    self.fn += 1

            # Progress output
            if self.verbose:
                sent_so_far = i_end
                pct = (sent_so_far / self.total_flows) * 100
                prec = (self.tp / (self.tp + self.fp) * 100) if (self.tp + self.fp) > 0 else 100.0
                rec = (self.tp / (self.tp + self.fn) * 100) if (self.tp + self.fn) > 0 else 100.0
                print(
                    f"[{b_idx+1:>3}/{num_batches}] Sent {sent_so_far:>6,}/{self.total_flows:,} flows ({pct:>5.1f}%) "
                    f"| Detections: {self.detected_known} Known, {self.detected_novel} Novel, {self.detected_benign} Benign "
                    + (f"| Precision: {prec:>5.1f}% | Recall: {rec:>5.1f}%" if self.tp + self.fn
                       else f"| False alarms: {self.fp} of {self.fp + self.tn:,} benign")
                )

        elapsed = max(time.time() - start_time, 0.001)
        fps = self.total_flows / elapsed
        prec = (self.tp / (self.tp + self.fp)) if (self.tp + self.fp) > 0 else 1.0
        rec = (self.tp / (self.tp + self.fn)) if (self.tp + self.fn) > 0 else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        summary = ReplaySummary(
            scenario=self.scenario_name,
            file_path=self.file_path,
            bundle=self.bundle,
            total_flows=self.total_flows,
            batches_sent=self.batches_sent,
            elapsed_seconds=elapsed,
            throughput_fps=fps,
            detected_known=self.detected_known,
            detected_novel=self.detected_novel,
            detected_benign=self.detected_benign,
            true_positives=self.tp,
            false_positives=self.fp,
            true_negatives=self.tn,
            false_negatives=self.fn,
            precision=prec,
            recall=rec,
            f1=f1,
            incidents_created=self.incidents_created,
            incidents_updated=self.incidents_updated,
            gt_counts=self.gt_counts,
        )

        if self.verbose:
            print("\n--------------------------------------------------------------------------------")
            print(f"REPLAY SUMMARY: {self.scenario_name}")
            if simulated:
                print(f"*** {SIMULATED_LABEL} ***")
            print(f"Flows Replayed : {summary.total_flows:,} in {summary.elapsed_seconds:.2f}s ({summary.throughput_fps:,.0f} flows/s)")
            print(f"Detections     : {summary.detected_known:,} Known | {summary.detected_novel:,} Novel | {summary.detected_benign:,} Benign")
            print(f"Incidents      : {summary.incidents_created:,} Created, {summary.incidents_updated:,} Updated")
            attacks, benign = self.tp + self.fn, self.fp + self.tn
            if attacks:
                print(f"Precision      : {summary.precision * 100:.2f}% | Recall: {summary.recall * 100:.2f}% | F1: {summary.f1:.4f}")
            else:
                print("Precision      : n/a (no attack flows in this replay)")
            if benign:
                print(f"False alarms   : {self.fp:,} of {benign:,} benign flows ({self.fp / benign * 100:.2f}%)")
            if self.outliers:
                print(f"Outliers       : {self.outliers_flagged:,} of {self.outliers:,} unexplained flows flagged "
                      "(not counted in precision / recall)")
            print(f"Ground Truth   : {dict(summary.gt_counts)}")
            print("--------------------------------------------------------------------------------\n")

        return summary


def run_replay(
    scenario: str | None = None,
    file_path: str | None = None,
    speed: float | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_flows: int | None = None,
    api_url: str = "http://127.0.0.1:8000",
    api_key: str = "change-me",
    bundle: str | None = None,
    mock: bool = False,
    dry_run: bool = False,
    verbose: bool = True,
    admin_key: str | None = None,
) -> ReplaySummary:
    """High-level function to run a replay session from python or CLI."""
    target_file: Path | None = None
    target_bundle = bundle or "cic-v1"
    target_speed = speed if speed is not None else 1.0
    target_batch = batch_size
    scenario_name = "custom"

    # Load scenario YAML if provided
    if scenario:
        scen_path = Path(scenario)
        if not scen_path.is_absolute():
            # Check relative to replay/scenarios/
            alt_path = Path(__file__).resolve().parent / "scenarios" / scenario
            if alt_path.exists():
                scen_path = alt_path
            elif (alt_path.with_suffix(".yaml")).exists():
                scen_path = alt_path.with_suffix(".yaml")
        if not scen_path.exists():
            raise FileNotFoundError(f"Scenario not found: {scenario}")

        scen_data = load_scenario(scen_path)
        scenario_name = scen_data.get("name", scen_path.stem)
        target_file = Path(scen_data.get("file", ""))
        target_bundle = bundle or scen_data.get("bundle", target_bundle)
        if speed is None and "speed" in scen_data:
            target_speed = float(scen_data["speed"])
        if batch_size is not None and batch_size != DEFAULT_BATCH_SIZE:
            target_batch = batch_size
        elif "batch_size" in scen_data:
            target_batch = int(scen_data["batch_size"])

    if file_path:
        target_file = Path(file_path)

    if not target_file:
        raise ValueError("Either --scenario or --file must be specified.")

    if not target_file.is_absolute():
        # Check relative to project root or replay/samples
        root_path = Path(__file__).resolve().parents[1]
        if (root_path / target_file).exists():
            target_file = root_path / target_file
        elif (root_path / "replay" / "samples" / target_file.name).exists():
            target_file = root_path / "replay" / "samples" / target_file.name

    flows, times = load_flow_records(target_file, max_flows=max_flows)

    engine = ReplayEngine(
        flows=flows,
        times=times,
        speed=target_speed,
        batch_size=target_batch,
        api_url=api_url,
        api_key=api_key,
        scenario_name=scenario_name,
        file_path=str(target_file),
        bundle=target_bundle,
        mock=mock,
        dry_run=dry_run,
        verbose=verbose,
        admin_key=admin_key,
    )
    return engine.run()


def main() -> None:
    try:  # NS_API_URL / NS_API_KEY / NS_ADMIN_KEY from the repo's .env; shell variables win
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
    except ImportError:
        pass
    parser = argparse.ArgumentParser(description="NetSentinel Replay Engine (M5-05)")
    parser.add_argument("--scenario", "-s", type=str, help="Scenario YAML name or path")
    parser.add_argument("--file", "-f", type=str, help="CSV/CSV.gz path directly")
    parser.add_argument("--speed", type=float, default=None, help="Pacing speed multiplier (0=instant)")
    parser.add_argument("--batch-size", "-b", type=int, default=DEFAULT_BATCH_SIZE, help="Flows per batch")
    parser.add_argument("--max-flows", "-n", type=int, default=None, help="Max flows to send")
    parser.add_argument(
        "--api-url",
        type=str,
        default=os.getenv("NS_API_URL", "http://127.0.0.1:8000"),
        help="FastAPI base URL",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.getenv("NS_API_KEY") or os.getenv("NS_INGEST_API_KEY", "change-me"),
        help="Ingest API key (default: $NS_API_KEY, the variable the API reads)",
    )
    parser.add_argument(
        "--admin-key",
        type=str,
        default=os.getenv("NS_ADMIN_KEY"),
        help="Admin key: lets replay switch the API to the scenario's model (default: $NS_ADMIN_KEY)",
    )
    parser.add_argument("--bundle", type=str, default=None, help="Bundle name (overrides scenario)")
    parser.add_argument("--mock", action="store_true",
                        help="SIMULATED run without the API: verdicts copied from ground truth (never real results)")
    parser.add_argument("--dry-run", action="store_true", help="Parse and validate without sending")

    args = parser.parse_args()

    try:
        run_replay(
            scenario=args.scenario,
            file_path=args.file,
            speed=args.speed,
            batch_size=args.batch_size,
            max_flows=args.max_flows,
            api_url=args.api_url,
            api_key=args.api_key,
            bundle=args.bundle,
            mock=args.mock,
            dry_run=args.dry_run,
            verbose=True,
            admin_key=args.admin_key,
        )
    except Exception as exc:
        print(f"\n[ERROR] Replay failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
