"""Unit test for the M5-04 brief evaluation harness.

Ensures that all 10 varied evaluation incidents pass grounding, hedging,
category rules, and determinism checks.
"""

from __future__ import annotations

import pytest

from api.app.services.brief_eval import (
    build_10_eval_incidents,
    evaluate_single_brief,
    run_all_evaluations,
)
from api.app.services.brief import generate_brief


def test_all_10_eval_incidents_pass():
    """All 10 evaluation incidents must pass all safety and grounding criteria."""
    results = run_all_evaluations()
    assert len(results) == 10

    failures = []
    for r in results:
        if not r.passed:
            failures.append(f"{r.case_id} ({r.name}): {', '.join(r.details)}")

    assert not failures, f"Evaluation failures encountered: {failures}"


def test_eval_grounding_catches_hallucinations():
    """Verify that the evaluator correctly detects ungrounded claims or forbidden terms."""
    incidents = build_10_eval_incidents()
    target_inc = incidents[0]

    # Generate normal brief
    brief = generate_brief(target_inc, refresh=True, client=None)

    # Corrupt brief with a forbidden hallucination
    corrupted_brief = brief.model_copy(
        update={"text": brief.text + " Exploitation confirmed via CVE-2021-44228 log4j vulnerability."}
    )

    eval_result = evaluate_single_brief(target_inc, corrupted_brief)
    assert not eval_result.is_grounded
    assert not eval_result.passed
    assert any("Forbidden terms" in d for d in eval_result.details)
