import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from nscore.contracts.schemas import Brief


async def _mock_llm_generation(incident_id: str, incident_data: dict[str, Any]) -> str:
    # Simulate LLM delay. We use a mock LLM logic here.
    if incident_data.get("_test_timeout"):
        await asyncio.sleep(10.0)
    else:
        await asyncio.sleep(0.1)

    text = f"LLM generated brief for incident {incident_id}."
    
    return text

async def generate_and_cache_brief(
    incident_id: str,
    incident_data: dict[str, Any],
    repo,
    refresh: bool = False,
    timeout: float = 8.0
) -> Brief:
    if not refresh and incident_data.get("brief_json"):
        return Brief.model_validate(json.loads(incident_data["brief_json"]))

    try:
        text = await asyncio.wait_for(_mock_llm_generation(incident_id, incident_data), timeout=timeout)
        
        # Enforce strict wording constraints post-generation as required
        if incident_data.get("attack_family") == "novel_anomaly" or incident_data.get("verdict") == "anomaly":
            if "novel_anomaly" not in text:
                text += " This incident exhibits a novel_anomaly."
        if incident_data.get("attack_family") == "Malicious" or incident_data.get("verdict") == "Malicious":
            if "Malicious" not in text:
                text += " The behavior is classified as Malicious."

        source = "llm"
        confidence_band = "high"
    except TimeoutError:
        text = (
            f"Fallback deterministic template brief for incident {incident_id}. "
            f"Risk level is {incident_data.get('risk_level', 'UNKNOWN')}."
        )
        source = "template"
        confidence_band = "low"

    brief = Brief(
        incident_id=incident_id,
        text=text,
        source=source,
        confidence_band=confidence_band,
        generated_at=datetime.now(UTC)
    )

    brief_json = brief.model_dump_json()
    repo.update_incident_brief(incident_id, brief_json)
    
    return brief
