"""Shared test helpers for the API tests."""

# Real (non-mock) requests must authenticate: ingest needs the API key, admin routes the admin key,
# analyst actions an `X-Analyst: Name + Role` header. The defaults match api.app.main when no env var is set.
AUTH_HEADERS = {"x-api-key": "test_api_key", "x-admin-key": "admin_secret"}


def one_flow_batch(flow_id: str = "f-1") -> dict:
    """A minimal, contract-valid FlowBatch (FlowBatch requires >= 1 flow; real scoring needs the bundle's features)."""
    return {"flows": [{
        "meta": {"flow_id": flow_id, "observed_at": "2026-10-04T12:00:00Z", "src_ip": "10.0.0.1",
                 "dst_ip": "192.168.1.100", "src_port": 12345, "dst_port": 80, "protocol": 6},
        "features": {"flow_duration": 10.0},
    }]}
