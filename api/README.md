# api/ - online pipeline (M3; brief service M5)

FastAPI service. Endpoints, scoring path, correlator, DB schema: docs/03_architecture.md §4.

```
api/app/
  main.py            app, startup bundle load (MODEL_REF), auth, all endpoints
  scoring.py         FlowBatch -> DetectionEngine -> SHAP (capped) -> persist -> correlate
  correlator.py      (src_ip, dst_ip, family) incidents, 5-minute window, risk recompute
  repository.py db.py fixtures.py
  services/          drift.py (PSI window + snapshots), brief.py (stub; M5-03 replaces it with Azure OpenAI)
api/tests/           conftest.py isolates the environment for every test; helpers.py has auth headers and a valid flow batch
```

## Run
```bash
python scripts/make_mock_bundle.py && python scripts/init_db.py          # mock bundle + empty database
NS_API_KEY=k NS_ADMIN_KEY=a MODEL_REF=local:artifacts/bundles/mock-cic uvicorn api.app.main:app --reload
```
`NS_MOCK=1` serves the contract fixtures when no bundle is loaded. With a real bundle (`MODEL_REF=local:artifacts/bundles/cic-v1`) the
API scores for real. See `.env.example` for every variable.

## Auth and headers
| Endpoint | Header |
|---|---|
| `POST /v1/flows` | `X-API-Key` (always enforced, mock mode included) |
| `POST /v1/incidents/{id}/actions` | `X-Analyst: Name + Role` (e.g. `Alice + Tier 2`); a bare name is rejected with 422 |
| `POST /v1/admin/reload-model` | `X-Admin-Key` |

## Performance note (found against the real M2 bundles)
Exact TreeSHAP costs 10-100 ms per flow. Only the `NS_SHAP_MAX_PER_BATCH` most suspicious flows of a batch (default 25) get
`top_features`; all flows are still scored, persisted and correlated, and an incident's SHAP mean is taken over its explained flows only.
Scoring 1,000 attack flows with `cic-v1` takes about 0.4 s.
