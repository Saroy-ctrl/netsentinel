# api/ — online pipeline (M3; brief service M5)

FastAPI service. Endpoints, scoring path, correlator, DB schema: docs/03_architecture.md §4.

```
api/app/
  main.py            app factory, startup bundle load
  routers/           flows.py incidents.py model.py ops.py
  services/          scoring.py correlator.py drift_monitor.py brief.py (M5)
  repo/              sqlite repository
api/tests/
```
`NS_MOCK=1 uvicorn api.app.main:app --reload` serves the contract fixtures (task M3-01).
