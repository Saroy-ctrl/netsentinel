# replay/ — demo traffic (M5)

`replay.py` streams flow CSVs into `POST /v1/flows` at a set pace. `scenarios/*.yaml` describe demo acts
(benign background + bursts). Each scenario names the bundle it needs: 2018 scenarios (brute force, DDoS-HOIC,
botnet vs the holdout bundle) use the CIC schema; LUFlow scenarios (later-month real traffic) need the LUFlow
bundle loaded via `POST /v1/admin/reload-model`. The API rejects flows that don't match the loaded schema. PCAP → flow CSV is an **offline** CICFlowMeter step (use the fixed CICFlowMeter
from Engelen et al.).

Safety: only capture traffic from machines we own (host-only VM network). Never scan anything else.
