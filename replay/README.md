# replay/ — demo traffic (M5)

`replay.py` streams flow CSVs into `POST /v1/flows` at a set pace. `scenarios/*.yaml` describe demo acts
(benign background + bursts). PCAP → flow CSV is an **offline** CICFlowMeter step (use the fixed CICFlowMeter
from Engelen et al.).

Safety: only capture traffic from machines we own (host-only VM network). Never scan anything else.
