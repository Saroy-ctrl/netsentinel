# M5-07: Own-Lab Capture & Replay Workflow (Stretch Goal)

This document specifies the architecture, safety constraints, and end-to-end execution pipeline for **Task M5-07 (Own-lab capture)**: capturing live network traffic in a dedicated two-VM testbed, extracting bidirectional statistical flow features offline using the fixed CICFlowMeter, normalizing the resulting CSV to NetSentinel's contract schema, and streaming the traffic through `replay/replay.py`.

---

## 1. Context & Objectives

As defined in [`docs/04_tasks.md`](04_tasks.md) and architectural validation [`docs/02_doc_validation.md`](02_doc_validation.md) (§A5, §B6):
* NetSentinel is a **flow-level telemetry system**, not an inline deep packet inspection (DPI) tap. The API consumes pre-extracted statistical flow records (`FlowRecord`) rather than raw network packets.
* The standard demo storyline (Acts 1–5, detailed in [`docs/demo_script.md`](demo_script.md)) replays held-out slices of benchmark datasets (`CSE-CIC-IDS2018` and `LUFlow`) stored in `replay/samples/`.
* **M5-07** serves as an operational proof-of-concept demonstrating that NetSentinel can ingest, score, correlate, and brief **new traffic captured outside the original training benchmarks**, validating the end-to-end telemetry bridge:
  $$\text{Raw Packets (PCAP)} \xrightarrow[\text{fixed CICFlowMeter}]{\text{Offline}} \text{Flow CSV} \xrightarrow[\text{Adapter}]{\text{Format}} \text{Replay CSV} \xrightarrow[\text{replay.py}]{\text{Streaming}} \text{POST /v1/flows}$$

> [!IMPORTANT]
> **State Distinction:**
> * **Repository-Prepared State (READY):** Replay engine (`replay/replay.py`), scenario parser, schema contracts (`FlowRecord`, `FlowMeta`, `FlowBatch`), feature specification (`nscore/contracts/feature_spec.json`), risk scoring policy (`policy.SEVERITY[AttackFamily.PORTSCAN] = 0.30`), and ingestion endpoints are fully implemented and verified by automated tests.
> * **Local Lab Execution State (PENDING LOCAL RUN):** Hypervisor provisioning, virtual machine creation, live packet capture (`tcpdump`), and nmap scanning require a local multi-VM environment. In accordance with repository policies, binary PCAP captures, VM disk images, and live ephemeral datasets are **never** committed to version control.

---

## 2. Safety & Legality Boundaries

Active network reconnaissance must be performed under strict legal and physical safeguards. Deviating from these boundaries is dangerous and prohibited.

### 2.1 Legal Compliance
* **Authorization Boundary:** Port scanning and packet interception on networks or hosts without explicit, prior authorization violate the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), the UK Computer Misuse Act 1990 (§ 1–3), and international computer crime statutes.
* **Scope Guarantee:** Scanning and capture operations must **target only virtual machines owned and operated by the tester** within an isolated private network.

### 2.2 Network Isolation Requirements
* **Dedicated Host-Only Network:** Both virtual machines must be attached exclusively to an isolated **Host-Only virtual switch** (e.g., VirtualBox `Host-Only Adapter` / `vboxnet0`, or VMware `vmnet1`).
* **Zero External Egress:** The host-only virtual switch must **not** be bridged to physical network adapters (Ethernet/Wi-Fi) and must **not** route traffic through a Network Address Translation (NAT) interface or default gateway during capture. This guarantees that probe packets cannot leak into the local LAN or the public internet.
* **Strict Target IP Binding:** All commands must explicitly specify the designated target VM IP (e.g., `192.168.56.101`). Never scan the host machine gateway (`192.168.56.1`), broadcast addresses (`192.168.56.255`), subnet CIDRs (`/24`), or `localhost` / `127.0.0.1`.

### 2.3 Rate Limiting & System Stability
* **Slow Timing Template:** Scans must utilize deliberate rate limiting (`nmap -T2` or `-T3`) with bounded port ranges (e.g., `-p 1-1000` or explicit service ports `-p 22,80,443,8080`) to prevent socket exhaustion, hypervisor instability, or unintended kernel crashes.

---

## 3. Prerequisites & Lab Topology

```
+---------------------------------------------------------------------------------+
|                       Isolated Host-Only Virtual Switch                        |
|                             Subnet: 192.168.56.0/24                             |
|                           [No External Gateway / NAT]                           |
+---------------------------------------------------------------------------------+
          |                                                               |
          | (eth1: 192.168.56.102)                        (eth1: 192.168.56.101)  |
          v                                                               v
+----------------------------+                          +----------------------------+
|        Scanner VM          |                          |         Target VM          |
|    (Attacker / Probe)      |                          |     (Victim / Server)      |
|----------------------------|                          |----------------------------|
| - OS: Kali Linux or Ubuntu |   Slow Nmap SYN Scan     | - OS: Ubuntu Server 22.04  |
| - IP: 192.168.56.102       | -----------------------> | - IP: 192.168.56.101       |
| - Tool: nmap, tcpdump      |   -sS -p 1-1000 -T2      | - Services: OpenSSH (22),  |
|                            |                          |             Nginx/HTTP (80)|
|                            |                          | - Tool: tcpdump (listener) |
+----------------------------+                          +----------------------------+
```

### 3.1 Environment Specification
1. **Hypervisor:** VirtualBox 7.x, VMware Workstation 17+, or KVM/QEMU.
2. **Target VM (Victim):**
   * **OS:** Minimal Ubuntu Server 22.04 LTS or Debian 12.
   * **IP Address:** `192.168.56.101` (static or host-only DHCP).
   * **Active Services:** OpenSSH (`port 22`), Nginx / Apache (`port 80`) to ensure both open and closed port responses for realistic bidirectional flow generation.
3. **Scanner VM (Attacker):**
   * **OS:** Kali Linux, Ubuntu, or Debian.
   * **IP Address:** `192.168.56.102`.
   * **Required Utilities:** `nmap` (>= 7.80), `tcpdump` (>= 4.9).
4. **Feature Extraction Environment:**
   * **Java Runtime:** JRE 8+ (`default-jre` or OpenJDK 11).
   * **Extractor Tool:** **Fixed CICFlowMeter** (Liu, Engelen et al., IEEE CNS 2022 release).
   * **Download Source:** `https://intrusion-detection.distrinet-research.be/CNS2022/`.
   * **Why Fixed Version:** As established in [`docs/01_problem_analysis.md`](01_problem_analysis.md) and [`docs/pitch_qa.md`](pitch_qa.md), the original 2017 CICFlowMeter contains severe implementation bugs (inverted flow directions, corrupted TCP header lengths, and omitted IP addresses). The Liu & Engelen (CNS 2022) fixed extractor resolves these defects and exports full 91-column CSVs containing valid source and destination IP metadata.

---

## 4. Execution Workflow

### Phase 1: Packet Capture in Isolated Lab

1. **Verify Interface Configuration on Both VMs:**
   ```bash
   # On Scanner VM: verify IP is on the host-only subnet
   ip -4 addr show eth1
   # Expected: inet 192.168.56.102/24

   # On Target VM: verify IP
   ip -4 addr show eth1
   # Expected: inet 192.168.56.101/24
   ```

2. **Start Network Packet Capture on Target VM:**
   Run `tcpdump` bound specifically to the host-only interface, filtering only traffic between the two lab endpoints to eliminate background multicast or ARP noise:
   ```bash
   sudo tcpdump -i eth1 -nn -s 0 -w lab_nmap_scan.pcap "host 192.168.56.101 and host 192.168.56.102"
   ```

3. **Execute Controlled Nmap Scan on Scanner VM:**
   Execute a slow TCP SYN scan across the first 1,000 ports:
   ```bash
   nmap -sS -p 1-1000 -T2 -v 192.168.56.101
   ```
   *Alternative Service Discovery Scan:*
   ```bash
   nmap -sV -p 21,22,80,443,8080 -T3 192.168.56.101
   ```

4. **Stop Capture and Inspect PCAP:**
   Once the scan reports complete in nmap, stop `tcpdump` (`Ctrl+C`). Verify the capture file integrity:
   ```bash
   tcpdump -r lab_nmap_scan.pcap -c 10
   ```

---

### Phase 2: Feature Extraction (Fixed CICFlowMeter)

1. **Transfer PCAP to Extraction Workspace:**
   Copy `lab_nmap_scan.pcap` to the machine hosting the fixed CICFlowMeter installation.
2. **Execute Fixed CICFlowMeter:**
   ```bash
   # Using the fixed CICFlowMeter CLI runner
   ./cfm lab_nmap_scan.pcap ./output/
   ```
   *Or directly invoking the Java JAR:*
   ```bash
   java -Djava.library.path=./jnetpcap/linux/jnetpcap-1.4.r1425 -jar CICFlowMeter.jar lab_nmap_scan.pcap ./output/
   ```
3. **Verify Generated CSV:**
   The tool outputs a raw flow CSV (e.g. `output/lab_nmap_scan_ISCX.csv`). Inspect column headers:
   ```bash
   head -n 2 output/lab_nmap_scan_ISCX.csv
   ```
   Confirm presence of `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`, and raw statistical flow metrics (`Flow Duration`, `Total Fwd Packet`, `Total Bwd packets`, etc.).

---

### Phase 3: Schema Normalization to NetSentinel Replay CSV

NetSentinel's `replay/replay.py` expects a CSV formatted identically to the files in `replay/samples/`:
1. **Metadata Columns:** `flow_id`, `observed_at` (UTC ISO), `t_rel_s` (elapsed seconds), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `ground_truth`, `tool`.
2. **Canonical Features:** Exactly the 46 features defined in `nscore/contracts/feature_spec.json` (snake_case names, `float32`).
3. **Imputation:** Any non-finite values (`NaN`, `Inf`) replaced with `train_median` from `feature_spec.json`.

Use the following Python normalization script (referencing the repository's feature specification):

```python
"""Convert raw fixed-CICFlowMeter CSV to NetSentinel replay CSV."""

import json
from pathlib import Path
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "nscore" / "contracts" / "feature_spec.json"

spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
feature_names = [f["name"] for f in spec["features"]]
raw_to_snake = {f["raw_name"]: f["name"] for f in spec["features"]}
medians = {f["name"]: f["train_median"] for f in spec["features"]}

# Read raw CICFlowMeter CSV
raw_csv_path = Path("output/lab_nmap_scan_ISCX.csv")
df_raw = pd.read_csv(raw_csv_path)

# Normalize column names
df_raw = df_raw.rename(columns=raw_to_snake)

# Ensure required timestamp and metadata columns exist
ts_series = pd.to_datetime(df_raw["Timestamp"], errors="coerce")
ts_min = ts_series.min()

df_out = pd.DataFrame()
df_out["flow_id"] = [f"lab-flow-{i:05d}" for i in range(len(df_raw))]
df_out["observed_at"] = ts_series.dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
df_out["t_rel_s"] = ((ts_series - ts_min).dt.total_seconds()).round(6)
df_out["src_ip"] = df_raw["Src IP"].astype(str)
df_out["src_port"] = df_raw["Src Port"].fillna(0).astype(int).clip(lower=0)
df_out["dst_ip"] = df_raw["Dst IP"].astype(str)
df_out["dst_port"] = df_raw["Dst Port"].fillna(0).astype(int).clip(lower=0)
df_out["protocol"] = df_raw["Protocol"].fillna(6).astype(int)
df_out["ground_truth"] = "PortScan"
df_out["tool"] = "Nmap"

# Extract and clean canonical 46 features
for feat in feature_names:
    if feat == "protocol":
        continue
    if feat in df_raw.columns:
        col_vals = df_raw[feat].astype("float64")
        mask_nonfinite = ~np.isfinite(col_vals)
        col_vals[mask_nonfinite] = medians[feat]
        df_out[feat] = col_vals.astype("float32")
    else:
        df_out[feat] = np.float32(medians[feat])

output_replay_path = REPO_ROOT / "replay" / "samples" / "lab_nmap_scan.csv"
df_out.to_csv(output_replay_path, index=False)
print(f"Normalized {len(df_out)} flows written to {output_replay_path}")
```

---

### Phase 4: Replay Execution via `replay/replay.py`

Once `lab_nmap_scan.csv` is generated, it is streamed through the replay engine against a live API instance. (`--mock` only produces SIMULATED output copied from the labels; never use it for results.)

#### Live API Streaming
1. Start the NetSentinel API:
   ```bash
   uvicorn api.app.main:app --host 127.0.0.1 --port 8000
   ```
2. Stream flows through the replay CLI:
   ```bash
   python replay/replay.py --file replay/samples/lab_nmap_scan.csv --speed 1.0 --bundle cic-v1 --api-url http://127.0.0.1:8000   # NS_API_KEY / NS_ADMIN_KEY from the environment
   ```

#### Declarative Scenario Definition
Optionally define a scenario YAML file `replay/scenarios/lab_nmap_scan.yaml`:
```yaml
name: lab_nmap_scan
description: Own-lab host-only VM Nmap port scan (M5-07 stretch)
file: lab_nmap_scan.csv
bundle: cic-v1
speed: 1.0
batch_size: 250
```
Then execute:
```bash
python replay/replay.py --scenario lab_nmap_scan
```

---

## 5. Expected System Behavior & Risk Scoring Pipeline

When the lab Nmap port scan flows enter NetSentinel, the pipeline responds deterministically according to the threat model ([`docs/threat_model.md`](threat_model.md)) and scoring contracts ([`nscore/contracts/policy.py`](../nscore/contracts/policy.py)):

### 5.1 Telemetry Classification & Anomaly Detection
* **Random Forest Multiclass:** Identifies high-velocity connection attempts with short flow duration, asymmetric packet counts, and elevated SYN flag counts, categorizing the traffic as `AttackFamily.PORTSCAN` with high confidence ($p_{\text{attack}} \approx 0.95$).
* **Alternative Internal Classification:** If scored against bundles trained exclusively on lateral movement scenarios, internal port reconnaissance aligns with `AttackFamily.INFILTRATION` ($W=1.00$, MITRE T1046).

### 5.2 Risk Engine Calculation
Under the perimeter reconnaissance classification:
* **Severity Weight:** $W[\text{PORTSCAN}] = 0.30$ (low severity, reconnaissance only).
* **Burst Factor:** For a bounded scan of 1,000 flows:
  $$\text{burst} = 1 + 0.15 \times \min\left(1.0, \frac{\log_{10}(1000)}{3}\right) = 1 + 0.15 \times 1.0 = 1.15$$
* **Risk Score:**
  $$\text{Score} = \text{round}(100 \times (0.95 \times 0.30 \times 1.15)) = \text{round}(32.77) = \mathbf{33} \quad (\mathbf{LOW})$$
  *(For a single probe flow without burst factor, score is $\mathbf{28}$ LOW).*

> [!TIP]
> **Alert Fatigue Protection in Practice:**
> Even though the machine learning model is 95% certain that an attack is occurring, NetSentinel's dual-factor risk engine prevents alert storming. Because perimeter reconnaissance causes no direct system compromise, the incident is appropriately triaged as **LOW (Score: 33)**, preventing the SOC queue from being overwhelmed.

### 5.3 SOC Playbook & Incident Brief
The brief service (`api/app/services/brief.py`) generates a grounded summary with high-confidence band hedging:
* **Source:** `azure_openai` (or deterministic `template` fallback).
* **Recommended Next Step Playbook Action:**
  > *"Add offending external IP to perimeter edge monitoring watchlists or firewall temporary drop rules if volume exceeds reconnaissance thresholds."*

---

## 6. Preparation & Status Checklist

| Pipeline Stage | Component / Artifact | Status | Execution Context |
|---|---|:---:|---|
| **Contract Schemas** | `FlowRecord`, `FlowMeta`, `FlowBatch` | ✅ Complete | Repository (`nscore/contracts/schemas.py`) |
| **Feature Specification** | Canonical 46-feature schema & medians | ✅ Complete | Repository (`nscore/contracts/feature_spec.json`) |
| **Replay Engine** | Pacing, batching, mock scoring, API client | ✅ Complete | Repository (`replay/replay.py`) |
| **Risk Scoring Policy** | PortScan severity ($0.30$), burst factor | ✅ Complete | Repository (`nscore/contracts/policy.py`) |
| **SOC Playbook Line** | PortScan edge watchlist drop rule | ✅ Complete | Repository (`docs/threat_model.md`, `brief.py`) |
| **Lab VM Topology** | 2 VMs on isolated host-only network | ⏳ Pending Local Run | User's local hypervisor (VirtualBox / VMware) |
| **Live Packet Capture** | `tcpdump -w lab_nmap_scan.pcap` | ⏳ Pending Local Run | Local Target/Scanner VM console |
| **Feature Extraction** | Fixed CICFlowMeter -> raw CSV | ⏳ Pending Local Run | Local Java JRE 8+ environment |
| **Data Artifacts** | PCAP binaries, disk images, generated CSVs | 🔒 Excluded | Excluded from git via `.gitignore` |
