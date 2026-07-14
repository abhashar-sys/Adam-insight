# 🔍 Adam Insight — Traffic Intelligence Agent

**Automated DDoS Attack Mitigation — Intelligent Network Signal & Insight Generator**

Adam Insight is a **LangGraph-based** traffic analysis micro-service that detects anomalous spikes (peaks) in network traffic data sourced from **ClickHouse** (sFlow telemetry) and **Cassandra** (daily baseline profiles). Given a detection target (IP or CIDR), it produces a full traffic snapshot — peak windows, per-peak decomposition by protocol, port, and scrub center, and delta comparison against a 6-day historical baseline.

The service is deployed as a **Kubernetes workload** with a **FastAPI REST API**, a **Helm chart**, and built via **Skaffold + Docker**.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Repository Structure](#-repository-structure)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Local Development](#-local-development)
- [Configuration](#-configuration)
- [Tech Stack & Dependencies](#-tech-stack--dependencies)
- [Testing](#-testing)
- [Data Model](#-data-model)
- [Peak Detection Algorithm](#-peak-detection-algorithm)
- [Delta Computation](#-delta-computation)

---

## ✨ Features

| Feature | Description |
|---|---|
| **FastAPI REST Service** | `GET /health` and `POST /analyze` endpoints with async request handling via ThreadPoolExecutor |
| **LangGraph State Machine** | Deterministic pipeline with parallel execution, fan-out decomposition, and automatic retry/fallback semantics |
| **Scope-Aware Peak Detection** | Detects peaks independently for overall (all SCs combined) and per scrub center — catches SC-local attacks diluted in aggregate |
| **10-Second Bucket Granularity** | Fine-grained aggregation windows catch micro-bursts; IQR-based dedup prevents fragmented peaks |
| **Baseline Delta Computation** | Compares each peak's composition against a 6-day pooled historical baseline and surfaces % rise/drop per dimension |
| **CIDR Support** | Accepts both single IPs and CIDR notation — uses `isIPAddressInRange()` in ClickHouse queries |
| **Cassandra TLS/SSL** | Automatically negotiates SSL/TLS with Cassandra nodes; graceful plaintext fallback |
| **Scrub Center Mapping** | Resolves SC names to device IPs via `owl_gold.scrubCenterNetworks_dict`; unmapped IPs shown with raw address |
| **Multi-View Decomposition** | Breaks down each peak by: overall totals, scrub center, EtherType, protocol, and destination port |
| **Graceful Degradation** | If Cassandra is unavailable, agent still produces live-only output (peaks without baseline comparison) |
| **Kubernetes-Native** | Helm chart with HPA, PDB, liveness/readiness probes, Cassandra secret mirroring |

---

## 🏗 Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         FastAPI (uvicorn)                                  │
│                      POST /analyze  GET /health                            │
└──────────────────────────────┬─────────────────────────────────────────────┘
                               │  ThreadPoolExecutor (non-blocking)
┌──────────────────────────────▼─────────────────────────────────────────────┐
│                        LangGraph State Machine                             │
│                                                                            │
│   START ─┬──▶ resolve_scrub_centers ──┐                                    │
│          │                            ├──▶ find_peaks ──fan-out──┐         │
│          └──▶ fetch_baseline ─────────┘                          │         │
│                                                                  ▼         │
│                                                    decompose_peak (×N)     │
│                                                          │                 │
│                                                    ──merge──               │
│                                                          │                 │
│                                                    compute_deltas          │
│                                                          │                 │
│                                                    format_output           │
│                                                          │                 │
│                                                         END                │
└────────────────────────────────────────────────────────────────────────────┘
         │                                        │
    ClickHouse                               Cassandra
  owl_bronze.sflowsPostmit            touchstone_ks.daily_profiles
  owl_gold.scrubCenterNetworks_dict
```

### Node Responsibilities

| Node | Role | Reads | Writes |
|---|---|---|---|
| `resolve_scrub_centers` | Map SC names → device IPs via `scrubCenterNetworks_dict` | `scrub_centers` | `device_ips` |
| `fetch_baseline` | Cassandra read of trailing 6-day `daily_profiles` | `detection_target` | `baseline` |
| `find_peaks` | Top-5 BPS and PPS peaks for overall + per-SC | `detection_target`, `device_ips` | `peaks_bps`, `peaks_pps` |
| `decompose_peak` | One ClickHouse query per peak — aggregate by SC, EtherType, protocol, dst_port | single `PeakWindow` | `peak_breakdowns[peak_id]` |
| `compute_deltas` | Compare each breakdown against baseline; produce % rise/drop | `peak_breakdowns`, `baseline` | updated `peak_breakdowns` |
| `format_output` | Assemble `TrafficSnapshot` | everything | `output` |

---

## 📁 Repository Structure

```
adam-insight/
│
├── skaffold.yaml                          # Skaffold build + Helm deploy config (poc profile)
├── pytest.ini                             # Pytest configuration (sets PYTHONPATH=.)
├── README.md
│
├── chart/adam-insight-traffic-intel-agent/   # 🎡 Helm chart
│   ├── Chart.yaml
│   ├── values.yaml                           # Default config, resource limits, Cassandra IPs
│   └── templates/
│       ├── configmap.yaml                    # Env vars + Cassandra secret mirror annotation
│       ├── deployment.yaml                   # Pod spec, probes, secret injection
│       ├── service.yaml                      # ClusterIP service (port 80 → targetPort 8080)
│       ├── hpa.yaml                          # Horizontal Pod Autoscaler
│       ├── pdb.yaml                          # Pod Disruption Budget
│       └── serviceaccount.yaml               # ServiceAccount
│
└── components/adam-insight-traffic-intel-agent/   # 🐍 Python application
    ├── Dockerfile                                  # Multi-stage build (builder + runtime)
    ├── pyproject.toml                              # Package metadata + dependencies
    ├── check_connections.py                        # Local connectivity test script
    └── src/traffic_intel_agent/
        │
        ├── api.py                       # FastAPI app: /health + /analyze endpoints
        │
        ├── config/
        │   └── settings.py              # All env-var driven settings (ClickHouse + Cassandra)
        │
        ├── models/
        │   └── traffic_analysis.py      # Pydantic models: PeakWindow, PeakBreakdown,
        │                                #   PooledBaseline, TrafficSnapshot, TrafficIntelState
        ├── repositories/
        │   ├── clickhouse_repo.py       # ClickHouse query builders (range, curve, breakdown)
        │   └── cassandra_repo.py        # Cassandra 6-day baseline fetcher with SSL/TLS
        │
        ├── services/
        │   ├── traffic_analyzer.py      # PeakDetector (scipy) + PeakDecomposer
        │   ├── baseline_pooler.py       # Pool Cassandra profiles into PooledBaseline
        │   └── delta_calculator.py      # Compute % deltas vs baseline
        │
        └── graph/
            ├── graph.py                 # LangGraph StateGraph definition + compilation
            └── nodes/
                ├── resolve_scrub_centers.py
                ├── fetch_baseline.py
                ├── traffic_analysis.py
                ├── decompose_peak.py
                ├── compute_deltas.py
                └── format_output.py
```

---

## 🌐 API Reference

### `GET /health`
Returns service liveness status.
```bash
curl http://localhost:8099/health
# {"status": "ok"}
```

### `POST /analyze`
Runs the full LangGraph pipeline and returns a `TrafficSnapshot`.

**Request body:**
```json
{
  "target": "198.18.207.38",
  "scrub_centers": []
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | ✅ | IP address or CIDR (e.g. `192.0.2.0/24`) |
| `scrub_centers` | `list[string]` | ❌ | Scrub center names to filter by (empty = all) |

**Interactive Swagger UI:** `http://localhost:8099/docs`

---

## 🚀 Deployment

### Prerequisites
- Docker + Skaffold installed
- `kubectl` configured with context `spock-dart-nss1-8`
- Docker registry credentials secret `spock-registry-creds` in namespace `adam`

### Build & Deploy (Kubernetes)

```bash
cd ~/Adam_insight/Adam-insight
sg docker -c "skaffold run --profile poc"
```

### Monitor Deployment

```bash
# Check pod status
kubectl get pods -n adam -l app.kubernetes.io/name=adam-insight-traffic-intel-agent \
  --context spock-dart-nss1-8

# Stream logs
kubectl logs -n adam -f -l app.kubernetes.io/name=adam-insight-traffic-intel-agent \
  --context spock-dart-nss1-8
```

### Access the API Locally (port-forward)

```bash
# Terminal 1: Start port-forward
kubectl port-forward -n adam svc/adam-insight-traffic-intel-agent 8099:80 \
  --context spock-dart-nss1-8

# Terminal 2: Query the API
curl -s -X POST http://localhost:8099/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "198.18.207.38"}' | python3 -m json.tool
```

---

## 💻 Local Development

```bash
# 1. Go to the component directory
cd components/adam-insight-traffic-intel-agent

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install the package in editable mode
pip install -e .

# 4. Set environment variables
export CLICKHOUSE_HOST=datalake.spock-dart-nss1-8.plx.tn.akamai.com
export CLICKHOUSE_PORT=9440
export CLICKHOUSE_PASSWORD=<your-password>
export CASSANDRA_CONTACT_POINTS=198.18.238.66:9042,...

# 5. Run the API server locally
python -m uvicorn traffic_intel_agent.api:app --host 127.0.0.1 --port 8999 --reload

# 6. Test connectivity (ClickHouse + Cassandra)
python check_connections.py
```

---

## ⚙️ Configuration

All settings are driven by **environment variables** (injected via Helm ConfigMap/Secrets in Kubernetes, or set manually for local dev). See [`settings.py`](components/adam-insight-traffic-intel-agent/src/traffic_intel_agent/config/settings.py).

| Variable | Default | Description |
|---|---|---|
| `CLICKHOUSE_HOST` | `datalake.spock-dart-nss1-8.plx.tn.akamai.com` | ClickHouse server hostname |
| `CLICKHOUSE_PORT` | `9440` | ClickHouse native TCP port (TLS) |
| `CLICKHOUSE_USERNAME` | `ch_read` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | *(from Secret)* | ClickHouse password |
| `CLICKHOUSE_DATABASE` | `owl_bronze` | ClickHouse database |
| `CASSANDRA_CONTACT_POINTS` | *explicit node IPs* | Comma-separated list of `host:port` |
| `CASSANDRA_PORT` | `9042` | Cassandra native port |
| `CASSANDRA_DATACENTER` | `DEV01` | Cassandra datacenter |
| `CASSANDRA_KEYSPACE` | `touchstone_ks` | Cassandra keyspace |
| `CASSANDRA_USERNAME` | *(from mirrored Secret)* | Cassandra username |
| `CASSANDRA_PASSWORD` | *(from mirrored Secret)* | Cassandra password |

### Cassandra Credentials (Secret Mirroring)
Cassandra credentials are automatically injected via the Kubernetes secret mirror mechanism:
```yaml
annotations:
  mirror.secret/dart-system.spock-dart-config.cassandra-creds: "enabled"
```

---

## 🛠 Tech Stack & Dependencies

| Package | Purpose |
|---|---|
| `fastapi` + `uvicorn` | REST API server |
| `langgraph` | LangGraph state machine orchestration |
| `clickhouse-driver` | ClickHouse native TCP client |
| `cassandra-driver` | Cassandra client for baseline profiles |
| `scipy` | `signal.find_peaks` & `peak_widths` for peak detection |
| `numpy` | Numerical array operations |
| `pydantic` ≥ 2.0 | Data validation & typed state models |
| `python-dotenv` | Load `.env` environment variables |

**Runtime:** Python 3.11 (container), Python 3.12 (local dev)

**External Services:**
- **ClickHouse** — `owl_bronze.sflowsPostmit`, `owl_gold.scrubCenterNetworks_dict`
- **Cassandra** — `touchstone_ks.daily_profiles`

---

## ✅ Testing

```bash
# From project root (Adam-insight/)
cd components/adam-insight-traffic-intel-agent
source venv/bin/activate

# Run all unit tests
python -m pytest tests/ -v

# Individual test files
python -m pytest tests/test_peak_detector.py -v
python -m pytest tests/test_delta_calculator.py -v
python -m pytest tests/test_baseline_pooler.py -v
```

---

## 📐 Data Model

### ClickHouse — `owl_bronze.sflowsPostmit`

```
sflowsPostmit
├── Core: time_received_ns, sequence_num, sampling_rate, sampler_address
├── L2:   frame_length, src_mac, dst_mac, ethernet_type
├── L3:   src_addr, dst_addr, protocol, ip_proto_no, ip_ttl, ip_tos
├── L4:   src_port, dst_port, tcp_flags
├── ICMP: icmp_type, icmp_code
├── DNS:  dns_answers, dns_questions
├── Encapsulation: vlan_id, is_fragment
├── BGP:  src_asn, dst_asn
└── Geo:  src/dst_latitude, src/dst_longitude, src/dst_city, src/dst_country
```

### Cassandra — `touchstone_ks.daily_profiles`

```
daily_profiles
├── destination (partition key)
├── data_type: 'border_flow' | 'access_flow'
├── location: '' (overall) | SC name
├── profile_ts: daily timestamp
└── profile_data (JSON):
    ├── bytes, packets
    ├── protocolList: [{bytes, packets, protocol}, ...]
    ├── dpList: [{bytes, packets, dp}, ...]
    └── countryList: [{bytes, packets, country}, ...]
```

---

## 🔬 Peak Detection Algorithm

Uses `scipy.signal.find_peaks` with a **data-derived prominence threshold**:

1. **Bucket**: Aggregate sFlow records into 10-second buckets (BPS and PPS).
2. **Threshold**: Compute the IQR-based Tukey fence (`Q3 + 1.5 × IQR`) as the `prominence` parameter. Falls back to a percentile-based threshold when IQR collapses (flat baseline).
3. **Detection**: `scipy.signal.find_peaks(series, prominence=threshold, distance=12)` — minimum 12-bucket (~2 min) gap between peaks.
4. **Width**: `scipy.signal.peak_widths` at half-prominence defines each peak's `[start_ts, end_ts]` window.
5. **Ranking**: Keep only the top-5 by strength, sorted chronologically.
6. **Scoping**: Run independently for "overall" (all selected SCs) and once per SC.

---

## 📊 Delta Computation

```
Total BPS delta       = (peak_bps      - baseline_bps)      / baseline_bps      × 100
Total PPS delta       = (peak_pps      - baseline_pps)      / baseline_pps      × 100
Per-value share delta = (peak_share[v] - baseline_share[v]) / baseline_share[v] × 100
```

**Edge cases:**
- Value not in baseline → `delta_pct = null`
- Baseline rate = 0 → `delta_pct = null`
- Protocol names → case-normalized (`.lower()`) for join

---

## 📄 License

Internal project — PLX-C2 team.
