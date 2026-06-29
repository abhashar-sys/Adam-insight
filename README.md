# 🔍 Adam Insight

**Automated DDoS Attack Mitigation — Intelligent Network Signal & Insight Generator**

Adam Insight is a **LangGraph-based** traffic analysis agent that detects anomalous spikes (peaks) in network traffic data sourced from **ClickHouse** (sFlow telemetry) and **Cassandra** (daily baseline profiles). Given a detection target (IP or CIDR) and a list of scrub centers, it produces a traffic snapshot that a SOCC engineer can read at a glance: what the target's traffic profile has looked like over the past week, what the largest spikes in the last hour were, and how each spike's composition compares to the historical baseline.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Folder Structure](#-folder-structure)
- [Module Descriptions](#-module-descriptions)
- [Tech Stack & Dependencies](#-tech-stack--dependencies)
- [Setup & Installation](#-setup--installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Testing](#-testing)
- [Data Model](#-data-model)
- [Peak Detection Algorithm](#-peak-detection-algorithm)
- [Delta Computation](#-delta-computation)

---

## ✨ Features

| Feature | Description |
|---|---|
| **LangGraph State Machine** | Deterministic pipeline with parallel execution, fan-out decomposition, and automatic retry/fallback semantics |
| **Scope-Aware Peak Detection** | Detects peaks independently for overall (all SCs combined) and per scrub center — catches SC-local attacks that get diluted in aggregate |
| **10-Second Bucket Granularity** | Fine-grained 10-second aggregation windows catch micro-bursts while IQR-based dedup prevents fragmented peaks |
| **Baseline Delta Computation** | Compares each peak's composition against a 6-day pooled historical baseline and surfaces % rise/drop per dimension |
| **Protocol Name Normalization** | Case-insensitive join between ClickHouse (`TCP`) and Cassandra (`tcp`) protocol names |
| **CIDR Support** | Accepts both single IPs and CIDR notation — uses `isIPAddressInRange()` in ClickHouse queries |
| **Scrub Center Filtering** | All queries filter by resolved device IPs (`sampler_address`) for accurate SC-scoped analysis |
| **Multi-View Decomposition** | Breaks down each peak by: overall totals, scrub center, EtherType, protocol, and destination port |
| **Tukey Fence Threshold** | Data-derived IQR prominence cutoff with percentile fallback for flat baselines |
| **Typed State Classes** | Full Pydantic v2 models for `PeakWindow`, `PeakBreakdown`, `PooledBaseline`, `TrafficSnapshot`, and `TrafficIntelState` |
| **Graceful Degradation** | If Cassandra is unavailable, the agent still produces live-only output (peaks without baseline comparison) |
| **29 Unit Tests** | Comprehensive coverage for peak detection, delta calculation, and baseline pooling |

---

## 🏗 Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        LangGraph State Machine                             │
│                                                                            │
│   START ─┬──▶ resolve_scrub_centers ──┐                                    │
│          │                            ├──▶ find_peaks ──fan-out──┐         │
│          └──▶ fetch_baseline ─────────┘                          │         │
│                                                                  ▼         │
│                                                    decompose_peak (×N)     │
│                                                          │                 │
│                                                    ──merge──              │
│                                                          │                 │
│                                                    compute_deltas          │
│                                                          │                 │
│                                                    format_output           │
│                                                          │                 │
│                                                         END                │
└────────────────────────────────────────────────────────────────────────────┘

Parallel:  resolve_scrub_centers ∥ fetch_baseline
Fan-out:   find_peaks → Send(decompose_peak) × (1+N) × 2 × 5 peaks
Blocking:  compute_deltas waits for all decompose_peak + fetch_baseline
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

## 📁 Folder Structure

```
adam-insight/
│
├── run_traffic_analysis.py          # CLI entry point — invokes the LangGraph agent
├── requirements.txt                 # Python dependencies
├── pytest.ini                       # Pytest configuration (sets PYTHONPATH=.)
├── .env                             # Environment variables (PYTHONPATH=.)
├── .gitignore                       # Git ignore rules
│
├── config/                          # ⚙️  Configuration layer
│   ├── __init__.py
│   ├── settings.py                  # ClickHouse + Cassandra connection settings
│   └── constants.py                 # Peak-detection tuning (10s buckets) & baseline constants
│
├── models/                          # 📦 Pydantic data models & typed state
│   ├── __init__.py                  # Re-exports all model classes
│   └── traffic_analysis.py          # SflowTelemetry, PeakWindow, PeakBreakdown,
│                                    #   PooledBaseline, TrafficSnapshot, TrafficIntelState
│
├── repositories/                    # 🗄️  Data access layer
│   ├── __init__.py
│   ├── clickhouse_repo.py           # ClickHouseRepository — SC-aware query builders,
│   │                                #   CIDR support, 10s buckets, combined CTE queries
│   └── cassandra_repo.py            # CassandraRepository — 6-day baseline profile fetcher
│
├── services/                        # 🔧 Business logic layer
│   ├── __init__.py
│   ├── traffic_analyzer.py          # PeakDetector (scipy) + PeakDecomposer
│   ├── baseline_pooler.py           # Pool raw Cassandra profiles into PooledBaseline
│   ├── delta_calculator.py          # Compare peak breakdowns vs baseline (% deltas)
│   └── customer_context_service.py  # Placeholder — future customer context logic
│
├── graph/                           # 🔀 LangGraph orchestration
│   ├── __init__.py
│   ├── graph.py                     # StateGraph definition & compilation
│   └── nodes/                       # Individual graph nodes
│       ├── __init__.py
│       ├── resolve_scrub_centers.py # SC name → device IP resolution
│       ├── fetch_baseline.py        # Cassandra baseline fetch + pooling
│       ├── traffic_analysis.py      # Scope-aware peak detection (overall + per-SC)
│       ├── decompose_peak.py        # Fan-out peak decomposition
│       ├── compute_deltas.py        # Baseline delta enrichment
│       ├── format_output.py         # Final TrafficSnapshot assembly
│       └── customer_context.py      # Placeholder — future customer context node
│
├── tests/                           # ✅ Unit tests
│   ├── test_peak_detector.py        # 12 tests for PeakDetector (10s buckets, typed output)
│   ├── test_delta_calculator.py     # 8 tests for DeltaCalculator (normalization, edge cases)
│   └── test_baseline_pooler.py      # 9 tests for baseline_pooler (pooling, shares, dedup)
│
├── main.py                          # (Legacy) Original entry point — replaced by run_traffic_analysis.py
├── plot_peaks.py                    # 📊 (Local dev) Matplotlib peak visualisation from CSV
└── test_on_csv.py                   # 📋 (Local dev) CSV-based offline peak analysis
```

---

## 📖 Module Descriptions

### `run_traffic_analysis.py`
The CLI entry point. Invokes the LangGraph `graph.invoke()` with a detection target and scrub centers, then pretty-prints the resulting `TrafficSnapshot`.

```bash
python run_traffic_analysis.py 192.0.2.10 lon,fra
```

### `config/`
| File | Purpose |
|---|---|
| `settings.py` | ClickHouse connection (`host`, `port`, `username`, `password`, `database`) + Cassandra connection (`contact_points`, `port`, `datacenter`, `keyspace`) |
| `constants.py` | `BUCKET_SECONDS` (10), `MIN_GAP_BUCKETS` (12 ≈ 2 min), `TOP_N` (5), `TUKEY_FENCE` (1.5), `FALLBACK_PERCENTILE` (95), `TRAILING_BASELINE_DAYS` (6) |

### `models/traffic_analysis.py`

| Class | Purpose |
|---|---|
| `SflowTelemetry` | Full Pydantic model mapping the `owl_bronze.sflowsPostmit` ClickHouse schema (L2–L4, ICMP, DNS, ESP/GRE, BGP/Geo) |
| `PeakWindow` | A single detected peak: `{peak_id, scope, metric, start_ts, end_ts, total_bps, total_pps}` |
| `BreakdownEntry` | One row in a dimensional breakdown: `{value, bps, pps, share_pct, baseline_share_pct, delta_pct}` |
| `PeakBreakdown` | Full decomposition across SC, EtherType, protocol, dst_port |
| `PooledBaseline` | 6-day pooled baseline rates + per-dimension shares (protocol, port, SC) |
| `TrafficSnapshot` | Final output: baseline + peaks + breakdowns, ready to render |
| `TrafficIntelState` | LangGraph TypedDict state — wires all nodes together |

### `repositories/`

| File | Key Changes from V1 |
|---|---|
| `clickhouse_repo.py` | CIDR support (`isIPAddressInRange`), SC filtering (`sampler_address IN`), combined range+curve CTE, 10-second buckets, new `build_resolve_sc_query`, `build_by_sc_query`, `build_by_ethernet_type_query` |
| `cassandra_repo.py` | Uses `config.settings`, location filtering for SC scoping, returns `profile_ts` |

### `services/`

| File | Purpose |
|---|---|
| `traffic_analyzer.py` | `PeakDetector` (10s buckets, typed `PeakWindow` output, scope-aware `peak_id`s) + `PeakDecomposer` (SC-filtered decomposition) |
| `baseline_pooler.py` | Transforms raw Cassandra `daily_profiles` into a `PooledBaseline` with volume-weighted shares |
| `delta_calculator.py` | Computes total BPS/PPS deltas and per-dimension share deltas with protocol name case-normalization |

### `graph/`

| File | Purpose |
|---|---|
| `graph.py` | LangGraph `StateGraph` with parallel start, `Send` fan-out, merge reducer for `peak_breakdowns`, and sequential finish |
| `nodes/resolve_scrub_centers.py` | Reverse-maps SC names → device IPs via `scrubCenterNetworks_dict` |
| `nodes/fetch_baseline.py` | Fetches + pools Cassandra baseline; returns `None` on failure |
| `nodes/traffic_analysis.py` | Runs peak detection for overall + each SC |
| `nodes/decompose_peak.py` | Fan-out: decomposes one peak into 5 dimensional views |
| `nodes/compute_deltas.py` | Enriches breakdowns with baseline deltas |
| `nodes/format_output.py` | Assembles `TrafficSnapshot` |

---

## 🛠 Tech Stack & Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cassandra-driver` | ≥ 3.29 | Cassandra client for baseline profiles |
| `clickhouse-connect` | 1.2.0 | ClickHouse HTTP client |
| `langgraph` | ≥ 0.2 | State machine orchestration with parallel/fan-out |
| `matplotlib` | 3.11.0 | Traffic curve & peak visualisation (local dev) |
| `numpy` | 2.4.6 | Numerical array operations |
| `pydantic` | ≥ 2.0 | Data validation & typed state models |
| `python-dotenv` | 1.2.2 | Load `.env` environment variables |
| `scipy` | 1.17.1 | `signal.find_peaks` & `peak_widths` |

**Runtime:** Python 3.10+

**External Services:**
- **ClickHouse** — sFlow telemetry (`owl_bronze.sflowsPostmit`, `owl_gold.scrubCenterNetworks_dict`)
- **Cassandra** — Daily baseline profiles (`touchstone_ks.daily_profiles`)

---

## 🚀 Setup & Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd adam-insight

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure connections
#    Edit config/settings.py with your ClickHouse + Cassandra connection details

# 5. Set PYTHONPATH (already in .env, but for manual runs)
export PYTHONPATH=.
```

---

## ⚙️ Configuration

### ClickHouse Connection (`config/settings.py`)

```python
CLICKHOUSE_HOST     = 'localhost'
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_USERNAME = 'default'
CLICKHOUSE_PASSWORD = ''
CLICKHOUSE_DATABASE = 'owl_bronze'
```

### Cassandra Connection (`config/settings.py`)

```python
CASSANDRA_CONTACT_POINTS = ['198.18.238.66', '198.18.238.67', '198.18.238.68', '198.18.238.69']
CASSANDRA_PORT       = 9042
CASSANDRA_DATACENTER = 'DEV01'
CASSANDRA_KEYSPACE   = 'touchstone_ks'
```

### Peak Detection Tuning (`config/constants.py`)

| Constant | Default | Description |
|---|---|---|
| `BUCKET_SECONDS` | `10` | Aggregation bucket size (seconds) |
| `MIN_GAP_BUCKETS` | `12` | Min distance between peaks (~2 min at 10s buckets) |
| `TOP_N` | `5` | Max peaks returned per scope per metric |
| `TUKEY_FENCE` | `1.5` | IQR multiplier for Tukey fence (Q3 + k×IQR) |
| `FALLBACK_PERCENTILE` | `95` | Percentile fallback when IQR = 0 |
| `TRAILING_BASELINE_DAYS` | `6` | Days of Cassandra baseline to pool |

---

## 🎯 Usage

### Run the Agent

```bash
# Analyse a single IP with specific scrub centers
python run_traffic_analysis.py 192.0.2.10 lon,fra

# Analyse a CIDR
python run_traffic_analysis.py 192.0.2.0/24 lon,fra

# Analyse with all scrub centers (no filter)
python run_traffic_analysis.py 192.0.2.10
```

### CSV Offline Analysis (no database needed)

```bash
python test_on_csv.py /path/to/csv/exports
```

### Generate Peak Visualisation Plots

```bash
python plot_peaks.py
```

---

## ✅ Testing

```bash
# Run all tests
pytest -v

# Run specific test suites
pytest tests/test_peak_detector.py -v       # 12 tests
pytest tests/test_delta_calculator.py -v    # 8 tests
pytest tests/test_baseline_pooler.py -v     # 9 tests
```

**All 29 tests pass.** Tests cover peak detection (10s buckets, typed output, IQR thresholding), delta computation (case normalization, edge cases), and baseline pooling (dedup, shares).

---

## 📐 Data Model

### ClickHouse — `owl_bronze.sflowsPostmit`

```
sflowsPostmit
├── Core: time_received_ns, sequence_num, sampling_rate, sampler_address
├── L2:   frame_length, src_mac, dst_mac, ethernet_type
├── L3:   src_addr, dst_addr, protocol, ip_proto_no, ip_ttl, ip_tos
├── L4:   src_port, dst_port, tcp_flags, tcp_seq_no, udp_header_len
├── ICMP: icmp_type, icmp_code, icmp_type_code_name
├── DNS:  dns_answers, dns_questions, dns_authorities, dns_additionals
├── ESP:  esp_seq, esp_spi
├── GRE:  gre_version, gre_protocol, gre_key, gre_seq_no
├── Encapsulation: layer_stack, layer_size, vlan_id, is_fragment
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
    ├── sipList, spList, flgList, frgList, ...
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
- Value not in baseline → rendered as "new (not in baseline)"
- Value not in peak → delta = -100%
- Baseline rate = 0 → delta = None
- Protocol names → case-normalized (`.lower()`) for join

---

## 📄 License

Internal project — PLX-C2 team.
