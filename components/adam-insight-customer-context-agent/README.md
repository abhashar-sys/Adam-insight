# ADAM-Insight: Customer Context Agent

An asynchronous, graph-driven microservice that intercepts inbound security alerts, aggregates localized customer intelligence metrics, and dynamically compiles structured "Customer Intelligence Cards" to securely ground downstream LLM analysis.

This service acts as a crucial decision-support guardrail, verifying network telemetry and defensive boundaries before any mitigations are evaluated.

---

## 🚀 Core Features & High-Pressure Logic

* **Asynchronous Graph Orchestration:** Built on LangGraph and FastAPI, the service coordinates a parallel, non-blocking fan-out execution structure across the Customer and Xiphos APIs, resolving data dependencies sequentially before querying historical metrics from Chakra-RS.
* **Resilient Network Normalization:** If an inbound alert contains a raw target IP missing a subnet mask, the agent automatically normalizes the data, defaulting safely to a `/32` subnet for IPv4 or `/128` for IPv6.
* **Longest Prefix Match (LPM) Algorithm:** Avoids shallow, error-prone string matching on network fields. The agent parses true CIDR blocks mathematically using the Python `ipaddress` library to precisely map a target IP to its exact corporate infrastructure owner.

---

## 📂 Layout and Packaging Architecture

This component follows modern PEP 517 and PEP 621 Python packaging standards utilizing a `src/` layout configuration driven by `pyproject.toml`.

```text
components/adam-insight-customer-context-agent/
├── pyproject.toml         # Package metadata, runtime & dev dependencies
├── Dockerfile             # Multi-stage optimized production image
├─- README.md              # Documentation
|-- docs/
    |-- openapi.yaml
├── src/
│   └── customer_context/  # Main importable package namespace
│       ├── __init__.py
│       ├── app.py         # FastAPI entryway and HTTP facade
│       ├── graph.py       # LangGraph state workflow management
│       ├── models/        # Pydantic data contract validations
│       ├── nodes/         # Workflow logical execution steps
│       ├── services/      # Asynchronous backend API clients
│       └── tools/         # Core network utility computations (CIDR/LPM)
└── tests/                 # Isolated test suites