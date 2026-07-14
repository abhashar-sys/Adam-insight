"""Application settings — all values read from environment variables.

Set these in your Kubernetes Secret / ConfigMap (via Helm values.yaml).
The defaults here are only for local development; they are overridden at
runtime by the env vars injected by the Helm chart / Skaffold.

Required Kubernetes Secret (create once per cluster):
    kubectl create secret generic traffic-intel-agent-credentials \\
      --from-literal=CLICKHOUSE_USERNAME=<user> \\
      --from-literal=CLICKHOUSE_PASSWORD=<pass> \\
      --from-literal=CASSANDRA_USER=<user> \\
      --from-literal=CASSANDRA_PASSWORD=<pass> \\
      --namespace adam
"""

import os

# ── ClickHouse ────────────────────────────────────────────────────────────────
CLICKHOUSE_HOST     = os.getenv("CLICKHOUSE_HOST",     "datalake.spock-dart-nss1-8.plx.tn.akamai.com")
CLICKHOUSE_PORT     = int(os.getenv("CLICKHOUSE_PORT", "9440"))
CLICKHOUSE_SECURE   = os.getenv("CLICKHOUSE_SECURE",   "true").lower() == "true"
CLICKHOUSE_USERNAME = os.getenv("CLICKHOUSE_USERNAME", "ch_read")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")  # must be set via Secret in production
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "owl_bronze")

# ── Cassandra ─────────────────────────────────────────────────────────────────
# CASSANDRA_CONTACT_POINTS accepts a comma-separated list (e.g. "host1,host2")
_cassandra_cp_raw       = os.getenv("CASSANDRA_CONTACT_POINTS", "127.0.0.1")
CASSANDRA_CONTACT_POINTS: list[str] = [h.strip().split(":")[0] for h in _cassandra_cp_raw.split(",") if h.strip()]
CASSANDRA_PORT          = int(os.getenv("CASSANDRA_PORT",       "9042"))
CASSANDRA_DATACENTER    = os.getenv("CASSANDRA_DATACENTER",     "DEV01")
CASSANDRA_KEYSPACE      = os.getenv("CASSANDRA_KEYSPACE",       "touchstone_ks")
CASSANDRA_USERNAME      = os.getenv("CASSANDRA_USERNAME",       "")
CASSANDRA_PASSWORD      = os.getenv("CASSANDRA_PASSWORD",       "")