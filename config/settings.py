# ── ClickHouse ────────────────────────────────────────────────────
CLICKHOUSE_HOST     = 'localhost'
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_USERNAME = 'default'
CLICKHOUSE_PASSWORD = ''
CLICKHOUSE_DATABASE = 'owl_bronze'

# ── Cassandra ─────────────────────────────────────────────────────
CASSANDRA_CONTACT_POINTS = [
    '127.0.0.1',
]
CASSANDRA_PORT       = 9042
CASSANDRA_DATACENTER = 'DEV01'
CASSANDRA_KEYSPACE   = 'touchstone_ks'