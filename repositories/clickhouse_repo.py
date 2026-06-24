# pyrefly: ignore [missing-import]
import clickhouse_connect

from config.settings import (
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USERNAME,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_DATABASE,
)


class ClickHouseRepository:
    """Encapsulates all ClickHouse data access: client management and query building."""

    def __init__(self):
        self.client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USERNAME,
            password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DATABASE,
        )

    def query(self, sql):
        """Execute a raw SQL query and return the result."""
        return self.client.query(sql)

    def query_as_dicts(self, sql):
        """Execute a query and return results as a list of dicts."""
        res = self.client.query(sql)
        cols = res.column_names
        return [dict(zip(cols, row)) for row in res.result_rows]

    # ── Query Builders ───────────────────────────────────────────────

    @staticmethod
    def build_curve_query(targetip, start_ns, end_ns):
        """Per-minute bps/pps over [start_ns, end_ns], gaps zero-filled. Filters on raw ns."""
        return f"""SELECT
    toStartOfMinute(toDateTime(intDiv(time_received_ns, 1000000000))) AS minute,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 60 AS total_bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 60 AS total_pps
FROM owl_bronze.sflowsPostmit
WHERE dst_addr = '{targetip}'
    AND time_received_ns >= {start_ns}
    AND time_received_ns <  {end_ns}
GROUP BY minute
ORDER BY minute WITH FILL
    FROM toStartOfMinute(toDateTime(intDiv({start_ns}, 1000000000)))
    TO   toStartOfMinute(toDateTime(intDiv({end_ns}, 1000000000)))
    STEP toIntervalMinute(1)"""

    @staticmethod
    def build_breakdown_query(target_ip, start_ns, end_ns):
        """Decompose one peak window by scrub center + L2/L3/L4 layers."""
        return f"""SELECT
    dictGet('owl_gold.scrubCenterNetworks_dict', 'sc', toIPv4(sampler_address)) AS scrub_center,
    ethernet_type,
    protocol,
    dst_port,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 60 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 60 AS pps
FROM owl_bronze.sflowsPostmit
WHERE dst_addr = '{target_ip}'
    AND time_received_ns >= {start_ns}
    AND time_received_ns <  {end_ns}
GROUP BY scrub_center, ethernet_type, protocol, dst_port
ORDER BY bps DESC"""

    @staticmethod
    def build_overall_query(target_ip, start_ns, end_ns):
        """Total bps/pps for the peak window — no grouping."""
        return f"""SELECT
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 60 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 60 AS pps
FROM owl_bronze.sflowsPostmit
WHERE dst_addr = '{target_ip}'
    AND time_received_ns >= {start_ns}
    AND time_received_ns <  {end_ns}"""

    @staticmethod
    def build_by_protocol_query(target_ip, start_ns, end_ns):
        """Bps/pps grouped by protocol for the peak window."""
        return f"""SELECT
    protocol,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 60 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 60 AS pps
FROM owl_bronze.sflowsPostmit
WHERE dst_addr = '{target_ip}'
    AND time_received_ns >= {start_ns}
    AND time_received_ns <  {end_ns}
GROUP BY protocol
ORDER BY bps DESC"""

    @staticmethod
    def build_by_port_query(target_ip, start_ns, end_ns, top_n=10):
        """Bps/pps grouped by destination port for the peak window."""
        return f"""SELECT
    dst_port,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 60 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 60 AS pps
FROM owl_bronze.sflowsPostmit
WHERE dst_addr = '{target_ip}'
    AND time_received_ns >= {start_ns}
    AND time_received_ns <  {end_ns}
GROUP BY dst_port
ORDER BY bps DESC
LIMIT {top_n}"""


# Module-level singleton for convenience
clickhouse_repo = ClickHouseRepository()
