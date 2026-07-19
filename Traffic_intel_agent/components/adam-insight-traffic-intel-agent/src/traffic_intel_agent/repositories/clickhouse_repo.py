"""ClickHouse data access — query builders & executor.

All query builders accept an optional ``device_ips`` parameter for
scrub-center filtering, and the target filter supports both single IPs
and CIDR notation (via ``isIPAddressInRange``).
"""

import ipaddress
import logging

# pyrefly: ignore [missing-import]
import clickhouse_connect

from traffic_intel_agent.config.settings import (
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USERNAME,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_DATABASE,
)

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────

def build_target_filter(target: str) -> str:
    """Return the WHERE clause fragment for the detection target.

    - Single IP  → ``dst_addr = '1.2.3.4'``
    - CIDR       → ``isIPAddressInRange(dst_addr, '1.2.3.0/24')``
    """
    try:
        # Will succeed for bare IPs (no prefix) — treat as exact match
        ipaddress.ip_address(target)
        return f"dst_addr = '{target}'"
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return f"isIPAddressInRange(dst_addr, '{target}')"
    except ValueError:
        # Fallback: treat as exact match and let ClickHouse error if bad
        logger.warning("Target %r is not a valid IP or CIDR; using exact match", target)
        return f"dst_addr = '{target}'"


def build_sc_filter(device_ips: list[str] | None) -> str:
    """Return an AND clause that restricts to the given sampler addresses.

    Returns an empty string when ``device_ips`` is None or empty.
    """
    if not device_ips:
        return ""
    ips = ", ".join(f"'{ip}'" for ip in device_ips)
    return f"AND sampler_address IN ({ips})"


# ── Repository ───────────────────────────────────────────────────────

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

    def query(self, sql: str):
        """Execute a raw SQL query and return the result."""
        return self.client.query(sql)

    def query_as_dicts(self, sql: str) -> list[dict]:
        """Execute a query and return results as a list of dicts."""
        res = self.client.query(sql)
        cols = res.column_names
        return [dict(zip(cols, row)) for row in res.result_rows]

    # ── SC Resolver ──────────────────────────────────────────────────

    @staticmethod
    def build_resolve_sc_query(sc_names: list[str]) -> str:
        """Get distinct sampler_addresses for each scrub center name.

        Uses the ``owl_gold.scrubCenterNetworks_dict`` dictionary to
        reverse-map SC names to device IPs (sampler_address).
        """
        sc_list = ", ".join(f"'{sc}'" for sc in sc_names)
        return f"""SELECT DISTINCT
    dictGet('owl_gold.scrubCenterNetworks_dict', 'sc', toIPv4(sampler_address)) AS sc_name,
    sampler_address
FROM owl_bronze.sflowsPostmit
WHERE sc_name IN ({sc_list})"""

    # ── Curve Query (combined range + curve, 10-second buckets) ──────

    @staticmethod
    def build_curve_query(
        target: str,
        device_ips: list[str] | None = None,
    ) -> str:
        """Per-10-second bps/pps for the last hour, gaps zero-filled.

        Combines the time-range discovery and the curve query into a
        single statement using a CTE.  Filters on nanosecond timestamps.
        """
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""WITH range AS (
    SELECT
        min(time_received_ns) AS start_ns,
        max(time_received_ns) AS end_ns
    FROM owl_bronze.sflowsPostmit
    WHERE {target_filter}
      {sc_filter}
      AND time_received_ns >= toUnixTimestamp(now() - INTERVAL 1 HOUR) * 1000000000
)
SELECT
    toStartOfInterval(
        toDateTime(intDiv(time_received_ns, 1000000000)),
        INTERVAL 10 SECOND
    ) AS bucket,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS total_bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS total_pps
FROM owl_bronze.sflowsPostmit, range
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= range.start_ns
  AND time_received_ns <  range.end_ns + 1
GROUP BY bucket
ORDER BY bucket WITH FILL
    FROM toStartOfInterval(
        toDateTime(intDiv(coalesce((SELECT start_ns FROM range), 0), 1000000000)),
        INTERVAL 10 SECOND
    )
    TO toStartOfInterval(
        toDateTime(intDiv(coalesce((SELECT end_ns FROM range), 0), 1000000000)),
        INTERVAL 10 SECOND
    )
    STEP toIntervalSecond(10)"""

    # ── Decomposition Queries ────────────────────────────────────────

    @staticmethod
    def build_overall_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
    ) -> str:
        """Total bps/pps for the peak window — no grouping."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}"""

    @staticmethod
    def build_breakdown_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
    ) -> str:
        """Decompose one peak window by scrub center + L2/L3/L4 layers."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    dictGet('owl_gold.scrubCenterNetworks_dict', 'sc', toIPv4(sampler_address)) AS scrub_center,
    ethernet_type,
    protocol,
    dst_port,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}
GROUP BY scrub_center, ethernet_type, protocol, dst_port
ORDER BY bps DESC"""

    @staticmethod
    def build_by_protocol_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
    ) -> str:
        """Bps/pps grouped by protocol for the peak window."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    protocol,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}
GROUP BY protocol
ORDER BY bps DESC"""

    @staticmethod
    def build_by_port_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
        top_n: int = 10,
    ) -> str:
        """Bps/pps grouped by destination port for the peak window."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    dst_port,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}
GROUP BY dst_port
ORDER BY bps DESC
LIMIT {top_n}"""

    @staticmethod
    def build_by_ethernet_type_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
    ) -> str:
        """Bps/pps grouped by EtherType for the peak window."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    ethernet_type,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}
GROUP BY ethernet_type
ORDER BY bps DESC"""

    @staticmethod
    def build_by_sc_query(
        target: str,
        start_ns: int,
        end_ns: int,
        device_ips: list[str] | None = None,
    ) -> str:
        """Bps/pps grouped by scrub center for the peak window."""
        target_filter = build_target_filter(target)
        sc_filter = build_sc_filter(device_ips)
        return f"""SELECT
    if(dictGet('owl_gold.scrubCenterNetworks_dict', 'sc', toIPv4(sampler_address)) = '', concat('unmapped (', sampler_address, ')'), dictGet('owl_gold.scrubCenterNetworks_dict', 'sc', toIPv4(sampler_address))) AS scrub_center,
    sum(frame_length * if(sampling_rate > 0, sampling_rate, 1)) * 8 / 10 AS bps,
    sum(if(sampling_rate > 0, sampling_rate, 1)) / 10 AS pps
FROM owl_bronze.sflowsPostmit
WHERE {target_filter}
  {sc_filter}
  AND time_received_ns >= {start_ns}
  AND time_received_ns <  {end_ns}
GROUP BY scrub_center
ORDER BY bps DESC"""


# Module-level singleton for convenience
clickhouse_repo = ClickHouseRepository()
