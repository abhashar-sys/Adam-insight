"""Graph node: decompose a single peak into multi-dimensional breakdowns.

This node is designed for fan-out via LangGraph's ``Send`` API — one
invocation per peak.  It runs ClickHouse queries to aggregate traffic
by scrub center, EtherType, protocol, and destination port for the
peak's time window.

Reads : a single ``PeakWindow`` (passed via Send)
Writes: ``peak_breakdowns[peak_id]``  (PeakBreakdown)
"""

import logging

from traffic_intel_agent.models.traffic_analysis import (
    BreakdownEntry,
    PeakBreakdown,
    PeakWindow,
)
from traffic_intel_agent.repositories.clickhouse_repo import ClickHouseRepository

logger = logging.getLogger(__name__)


def _rows_to_breakdown_entries(
    rows: list[dict],
    value_key: str,
    metric_key: str = "bps",
) -> list[BreakdownEntry]:
    """Convert raw query result rows into BreakdownEntry objects.

    Computes ``share_pct`` as the percentage of total BPS or PPS
    contributed by each row.
    """
    total = sum(float(r.get(metric_key, 0)) for r in rows) or 1.0

    entries = []
    for row in rows:
        val = str(row.get(value_key, "unknown"))
        bps = float(row.get("bps", 0))
        pps = float(row.get("pps", 0))
        metric_val = float(row.get(metric_key, 0))

        entries.append(BreakdownEntry(
            value=val,
            bps=bps,
            pps=pps,
            share_pct=(metric_val / total) * 100,
        ))

    return entries


def decompose_peak(state: dict) -> dict:
    """Decompose one peak into breakdown views.

    The ``state`` dict is expected to contain:
    - ``peak``: PeakWindow
    - ``detection_target``: str
    - ``device_ips``: dict[str, list[str]]

    Returns
    -------
    dict
        ``{"peak_breakdowns": {peak_id: PeakBreakdown}}``
    """
    peak: PeakWindow = state["peak"]
    target: str = state["detection_target"]
    device_ips: dict[str, list[str]] = state.get("device_ips", {})

    # Determine which device IPs to use based on peak scope
    if peak.scope == "overall":
        scope_ips = []
        for ips in device_ips.values():
            scope_ips.extend(ips)
        scope_ips = scope_ips if scope_ips else None
    else:
        scope_ips = device_ips.get(peak.scope)

    repo = ClickHouseRepository()
    start_ns = int(peak.start_ts.timestamp() * 1_000_000_000)
    end_ns   = int(peak.end_ts.timestamp() * 1_000_000_000)

    try:
        overall_rows = repo.query_as_dicts(
            repo.build_overall_query(target, start_ns, end_ns, scope_ips))
        sc_rows = repo.query_as_dicts(
            repo.build_by_sc_query(target, start_ns, end_ns, scope_ips))
        ether_rows = repo.query_as_dicts(
            repo.build_by_ethernet_type_query(target, start_ns, end_ns, scope_ips))
        proto_rows = repo.query_as_dicts(
            repo.build_by_protocol_query(target, start_ns, end_ns, scope_ips))
        port_rows = repo.query_as_dicts(
            repo.build_by_port_query(target, start_ns, end_ns, scope_ips))
    except Exception as e:
        logger.error("Decomposition failed for peak %s: %s", peak.peak_id, e)
        return {"peak_breakdowns": {peak.peak_id: PeakBreakdown(peak_id=peak.peak_id)}}

    # Overall BPS/PPS
    overall_bps = float(overall_rows[0].get("bps", 0)) if overall_rows else 0
    overall_pps = float(overall_rows[0].get("pps", 0)) if overall_rows else 0

    # Determine which metric to use for share_pct based on peak metric
    metric_key = "bps" if peak.metric == "bps" else "pps"

    breakdown = PeakBreakdown(
        peak_id=peak.peak_id,
        overall_bps=overall_bps,
        overall_pps=overall_pps,
        by_sc=_rows_to_breakdown_entries(sc_rows, "scrub_center", metric_key),
        by_ethernet_type=_rows_to_breakdown_entries(ether_rows, "ethernet_type", metric_key),
        by_protocol=_rows_to_breakdown_entries(proto_rows, "protocol", metric_key),
        by_dst_port=_rows_to_breakdown_entries(port_rows, "dst_port", metric_key),
    )

    logger.info(
        "Decomposed peak %s: %d SC(s), %d proto(s), %d port(s)",
        peak.peak_id,
        len(breakdown.by_sc),
        len(breakdown.by_protocol),
        len(breakdown.by_dst_port),
    )

    return {"peak_breakdowns": {peak.peak_id: breakdown}}
