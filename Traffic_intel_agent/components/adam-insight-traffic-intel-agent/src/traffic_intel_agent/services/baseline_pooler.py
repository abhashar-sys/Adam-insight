"""Pool raw Cassandra daily_profiles into a PooledBaseline.

The 6-day baseline is computed by summing bytes/packets across all
trailing daily profiles and normalising to a rate:

    baseline_bps = sum(bytes)  * 8 / (num_days * 86400)
    baseline_pps = sum(packets)    / (num_days * 86400)

Per-dimension shares are weighted by traffic volume — heavier days
naturally count more, which is intentional ("typical day" = volume-weighted).
"""

from traffic_intel_agent.models.traffic_analysis import PooledBaseline
from traffic_intel_agent.config.constants import SECONDS_PER_DAY


def pool_baseline(raw_profiles: list[dict]) -> PooledBaseline:
    """Transform raw Cassandra profile rows into a PooledBaseline.

    Parameters
    ----------
    raw_profiles : list[dict]
        Each entry has ``{"location": str, "profile_ts": datetime, "data": dict}``.
        The ``data`` dict is the parsed ``profile_data`` JSON from Cassandra.

    Returns
    -------
    PooledBaseline
    """
    if not raw_profiles:
        return PooledBaseline()

    total_bytes = 0.0
    total_packets = 0.0
    protocol_bytes: dict[str, float] = {}
    dst_port_bytes: dict[str, float] = {}
    sc_bytes: dict[str, float] = {}

    # Collect unique profile dates to count actual days
    profile_dates: set[str] = set()

    for profile in raw_profiles:
        data = profile["data"]
        location = profile.get("location", "")
        profile_ts = profile.get("profile_ts")

        row_bytes = float(data.get("bytes", 0))
        row_packets = float(data.get("packets", 0))

        # Only count the "overall" rows (empty location) for total rates
        # to avoid double-counting when both overall + per-SC rows exist.
        if not location:
            total_bytes += row_bytes
            total_packets += row_packets
            if profile_ts:
                profile_dates.add(str(profile_ts.date()) if hasattr(profile_ts, 'date') else str(profile_ts)[:10])

        # Per-location (SC) breakdown — only non-empty locations
        if location:
            sc_bytes[location] = sc_bytes.get(location, 0) + row_bytes

        # Protocol shares — aggregate from protocolList
        for entry in data.get("protocolList", []):
            proto = entry.get("protocol", "unknown").lower()
            b = float(entry.get("bytes", 0))
            protocol_bytes[proto] = protocol_bytes.get(proto, 0) + b

        # Destination port shares — aggregate from dpList
        for entry in data.get("dpList", []):
            port = str(entry.get("dp", "unknown"))
            b = float(entry.get("bytes", 0))
            dst_port_bytes[port] = dst_port_bytes.get(port, 0) + b

    num_days = max(len(profile_dates), 1)
    window_seconds = num_days * SECONDS_PER_DAY

    baseline_bps = total_bytes * 8 / window_seconds if window_seconds else 0
    baseline_pps = total_packets / window_seconds if window_seconds else 0

    # Compute shares
    protocol_total = sum(protocol_bytes.values()) or 1
    protocol_shares = {k: v / protocol_total for k, v in protocol_bytes.items()}

    port_total = sum(dst_port_bytes.values()) or 1
    dst_port_shares = {k: v / port_total for k, v in dst_port_bytes.items()}

    sc_total = sum(sc_bytes.values()) or 1
    sc_shares = {k: v / sc_total for k, v in sc_bytes.items()}

    return PooledBaseline(
        total_bytes=total_bytes,
        total_packets=total_packets,
        num_days=num_days,
        baseline_bps=baseline_bps,
        baseline_pps=baseline_pps,
        protocol_shares=protocol_shares,
        dst_port_shares=dst_port_shares,
        sc_shares=sc_shares,
        raw_profiles=raw_profiles,
    )
