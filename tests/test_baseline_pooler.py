"""Tests for baseline_pooler — pooling raw Cassandra profiles."""

from datetime import datetime
from traffic_intel_agent.services.baseline_pooler import pool_baseline
from traffic_intel_agent.models.traffic_analysis import PooledBaseline


# ─── helpers ──────────────────────────────────────────────────────

def make_profile(
    location: str = "",
    bytes_val: float = 1e9,
    packets_val: float = 1e6,
    protocol_list: list | None = None,
    dp_list: list | None = None,
    profile_ts: datetime | None = None,
) -> dict:
    """Build a raw profile dict matching the Cassandra output format."""
    data = {
        "bytes": bytes_val,
        "packets": packets_val,
        "protocolList": protocol_list or [
            {"bytes": bytes_val, "packets": packets_val, "protocol": "udp"}
        ],
        "dpList": dp_list or [
            {"bytes": bytes_val, "packets": packets_val, "dp": "5204"}
        ],
    }
    return {
        "location": location,
        "profile_ts": profile_ts or datetime(2026, 6, 5),
        "data": data,
    }


# ─── basic pooling ───────────────────────────────────────────────

def test_empty_profiles():
    """Empty input returns zero baseline."""
    result = pool_baseline([])
    assert isinstance(result, PooledBaseline)
    assert result.baseline_bps == 0
    assert result.baseline_pps == 0
    assert result.num_days == 0


def test_single_day_single_location():
    """Single overall profile produces correct rates."""
    profiles = [make_profile(location="", bytes_val=86400 * 1e6, packets_val=86400 * 1e3)]
    result = pool_baseline(profiles)

    # baseline_bps = 86400e6 * 8 / (1 * 86400) = 8e6 = 8 Mbps
    assert abs(result.baseline_bps - 8e6) < 1
    # baseline_pps = 86400e3 / (1 * 86400) = 1e3 = 1000 pps
    assert abs(result.baseline_pps - 1000) < 1
    assert result.num_days == 1


def test_multiple_days():
    """Multiple days are summed and averaged correctly."""
    profiles = [
        make_profile(location="", bytes_val=86400 * 1e6, profile_ts=datetime(2026, 6, 5)),
        make_profile(location="", bytes_val=86400 * 2e6, profile_ts=datetime(2026, 6, 6)),
    ]
    result = pool_baseline(profiles)

    # total bytes = 86400 * 3e6, num_days = 2
    # baseline_bps = 86400*3e6 * 8 / (2 * 86400) = 12e6 = 12 Mbps
    assert abs(result.baseline_bps - 12e6) < 1
    assert result.num_days == 2


def test_overall_vs_per_sc_no_double_count():
    """Per-SC rows don't inflate the total baseline; only overall rows count."""
    profiles = [
        make_profile(location="", bytes_val=1e9),       # overall
        make_profile(location="lon", bytes_val=5.5e8),   # per-SC (should not add to total)
        make_profile(location="fra", bytes_val=4.5e8),   # per-SC
    ]
    result = pool_baseline(profiles)

    # total_bytes should only be 1e9 (from the overall row)
    assert result.total_bytes == 1e9


def test_sc_shares():
    """Per-SC shares are computed from per-SC rows only."""
    profiles = [
        make_profile(location="", bytes_val=1e9),
        make_profile(location="lon", bytes_val=5.5e8),
        make_profile(location="fra", bytes_val=4.5e8),
    ]
    result = pool_baseline(profiles)

    assert abs(result.sc_shares["lon"] - 0.55) < 0.01
    assert abs(result.sc_shares["fra"] - 0.45) < 0.01


# ─── protocol shares ─────────────────────────────────────────────

def test_protocol_shares_single_protocol():
    """Single protocol gets 100% share."""
    profiles = [make_profile(
        location="",
        protocol_list=[{"bytes": 1e9, "packets": 1e6, "protocol": "udp"}],
    )]
    result = pool_baseline(profiles)

    assert "udp" in result.protocol_shares
    assert abs(result.protocol_shares["udp"] - 1.0) < 0.001


def test_protocol_shares_multi():
    """Multiple protocols get proportional shares."""
    profiles = [make_profile(
        location="",
        protocol_list=[
            {"bytes": 700, "packets": 70, "protocol": "tcp"},
            {"bytes": 250, "packets": 25, "protocol": "udp"},
            {"bytes": 50, "packets": 5, "protocol": "icmp"},
        ],
    )]
    result = pool_baseline(profiles)

    assert abs(result.protocol_shares["tcp"] - 0.70) < 0.01
    assert abs(result.protocol_shares["udp"] - 0.25) < 0.01
    assert abs(result.protocol_shares["icmp"] - 0.05) < 0.01


def test_protocol_names_are_lowercased():
    """Protocol names are stored lowercase in the baseline."""
    profiles = [make_profile(
        location="",
        protocol_list=[{"bytes": 1000, "packets": 100, "protocol": "UDP"}],
    )]
    result = pool_baseline(profiles)

    # The pooler lowercases protocol names
    assert "udp" in result.protocol_shares


# ─── dst port shares ─────────────────────────────────────────────

def test_dst_port_shares():
    """Destination port shares are computed correctly."""
    profiles = [make_profile(
        location="",
        dp_list=[
            {"bytes": 600, "packets": 60, "dp": "443"},
            {"bytes": 400, "packets": 40, "dp": "80"},
        ],
    )]
    result = pool_baseline(profiles)

    assert abs(result.dst_port_shares["443"] - 0.60) < 0.01
    assert abs(result.dst_port_shares["80"] - 0.40) < 0.01
