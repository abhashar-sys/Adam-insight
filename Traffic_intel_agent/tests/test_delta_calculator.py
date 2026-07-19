"""Tests for DeltaCalculator — compare peak breakdowns against baseline."""

from datetime import datetime
from models.traffic_analysis import (
    BreakdownEntry,
    PeakBreakdown,
    PeakWindow,
    PooledBaseline,
)
from services.delta_calculator import DeltaCalculator


# ─── helpers ──────────────────────────────────────────────────────

def make_baseline(**kwargs) -> PooledBaseline:
    """Build a PooledBaseline with sensible defaults."""
    defaults = dict(
        total_bytes=1e9,
        total_packets=1e6,
        num_days=6,
        baseline_bps=1e9 * 8 / (6 * 86400),  # ~1.54 kbps
        baseline_pps=1e6 / (6 * 86400),       # ~1.93 pps
        protocol_shares={"tcp": 0.70, "udp": 0.25, "icmp": 0.05},
        dst_port_shares={"443": 0.60, "80": 0.20, "8080": 0.10, "53": 0.10},
        sc_shares={"lon": 0.55, "fra": 0.45},
    )
    defaults.update(kwargs)
    return PooledBaseline(**defaults)


def make_peak(**kwargs) -> PeakWindow:
    """Build a PeakWindow with sensible defaults."""
    defaults = dict(
        peak_id="overall_bps_1",
        scope="overall",
        metric="bps",
        start_ts=datetime(2026, 6, 11, 11, 32, 0),
        end_ts=datetime(2026, 6, 11, 11, 33, 0),
        total_bps=1_420_000_000,
        total_pps=752_000,
    )
    defaults.update(kwargs)
    return PeakWindow(**defaults)


def make_breakdown(peak_id="overall_bps_1", **kwargs) -> PeakBreakdown:
    """Build a PeakBreakdown with sensible defaults."""
    defaults = dict(
        peak_id=peak_id,
        overall_bps=1_420_000_000,
        overall_pps=752_000,
        by_protocol=[
            BreakdownEntry(value="UDP", bps=1_349_000_000, pps=714_400, share_pct=95.0),
            BreakdownEntry(value="TCP", bps=56_800_000, pps=30_080, share_pct=4.0),
        ],
        by_dst_port=[
            BreakdownEntry(value="53", bps=1_107_600_000, pps=586_560, share_pct=78.0),
            BreakdownEntry(value="443", bps=170_400_000, pps=90_240, share_pct=12.0),
        ],
        by_sc=[
            BreakdownEntry(value="lon", bps=1_136_000_000, pps=601_600, share_pct=80.0),
            BreakdownEntry(value="fra", bps=284_000_000, pps=150_400, share_pct=20.0),
        ],
    )
    defaults.update(kwargs)
    return PeakBreakdown(**defaults)


# ─── total deltas ─────────────────────────────────────────────────

def test_total_bps_delta():
    """Total BPS delta is computed correctly."""
    baseline = make_baseline(baseline_bps=82_000_000)
    peak = make_peak(total_bps=1_420_000_000)
    calc = DeltaCalculator(baseline)
    bps_delta, _ = calc.compute_total_deltas(peak)

    # (1.42G - 82M) / 82M * 100 ≈ 1631.7%
    assert bps_delta is not None
    assert abs(bps_delta - 1631.7) < 1


def test_total_pps_delta():
    """Total PPS delta is computed correctly."""
    baseline = make_baseline(baseline_pps=12_000)
    peak = make_peak(total_pps=752_000)
    calc = DeltaCalculator(baseline)
    _, pps_delta = calc.compute_total_deltas(peak)

    # (752k - 12k) / 12k * 100 ≈ 6166.7%
    assert pps_delta is not None
    assert abs(pps_delta - 6166.7) < 1


def test_total_delta_zero_baseline():
    """When baseline rate is 0, delta is None."""
    baseline = make_baseline(baseline_bps=0, baseline_pps=0)
    peak = make_peak(total_bps=100, total_pps=10)
    calc = DeltaCalculator(baseline)
    bps_delta, pps_delta = calc.compute_total_deltas(peak)

    assert bps_delta is None
    assert pps_delta is None


# ─── per-dimension share deltas ──────────────────────────────────

def test_protocol_delta_case_normalization():
    """Protocol name normalisation: ClickHouse 'UDP' matches baseline 'udp'."""
    baseline = make_baseline(protocol_shares={"udp": 0.25, "tcp": 0.70})
    breakdown = make_breakdown(by_protocol=[
        BreakdownEntry(value="UDP", share_pct=95.0),  # uppercase from ClickHouse
        BreakdownEntry(value="TCP", share_pct=4.0),
    ])
    peak = make_peak()
    calc = DeltaCalculator(baseline)
    enriched = calc.enrich_breakdown(breakdown, peak)

    # UDP: (0.95 - 0.25) / 0.25 * 100 = 280%
    udp_entry = next(e for e in enriched.by_protocol if e.value == "UDP")
    assert udp_entry.delta_pct is not None
    assert abs(udp_entry.delta_pct - 280.0) < 0.1
    assert abs(udp_entry.baseline_share_pct - 25.0) < 0.1


def test_value_not_in_baseline_is_new():
    """A breakdown value absent from baseline gets delta=None ('new')."""
    baseline = make_baseline(dst_port_shares={"443": 0.60, "80": 0.40})
    breakdown = make_breakdown(by_dst_port=[
        BreakdownEntry(value="53", share_pct=78.0),  # port 53 not in baseline
    ])
    peak = make_peak()
    calc = DeltaCalculator(baseline)
    enriched = calc.enrich_breakdown(breakdown, peak)

    port_53 = enriched.by_dst_port[0]
    assert port_53.delta_pct is None      # "new (not in baseline)"
    assert port_53.baseline_share_pct is None


def test_value_share_drop():
    """A value that dominates baseline but shrinks in peak shows negative delta."""
    baseline = make_baseline(protocol_shares={"tcp": 0.70, "udp": 0.25})
    breakdown = make_breakdown(by_protocol=[
        BreakdownEntry(value="TCP", share_pct=4.0),   # dropped from 70%
        BreakdownEntry(value="UDP", share_pct=95.0),
    ])
    peak = make_peak()
    calc = DeltaCalculator(baseline)
    enriched = calc.enrich_breakdown(breakdown, peak)

    tcp_entry = next(e for e in enriched.by_protocol if e.value == "TCP")
    # (0.04 - 0.70) / 0.70 * 100 ≈ -94.3%
    assert tcp_entry.delta_pct is not None
    assert tcp_entry.delta_pct < -90


def test_sc_share_delta():
    """SC share deltas are computed correctly."""
    baseline = make_baseline(sc_shares={"lon": 0.55, "fra": 0.45})
    breakdown = make_breakdown(by_sc=[
        BreakdownEntry(value="lon", share_pct=80.0),
        BreakdownEntry(value="fra", share_pct=20.0),
    ])
    peak = make_peak()
    calc = DeltaCalculator(baseline)
    enriched = calc.enrich_breakdown(breakdown, peak)

    lon = next(e for e in enriched.by_sc if e.value == "lon")
    fra = next(e for e in enriched.by_sc if e.value == "fra")

    # lon: (0.80 - 0.55) / 0.55 * 100 ≈ 45.5%
    assert lon.delta_pct is not None
    assert abs(lon.delta_pct - 45.45) < 1

    # fra: (0.20 - 0.45) / 0.45 * 100 ≈ -55.6%
    assert fra.delta_pct is not None
    assert fra.delta_pct < -50


def test_ethernet_type_no_baseline():
    """EtherType has no Cassandra baseline — deltas remain None."""
    baseline = make_baseline()
    breakdown = make_breakdown(by_ethernet_type=[
        BreakdownEntry(value="IPv4", share_pct=100.0),
    ])
    peak = make_peak()
    calc = DeltaCalculator(baseline)
    enriched = calc.enrich_breakdown(breakdown, peak)

    ipv4 = enriched.by_ethernet_type[0]
    assert ipv4.delta_pct is None
    assert ipv4.baseline_share_pct is None
