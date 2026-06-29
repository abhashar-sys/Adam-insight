"""Adam Insight — sFlow traffic analysis agent.

Entry point for the LangGraph-based traffic analysis pipeline.
Resolves scrub centers, fetches baseline, detects peaks, decomposes
them, computes deltas vs baseline, and assembles a TrafficSnapshot.
"""

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-36s  %(levelname)-5s  %(message)s",
)
logger = logging.getLogger(__name__)


def quiet_logs():
    """Silence INFO chatter from noisy modules so they don't interleave with the report."""
    logging.getLogger().setLevel(logging.WARNING)
    for noisy in ("cassandra", "urllib3", "graph", "repositories", "services"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

def _fmt_bps(bps: float) -> str:
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if bps >= div:
            return f"{bps/div:,.2f} {unit}"
    return f"{bps:,.0f} bps"

def _fmt_delta(pct: float | None) -> str:
    if pct is None:
        return "new"
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%"

def _fmt_breakdown(items: list) -> str:
    if not items:
        return "—"
    parts = []
    for it in items:
        value = it.value
        share = it.share_pct
        delta = it.delta_pct
        tag = " (new)" if delta is None else f" ({_fmt_delta(delta)})"
        parts.append(f"{value} {share:.0f}%{tag}")
    return ", ".join(parts)

def _print_peak(peak, breakdown) -> None:
    pid = peak.peak_id
    start = peak.start_ts
    end = peak.end_ts
    bps = peak.total_bps
    pps = peak.total_pps
    
    dbps = breakdown.total_bps_delta_pct if breakdown else None
    dpps = breakdown.total_pps_delta_pct if breakdown else None

    print(f"  ┌─ {pid}")
    print(f"  │  window   {start}  →  {end}")
    print(f"  │  rate     {_fmt_bps(bps):>14}   |   {pps:,.0f} pps")
    print(f"  │  vs base  BPS {_fmt_delta(dbps):>8}   |   PPS {_fmt_delta(dpps):>8}")
    if breakdown:
        print(f"  │  by SC    {_fmt_breakdown(breakdown.by_sc)}")
        print(f"  │  by proto {_fmt_breakdown(breakdown.by_protocol)}")
        print(f"  │  by port  {_fmt_breakdown(breakdown.by_dst_port)}")
        print(f"  │  by ether {_fmt_breakdown(breakdown.by_ethernet_type)}")
    print(f"  └{'─' * 60}")

def _print_peak_table(title: str, peaks: list, breakdowns: dict) -> None:
    print(f"\n  {title}")
    print(f"  {'─' * 60}")
    if not peaks:
        print("    (none)")
        return
    for p in peaks:
        bd = breakdowns.get(p.peak_id) if breakdowns else None
        _print_peak(p, bd)

def _print_snapshot(snapshot) -> None:
    target = snapshot.detection_target
    scs = snapshot.scrub_centers or []
    sc_label = ", ".join(scs) if scs else "(all)"
    baseline = snapshot.baseline
    breakdowns = snapshot.peak_breakdowns or {}

    bar = "═" * 70
    print(f"\n{bar}")
    print(f"  TRAFFIC SNAPSHOT  —  {target}")
    print(f"  scrub centers: {sc_label}")
    print(bar)

    # ── baseline section ──
    if baseline:
        n_days = baseline.num_days
        print(f"\n  BASELINE  ({n_days}-day average)")
        print(f"  {'─' * 60}")
        bbps = baseline.baseline_bps
        bpps = baseline.baseline_pps
        print(f"    avg rate   {_fmt_bps(bbps):>14}   |   {bpps:,.0f} pps")

        proto = baseline.protocol_shares or {}
        if proto:
            mix = ", ".join(f"{k} {v*100:.0f}%" for k, v in proto.items())
            print(f"    protocols  {mix}")
        ports = baseline.dst_port_shares or {}
        if ports:
            mix = ", ".join(f"{k} {v*100:.0f}%" for k, v in ports.items())
            print(f"    dst ports  {mix}")
    else:
        print("\n  ⚠ No baseline available")

    # ── peaks by scope ──
    peaks_bps = snapshot.bps_peaks or {}
    peaks_pps = snapshot.pps_peaks or {}
    scopes = sorted(set(peaks_bps) | set(peaks_pps))

    for scope in scopes:
        print(f"\n{'─' * 70}")
        print(f"  SCOPE: {scope}")
        print(f"{'─' * 70}")
        _print_peak_table(
            f"Top BPS peaks",
            peaks_bps.get(scope, []), breakdowns,
        )
        _print_peak_table(
            f"Top PPS peaks",
            peaks_pps.get(scope, []), breakdowns,
        )

    print(f"\n{bar}\n")


def main():
    """Run the traffic analysis agent."""
    quiet_logs()
    # Default inputs — override via command-line or future API
    target = sys.argv[1] if len(sys.argv) > 1 else "192.0.2.10"
    scrub_centers = sys.argv[2].split(",") if len(sys.argv) > 2 else []

    print(f"Adam Insight — analysing {target}")
    if scrub_centers:
        print(f"  Scrub centers: {', '.join(scrub_centers)}")

    from graph.graph import graph

    result = graph.invoke({
        "detection_target": target,
        "scrub_centers": scrub_centers,
    })

    snapshot = result.get("output")
    if snapshot:
        _print_snapshot(snapshot)
    else:
        print("No output produced.")


if __name__ == "__main__":
    main()
