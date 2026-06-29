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


def _print_snapshot(snapshot) -> None:
    """Pretty-print a TrafficSnapshot to the console."""
    print(f"\n{'═' * 80}")
    print(f"  Traffic Snapshot for {snapshot.detection_target}")
    print(f"  Scrub Centers: {', '.join(snapshot.scrub_centers) or '(all)'}")
    print(f"{'═' * 80}")

    # ── Baseline ──
    if snapshot.baseline:
        b = snapshot.baseline
        print(f"\n{'─' * 40}")
        print(f"  6-Day Baseline ({b.num_days} day(s))")
        print(f"{'─' * 40}")
        print(f"  Avg BPS: {b.baseline_bps:>15,.0f}  ({b.baseline_bps / 1e6:.2f} Mbps)")
        print(f"  Avg PPS: {b.baseline_pps:>15,.0f}")

        if b.protocol_shares:
            print("\n  Protocol mix (by bytes):")
            for proto, share in sorted(b.protocol_shares.items(), key=lambda x: -x[1]):
                print(f"    {proto:<12} {share * 100:>6.1f}%")

        if b.dst_port_shares:
            top_ports = sorted(b.dst_port_shares.items(), key=lambda x: -x[1])[:10]
            print("\n  Top dst ports (by bytes):")
            for port, share in top_ports:
                print(f"    {port:<12} {share * 100:>6.1f}%")
    else:
        print("\n  ⚠ No baseline available (Cassandra unreachable or no data)")

    # ── Peaks ──
    for metric_label, peaks_dict in [("BPS", snapshot.bps_peaks), ("PPS", snapshot.pps_peaks)]:
        for scope, peaks in peaks_dict.items():
            print(f"\n{'─' * 40}")
            print(f"  Top {metric_label} Peaks — scope: {scope}")
            print(f"{'─' * 40}")

            if not peaks:
                print("  (no peaks detected)")
                continue

            print(f"  {'ID':<22} {'Start':<22} {'End':<22} {'BPS':>15} {'PPS':>15}")
            print(f"  {'─' * 96}")

            for p in peaks:
                print(
                    f"  {p.peak_id:<22} "
                    f"{str(p.start_ts):<22} "
                    f"{str(p.end_ts):<22} "
                    f"{p.total_bps:>15,.0f} "
                    f"{p.total_pps:>15,.0f}"
                )

                # Show breakdown if available
                bd = snapshot.peak_breakdowns.get(p.peak_id)
                if bd:
                    if bd.total_bps_delta_pct is not None:
                        print(f"    Δ BPS vs baseline: {bd.total_bps_delta_pct:>+.1f}%")
                    if bd.total_pps_delta_pct is not None:
                        print(f"    Δ PPS vs baseline: {bd.total_pps_delta_pct:>+.1f}%")

                    if bd.by_protocol:
                        print("    Protocols:", end="")
                        for e in bd.by_protocol[:5]:
                            delta_str = f" (Δ{e.delta_pct:>+.0f}%)" if e.delta_pct is not None else " (new)"
                            print(f"  {e.value} {e.share_pct:.0f}%{delta_str}", end="")
                        print()

                    if bd.by_dst_port:
                        print("    Top ports:", end="")
                        for e in bd.by_dst_port[:5]:
                            delta_str = f" (Δ{e.delta_pct:>+.0f}%)" if e.delta_pct is not None else " (new)"
                            print(f"  {e.value} {e.share_pct:.0f}%{delta_str}", end="")
                        print()

            print(f"\n  ✓ {len(peaks)} {metric_label} peak(s) found for '{scope}'")

    print(f"\n{'═' * 80}\n")


def main():
    """Run the traffic analysis agent."""
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
