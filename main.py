from tools.database.finding_peaks import find_peaks
from utils.peak_decomposer import PeakDecomposer
from config.constants import TARGET_IP


def _print_peaks(peaks, label):
    """Print a formatted table of peaks."""
    if not peaks:
        print(f"  No {label} peaks detected.\n")
        return

    print(f"\n{'ID':<5} {'Start':<22} {'End':<22} {'BPS':>15} {'PPS':>15}")
    print("─" * 80)

    for p in peaks:
        print(
            f"{p['peak_id']:<5} "
            f"{str(p['start_ts']):<22} "
            f"{str(p['end_ts']):<22} "
            f"{p['total_bps']:>15,.0f} "
            f"{p['total_pps']:>15,.0f}"
        )

    print(f"\n✓ {len(peaks)} {label} peak(s) found.\n")


def _print_rows(rows, columns):
    """Print a generic list-of-dicts table using the given column names."""
    if not rows:
        print("    (no traffic in this window)\n")
        return

    # build header
    widths = {c: max(len(c), 14) for c in columns}
    header = "    " + "  ".join(f"{c:>{widths[c]}}" for c in columns)
    print(header)
    print("    " + "─" * (sum(widths.values()) + 2 * (len(columns) - 1)))

    for r in rows:
        line = "    " + "  ".join(
            f"{r[c]:>{widths[c]},.0f}" if isinstance(r[c], (int, float))
            else f"{str(r[c]):>{widths[c]}}"
            for c in columns
        )
        print(line)
    print()


def main():
    print(f"Finding peaks for {TARGET_IP} ...")
    result = find_peaks(TARGET_IP)

    if not result:
        print("No data found for this target.")
        return

    # --- Step 2: peaks ---
    print("\n═══ BPS Peaks (ranked by bits-per-second) ═══")
    _print_peaks(result["bps_peaks"], "BPS")

    print("═══ PPS Peaks (ranked by packets-per-second) ═══")
    _print_peaks(result["pps_peaks"], "PPS")

    # --- Step 3: decompose each BPS peak (all four views) ---
    print("═══ Peak Decomposition (BPS peaks) ═══")
    decomposer = PeakDecomposer(TARGET_IP)

    for peak in result["bps_peaks"]:
        print(
            f"\n── Peak #{peak['peak_id']}  "
            f"{peak['start_ts']} → {peak['end_ts']}  "
            f"({peak['total_bps']:,.0f} bps) ──"
        )
        views = decomposer.decompose_all_views(peak)

        print("\n  ▸ Overall")
        _print_rows(views["overall"], ["bps", "pps"])

        print("  ▸ By Scrub Center + L2/L3/L4")
        _print_rows(views["by_sc"], ["scrub_center", "ethernet_type", "protocol", "dst_port", "bps", "pps"])

        print("  ▸ By Protocol")
        _print_rows(views["by_protocol"], ["protocol", "bps", "pps"])

        print("  ▸ By Destination Port (top 10)")
        _print_rows(views["by_port"], ["dst_port", "bps", "pps"])


if __name__ == "__main__":
    main()