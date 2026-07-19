"""Graph node: find top-5 BPS and PPS peaks (overall + per-SC).

Runs peak detection once for "overall" (all SCs combined) and once
per scrub center (restricted to that SC's device IPs).

Result: ``(1 + N) × 2 × 5`` peak windows where N = number of SCs.

Reads : ``detection_target``, ``device_ips``
Writes: ``peaks_bps``, ``peaks_pps``
"""

import logging
from collections import defaultdict

from traffic_intel_agent.models.traffic_analysis import TrafficIntelState, PeakWindow
from traffic_intel_agent.repositories.clickhouse_repo import ClickHouseRepository
from traffic_intel_agent.services.traffic_analyzer import PeakDetector

logger = logging.getLogger(__name__)


def _detect_peaks_for_scope(
    repo: ClickHouseRepository,
    target: str,
    scope: str,
    device_ips: list[str] | None = None,
) -> tuple[list[PeakWindow], list[PeakWindow]]:
    """Fetch the curve for one scope and run peak detection.

    Returns
    -------
    (bps_peaks, pps_peaks) : tuple of list[PeakWindow]
    """
    sql = repo.build_curve_query(target, device_ips)

    try:
        res = repo.query(sql)
    except Exception as e:
        logger.error("Curve query failed for scope '%s': %s", scope, e)
        return [], []

    if not res.result_rows:
        logger.info("No traffic data for scope '%s'", scope)
        return [], []

    timestamps = [row[0] for row in res.result_rows]
    bps        = [row[1] for row in res.result_rows]
    pps        = [row[2] for row in res.result_rows]

    detector = PeakDetector(timestamps, bps, pps, scope=scope)

    bps_peaks = detector.detect(metric="bps")
    pps_peaks = detector.detect(metric="pps")

    logger.info(
        "Scope '%s': %d BPS peak(s), %d PPS peak(s) from %d buckets",
        scope, len(bps_peaks), len(pps_peaks), len(timestamps),
    )

    return bps_peaks, pps_peaks


def find_peaks(state: TrafficIntelState) -> dict:
    """Produce top-5 BPS and PPS peaks for overall + per-SC scopes."""
    target = state["detection_target"]
    device_ips = state.get("device_ips", {})

    repo = ClickHouseRepository()

    peaks_bps: dict[str, list[PeakWindow]] = {}
    peaks_pps: dict[str, list[PeakWindow]] = {}

    # ── Overall (all selected SCs combined) ──
    # Flatten all device IPs for the overall scope
    all_device_ips = []
    for ips in device_ips.values():
        all_device_ips.extend(ips)

    bps, pps = _detect_peaks_for_scope(
        repo, target, "overall",
        device_ips=all_device_ips if all_device_ips else None,
    )
    peaks_bps["overall"] = bps
    peaks_pps["overall"] = pps

    # ── Per-SC ──
    for sc_name, sc_ips in device_ips.items():
        bps, pps = _detect_peaks_for_scope(
            repo, target, sc_name,
            device_ips=sc_ips,
        )
        peaks_bps[sc_name] = bps
        peaks_pps[sc_name] = pps

    total_bps = sum(len(v) for v in peaks_bps.values())
    total_pps = sum(len(v) for v in peaks_pps.values())
    logger.info(
        "Total peaks found: %d BPS, %d PPS across %d scope(s)",
        total_bps, total_pps, len(peaks_bps),
    )

    return {"peaks_bps": peaks_bps, "peaks_pps": peaks_pps}
