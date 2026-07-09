"""Graph node: compute delta-vs-baseline for all peak breakdowns.

Pure compute — for each breakdown value, compare its share in the
peak vs its share in the 6-day baseline; produce % rise/drop.

If baseline is None (Cassandra was unavailable), this node is a
no-op — breakdowns pass through without deltas.

Reads : ``peak_breakdowns``, ``baseline``, ``peaks_bps``, ``peaks_pps``
Writes: updates ``peak_breakdowns`` with delta fields populated
"""

import logging

from models.traffic_analysis import (
    PeakBreakdown,
    PeakWindow,
    PooledBaseline,
    TrafficIntelState,
)
from services.delta_calculator import DeltaCalculator

logger = logging.getLogger(__name__)


def compute_deltas(state: TrafficIntelState) -> dict:
    """Enrich all peak breakdowns with baseline deltas."""
    baseline = state.get("baseline")
    breakdowns = state.get("peak_breakdowns", {})
    peaks_bps = state.get("peaks_bps", {})
    peaks_pps = state.get("peaks_pps", {})

    if baseline is None:
        logger.warning("No baseline available; skipping delta computation")
        return {"peak_breakdowns": breakdowns}

    # Build a lookup: peak_id → PeakWindow
    peak_lookup: dict[str, PeakWindow] = {}
    for scope_peaks in peaks_bps.values():
        for peak in scope_peaks:
            peak_lookup[peak.peak_id] = peak
    for scope_peaks in peaks_pps.values():
        for peak in scope_peaks:
            peak_lookup[peak.peak_id] = peak

    calculator = DeltaCalculator(baseline)
    enriched: dict[str, PeakBreakdown] = {}

    for peak_id, breakdown in breakdowns.items():
        peak = peak_lookup.get(peak_id)
        if peak is None:
            logger.warning("Peak %s not found in peak lookup; skipping", peak_id)
            enriched[peak_id] = breakdown
            continue

        enriched[peak_id] = calculator.enrich_breakdown(breakdown, peak)

    n_enriched = sum(
        1 for b in enriched.values()
        if b.total_bps_delta_pct is not None
    )
    logger.info(
        "Computed deltas for %d/%d breakdowns",
        n_enriched, len(enriched),
    )

    return {"peak_breakdowns": enriched}
