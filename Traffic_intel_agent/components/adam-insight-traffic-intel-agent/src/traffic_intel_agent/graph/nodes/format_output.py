"""Graph node: assemble the final TrafficSnapshot from all computed state.

Reads : everything in state
Writes: ``output``  (TrafficSnapshot)

LLM narration is deferred to a future iteration — this node produces
only the structured snapshot.
"""

import logging

from traffic_intel_agent.models.traffic_analysis import TrafficIntelState, TrafficSnapshot

logger = logging.getLogger(__name__)


def format_output(state: TrafficIntelState) -> dict:
    """Assemble the final TrafficSnapshot from the computed state."""
    snapshot = TrafficSnapshot(
        detection_target=state["detection_target"],
        scrub_centers=state.get("scrub_centers", []),
        baseline=state.get("baseline"),
        bps_peaks=state.get("peaks_bps", {}),
        pps_peaks=state.get("peaks_pps", {}),
        peak_breakdowns=state.get("peak_breakdowns", {}),
    )

    # Summary stats for logging
    total_bps = sum(len(v) for v in snapshot.bps_peaks.values())
    total_pps = sum(len(v) for v in snapshot.pps_peaks.values())
    n_breakdowns = len(snapshot.peak_breakdowns)
    has_baseline = snapshot.baseline is not None

    logger.info(
        "TrafficSnapshot assembled: target=%s, %d BPS peak(s), "
        "%d PPS peak(s), %d breakdown(s), baseline=%s",
        snapshot.detection_target,
        total_bps,
        total_pps,
        n_breakdowns,
        "yes" if has_baseline else "no",
    )

    return {"output": snapshot}
