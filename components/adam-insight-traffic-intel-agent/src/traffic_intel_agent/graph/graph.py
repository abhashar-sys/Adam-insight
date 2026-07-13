"""LangGraph state machine for the sFlow traffic analysis agent.

Graph topology:

    START
      ├──▶ resolve_scrub_centers ──┐
      │                            ├──▶ find_peaks ──fan-out──▶ decompose_peak (×N) ──merge──▶ compute_deltas ──▶ format_output ──▶ END
      └──▶ fetch_baseline ─────────┘

- ``resolve_scrub_centers`` and ``fetch_baseline`` run in parallel.
- ``find_peaks`` blocks on ``resolve_scrub_centers`` (needs device IPs).
- ``compute_deltas`` blocks on both ``fetch_baseline`` (needs baseline)
  and all ``decompose_peak`` branches (needs breakdowns).
- ``decompose_peak`` fans out via LangGraph's ``Send`` API, one branch
  per detected peak.
"""

import logging
import operator
from typing import Annotated

# pyrefly: ignore [missing-import]
from langgraph.graph import StateGraph, START, END
# pyrefly: ignore [missing-import]
from langgraph.constants import Send

from traffic_intel_agent.models.traffic_analysis import (
    PeakBreakdown,
    PeakWindow,
    PooledBaseline,
    TrafficIntelState,
    TrafficSnapshot,
)
from traffic_intel_agent.graph.nodes.resolve_scrub_centers import resolve_scrub_centers
from traffic_intel_agent.graph.nodes.fetch_baseline import fetch_baseline
from traffic_intel_agent.graph.nodes.traffic_analysis import find_peaks
from traffic_intel_agent.graph.nodes.decompose_peak import decompose_peak
from traffic_intel_agent.graph.nodes.compute_deltas import compute_deltas
from traffic_intel_agent.graph.nodes.format_output import format_output

logger = logging.getLogger(__name__)


# ── Merge reducer for peak_breakdowns ────────────────────────────
# Each decompose_peak invocation returns one {peak_id: PeakBreakdown}.
# We need to merge them all into a single dict.

def merge_breakdowns(
    existing: dict[str, PeakBreakdown],
    new: dict[str, PeakBreakdown],
) -> dict[str, PeakBreakdown]:
    """Reducer: merge decompose_peak results into one dict."""
    merged = dict(existing) if existing else {}
    merged.update(new)
    return merged


# ── Annotated state for reducers ─────────────────────────────────
# LangGraph needs reducers for fields that receive writes from
# multiple parallel branches (peak_breakdowns from fan-out).

class GraphState(TrafficIntelState, total=False):
    """Extended state with reducer annotations for LangGraph."""
    peak_breakdowns: Annotated[dict[str, PeakBreakdown], merge_breakdowns]


# ── Fan-out logic ────────────────────────────────────────────────

def fan_out_peaks(state: GraphState) -> list[Send]:
    """Create a Send for each detected peak to decompose in parallel."""
    sends = []
    peaks_bps = state.get("peaks_bps", {})
    peaks_pps = state.get("peaks_pps", {})

    for scope_peaks in peaks_bps.values():
        for peak in scope_peaks:
            sends.append(Send("decompose_peak", {
                "peak": peak,
                "detection_target": state["detection_target"],
                "device_ips": state.get("device_ips", {}),
            }))

    for scope_peaks in peaks_pps.values():
        for peak in scope_peaks:
            sends.append(Send("decompose_peak", {
                "peak": peak,
                "detection_target": state["detection_target"],
                "device_ips": state.get("device_ips", {}),
            }))

    logger.info("Fanning out %d peak decomposition(s)", len(sends))
    return sends


# ── Build the graph ──────────────────────────────────────────────

def build_graph() -> StateGraph:
    """Construct and compile the traffic analysis LangGraph."""
    builder = StateGraph(GraphState)

    # Register nodes
    builder.add_node("resolve_scrub_centers", resolve_scrub_centers)
    builder.add_node("fetch_baseline", fetch_baseline)
    builder.add_node("find_peaks", find_peaks)
    builder.add_node("decompose_peak", decompose_peak)
    builder.add_node("compute_deltas", compute_deltas)
    builder.add_node("format_output", format_output)

    # Parallel start: resolve_scrub_centers + fetch_baseline
    builder.add_edge(START, "resolve_scrub_centers")
    builder.add_edge(START, "fetch_baseline")

    # find_peaks depends on resolve_scrub_centers (needs device_ips)
    builder.add_edge("resolve_scrub_centers", "find_peaks")

    # Fan-out: find_peaks → decompose_peak (×N peaks)
    builder.add_conditional_edges("find_peaks", fan_out_peaks)

    # compute_deltas waits for all decompose_peak branches + fetch_baseline
    builder.add_edge("decompose_peak", "compute_deltas")
    builder.add_edge("fetch_baseline", "compute_deltas")

    # Final assembly
    builder.add_edge("compute_deltas", "format_output")
    builder.add_edge("format_output", END)

    return builder.compile()


# Module-level compiled graph
graph = build_graph()
