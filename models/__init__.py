"""
Data models for sFlow traffic analysis.

Classes:
    - SflowTelemetry: Full sFlow record schema (ClickHouse row model)
    - PeakWindow: A single detected traffic peak
    - BreakdownEntry: One row in a peak breakdown
    - PeakBreakdown: Full decomposition of a peak across dimensions
    - PooledBaseline: 6-day pooled baseline rates and shares
    - TrafficSnapshot: Final assembled output
    - TrafficIntelState: LangGraph agent state
"""

from models.traffic_analysis import (
    SflowTelemetry,
    PeakWindow,
    BreakdownEntry,
    PeakBreakdown,
    PooledBaseline,
    TrafficSnapshot,
    TrafficIntelState,
)

__all__ = [
    'SflowTelemetry',
    'PeakWindow',
    'BreakdownEntry',
    'PeakBreakdown',
    'PooledBaseline',
    'TrafficSnapshot',
    'TrafficIntelState',
]
