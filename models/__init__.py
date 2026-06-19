"""
Data models for sFlow traffic analysis.

Classes:
    - TrafficQueryInput: Input parameters
    - TrafficQueryOutput: Query results
    - MinuteBucket: 1-minute traffic summary
    - L2Breakdown: Layer 2 (EtherType) breakdown
    - L3Breakdown: Layer 3 (Protocol) breakdown
    - L4Breakdown: Layer 4 (Port) breakdown
"""

from models.sflow_traffic import (
    TrafficQueryInput,
    TrafficQueryOutput,
    MinuteBucket,
    L2Breakdown,
    L3Breakdown,
    L4Breakdown,
)

__all__ = [
    'TrafficQueryInput',
    'TrafficQueryOutput',
    'MinuteBucket',
    'L2Breakdown',
    'L3Breakdown',
    'L4Breakdown',
]
