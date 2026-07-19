"""Delta computation: compare peak breakdowns against the 6-day pooled baseline.

Delta math (from spec):
    Total BPS delta       = (peak_bps      - baseline_bps)      / baseline_bps      × 100
    Total PPS delta       = (peak_pps      - baseline_pps)      / baseline_pps      × 100
    Per-value share delta = (peak_share[v] - baseline_share[v]) / baseline_share[v] × 100

Edge cases:
    - Value not in baseline: delta = None  → rendered as "new (not in baseline)"
    - Value not in peak:     delta = -100%
    - Baseline rate is 0:    total delta = None
"""

from traffic_intel_agent.models.traffic_analysis import (
    BreakdownEntry,
    PeakBreakdown,
    PeakWindow,
    PooledBaseline,
)


class DeltaCalculator:
    """Compare peak breakdowns against the 6-day pooled baseline."""

    def __init__(self, baseline: PooledBaseline):
        self.baseline = baseline

    def _pct_delta(self, current: float, reference: float) -> float | None:
        """Compute percentage change; returns None when reference is 0."""
        if reference == 0:
            return None
        return (current - reference) / reference * 100

    def compute_total_deltas(self, peak: PeakWindow) -> tuple[float | None, float | None]:
        """Return (bps_delta_pct, pps_delta_pct) for a peak vs baseline."""
        bps_delta = self._pct_delta(peak.total_bps, self.baseline.baseline_bps)
        pps_delta = self._pct_delta(peak.total_pps, self.baseline.baseline_pps)
        return bps_delta, pps_delta

    def enrich_breakdown(self, breakdown: PeakBreakdown, peak: PeakWindow) -> PeakBreakdown:
        """Add baseline shares and deltas to each BreakdownEntry in place.

        Protocol names are case-normalised (lowered) for joining against
        the Cassandra baseline, which stores lowercase names (e.g. 'udp').

        Returns the same PeakBreakdown with delta fields populated.
        """
        # Total deltas
        bps_delta, pps_delta = self.compute_total_deltas(peak)
        breakdown.total_bps_delta_pct = bps_delta
        breakdown.total_pps_delta_pct = pps_delta

        # Per-dimension deltas
        self._enrich_entries(
            breakdown.by_protocol,
            self.baseline.protocol_shares,
            normalise_key=True,
        )
        self._enrich_entries(
            breakdown.by_dst_port,
            self.baseline.dst_port_shares,
        )
        self._enrich_entries(
            breakdown.by_sc,
            self.baseline.sc_shares,
        )
        # EtherType has no baseline data in Cassandra — leave deltas as None

        return breakdown

    def _enrich_entries(
        self,
        entries: list[BreakdownEntry],
        baseline_shares: dict[str, float],
        normalise_key: bool = False,
    ) -> None:
        """Populate baseline_share_pct and delta_pct on each entry.

        Parameters
        ----------
        entries : list[BreakdownEntry]
            The peak's breakdown entries for one dimension.
        baseline_shares : dict[str, float]
            The pooled baseline share for this dimension (0–1 scale).
        normalise_key : bool
            If True, lowercase the entry value before baseline lookup
            (for protocol name normalisation).
        """
        for entry in entries:
            lookup_key = entry.value.lower() if normalise_key else entry.value
            baseline_share = baseline_shares.get(lookup_key)

            if baseline_share is not None:
                entry.baseline_share_pct = baseline_share * 100
                # share_pct is already 0–100 scale; baseline_share is 0–1
                entry.delta_pct = self._pct_delta(
                    entry.share_pct / 100, baseline_share
                )
            else:
                # Value not in baseline → "new"
                entry.baseline_share_pct = None
                entry.delta_pct = None
