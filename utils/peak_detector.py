# pyrefly: ignore [missing-import]
import numpy as np
from datetime import timedelta
from config.constants import (
    MIN_GAP_MINUTES, TOP_N, BUCKET_MINUTES,
    TUKEY_FENCE, FALLBACK_PERCENTILE,
)


class PeakDetector:
    """End-to-end peak-detection pipeline.

    Usage
    -----
        detector = PeakDetector(minutes, bps, pps)
        peaks    = detector.detect()   # returns list of peak dicts
    """

    def __init__(self, minutes, bps, pps, *,
                 min_gap=MIN_GAP_MINUTES,
                 top_n=TOP_N,
                 bucket_minutes=BUCKET_MINUTES):
        self.minutes = minutes
        self.bps = bps
        self.pps = pps
        self.min_gap = min_gap
        self.top_n = top_n
        self.bucket_minutes = bucket_minutes

    # ── 1. threshold ─────────────────────────────────────────────

    @staticmethod
    def compute_threshold(values):
        """Outlier cutoff derived from the data.

        Primary: Q3 + 1.5*IQR (Tukey fence).
        Fallback: when IQR is 0 (very repetitive baseline), use a high
        percentile so a flat baseline doesn't flag everything.
        """
        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1

        if iqr > 0:
            return q3 + TUKEY_FENCE * iqr

        # IQR collapsed — baseline too repetitive.
        median = np.percentile(values, 50)
        p95 = np.percentile(values, FALLBACK_PERCENTILE)
        spread = p95 - median
        if spread > 0:
            return median + spread

        # everything is identical → nothing can be an outlier
        return max(values) + 1

    # ── 2. filtering ─────────────────────────────────────────────

    @staticmethod
    def flag_outliers(values, threshold):
        """Return the positions (indexes) of all minutes above the threshold.

        values    : the metric series (bps or pps), one value per minute
        threshold : the cutoff from compute_threshold()
        Returns   : list of indexes where value > threshold
        """
        return [i for i in range(len(values)) if values[i] > threshold]

    # ── 3. grouping ──────────────────────────────────────────────

    @staticmethod
    def weld_events(flagged):
        """Group consecutive flagged positions into distinct events.

        flagged : list of indexes from flag_outliers (e.g. [2, 3, 4, 8])
        Returns : list of events, each event a list of consecutive indexes
                  (e.g. [[2, 3, 4], [8]])
        """
        if not flagged:
            return []

        events = []
        current = [flagged[0]]

        for idx in flagged[1:]:
            if idx == current[-1] + 1:
                current.append(idx)
            else:
                events.append(current)
                current = [idx]

        events.append(current)
        return events

    def enforce_min_gap(self, events, values):
        """Drop events that are too close to a stronger event already kept.

        events  : list of events (each a list of indexes) from weld_events
        values  : the metric series, used to measure each event's strength
        Returns : list of events that are far enough apart
        """
        if not events:
            return []

        def event_strength(event):
            return max(values[i] for i in event)

        events_by_strength = sorted(events, key=event_strength, reverse=True)

        kept = []
        for event in events_by_strength:
            event_peak_idx = max(event, key=lambda i: values[i])

            far_enough = all(
                abs(event_peak_idx - max(k, key=lambda i: values[i])) >= self.min_gap
                for k in kept
            )
            if far_enough:
                kept.append(event)

        return kept

    # ── 4. packing top peaks ─────────────────────────────────────

    def pack_top_peaks(self, events, series):
        """Turn distinct events into the top-N peaks in the output contract shape.

        events  : distinct events (lists of indexes) from enforce_min_gap
        series  : the metric series used for ranking (bps or pps)
        Returns : list of dicts {peak_id, start_ts, end_ts, total_bps, total_pps}
        """
        if not events:
            return []

        packed = []
        for event in events:
            peak_idx = max(event, key=lambda i: series[i])

            packed.append({
                "start_ts":  self.minutes[event[0]],
                "end_ts":    self.minutes[event[-1]] + timedelta(minutes=self.bucket_minutes),
                "total_bps": self.bps[peak_idx],
                "total_pps": self.pps[peak_idx],
                "_strength": series[peak_idx],
            })

        top = sorted(packed, key=lambda p: p["_strength"], reverse=True)[:self.top_n]
        top.sort(key=lambda p: p["start_ts"])

        for n, p in enumerate(top, start=1):
            p["peak_id"] = n
            del p["_strength"]

        return top

    # ── full pipeline ────────────────────────────────────────────

    def detect(self, metric="bps"):
        """Run the complete peak-detection pipeline and return top peaks.

        metric  : 'bps' or 'pps' — which series to threshold/rank on
        Returns : list of dicts {peak_id, start_ts, end_ts, total_bps, total_pps}
        """
        series = self.bps if metric == "bps" else self.pps

        threshold = self.compute_threshold(series)
        flagged   = self.flag_outliers(series, threshold)
        events    = self.weld_events(flagged)
        events    = self.enforce_min_gap(events, series)
        return self.pack_top_peaks(events, series)

