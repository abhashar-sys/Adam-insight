# pyrefly: ignore [missing-import]
import numpy as np
from datetime import timedelta
from config.constants import (
    MIN_GAP_MINUTES, TOP_N, BUCKET_MINUTES,
    TUKEY_FENCE, FALLBACK_PERCENTILE,
)
# pyrefly: ignore [missing-import]
from scipy.signal import find_peaks, peak_widths  # noqa: E402
class PeakDetector:
    """End-to-end peak-detection pipeline using scipy.signal.find_peaks.

    The threshold used for peak prominence is **data-derived** via the
    IQR-based ``compute_threshold`` method (Tukey fence with a percentile
    fallback).  This value is passed directly to ``scipy.signal.find_peaks``
    as the ``prominence`` argument, so only peaks that rise significantly
    above the local baseline are retained.

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

    # ── 1. threshold (IQR-based, kept as-is) ─────────────────────

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

    # ── 2. peak detection via scipy ──────────────────────────────

    def _find_peaks_scipy(self, series):
        """Detect peaks using scipy.signal.find_peaks.

        The data-derived IQR threshold is used as the ``prominence``
        parameter so only statistically significant spikes are returned.
        ``distance`` enforces the minimum gap between neighbouring peaks.

        Returns
        -------
        peak_indices : ndarray
            Indexes into *series* where peaks were found.
        left_ips, right_ips : ndarray
            Fractional index boundaries of each peak's width at half prominence,
            used to derive start_ts / end_ts.
        """

        arr = np.asarray(series, dtype=float)

        if arr.size == 0:
            return np.array([], dtype=int), np.array([]), np.array([])

        # Data-derived prominence threshold (IQR / Tukey fence).
        prominence = self.compute_threshold(arr.tolist())

        peak_indices, properties = find_peaks(
            arr,
            prominence=prominence,
            distance=self.min_gap,
        )

        if peak_indices.size == 0:
            return peak_indices, np.array([]), np.array([])

        # peak_widths at half-prominence gives us the start/end window.
        _, _, left_ips, right_ips = peak_widths(arr, peak_indices, rel_height=0.5)

        return peak_indices, left_ips, right_ips

    # ── 3. packing top peaks ─────────────────────────────────────

    def pack_top_peaks(self, peak_indices, left_ips, right_ips, series):
        """Turn detected peaks into the top-N output dicts.

        Parameters
        ----------
        peak_indices : array-like of int
            Indexes of the detected peaks in *series*.
        left_ips, right_ips : array-like of float
            Fractional left/right boundaries from ``peak_widths``.
        series : array-like
            The metric series used for ranking (bps or pps).

        Returns
        -------
        list[dict]
            Each dict has keys {peak_id, start_ts, end_ts, total_bps, total_pps}.
        """
        if len(peak_indices) == 0:
            return []

        n_minutes = len(self.minutes)
        packed = []

        for i, pidx in enumerate(peak_indices):
            # Clamp fractional boundaries to valid minute indexes.
            left_idx  = max(0, int(np.floor(left_ips[i])))
            right_idx = min(n_minutes - 1, int(np.ceil(right_ips[i])))

            packed.append({
                "start_ts":  self.minutes[left_idx],
                "end_ts":    self.minutes[right_idx] + timedelta(minutes=self.bucket_minutes),
                "total_bps": self.bps[pidx],
                "total_pps": self.pps[pidx],
                "_strength": series[pidx],
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

        peak_indices, left_ips, right_ips = self._find_peaks_scipy(series)
        return self.pack_top_peaks(peak_indices, left_ips, right_ips, series)


class PeakDecomposer:
    """Decompose a detected peak into multiple traffic views using ClickHouse queries."""

    def __init__(self, target_ip):
        from repositories.clickhouse_repo import clickhouse_repo
        self.target_ip = target_ip
        self.repo = clickhouse_repo

    def decompose_all_views(self, peak):
        """Return all four views for one peak.

        Returns
        -------
        dict with keys: overall, by_sc, by_protocol, by_port
            Each value is a list of dicts (one dict per row).
        """
        start_ns = int(peak["start_ts"].timestamp() * 1_000_000_000)
        end_ns   = int(peak["end_ts"].timestamp() * 1_000_000_000)

        return {
            "overall":     self.repo.query_as_dicts(
                self.repo.build_overall_query(self.target_ip, start_ns, end_ns)),
            "by_sc":       self.repo.query_as_dicts(
                self.repo.build_breakdown_query(self.target_ip, start_ns, end_ns)),
            "by_protocol": self.repo.query_as_dicts(
                self.repo.build_by_protocol_query(self.target_ip, start_ns, end_ns)),
            "by_port":     self.repo.query_as_dicts(
                self.repo.build_by_port_query(self.target_ip, start_ns, end_ns)),
        }
