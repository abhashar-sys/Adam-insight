"""Peak detection and decomposition services.

PeakDetector  — scipy-powered peak-detection pipeline (10-second buckets).
PeakDecomposer — decomposes each peak into multi-dimensional views via ClickHouse.
"""

# pyrefly: ignore [missing-import]
import numpy as np
from datetime import timedelta

from traffic_intel_agent.config.constants import (
    MIN_GAP_BUCKETS, TOP_N, BUCKET_SECONDS,
    TUKEY_FENCE, FALLBACK_PERCENTILE,
)
from traffic_intel_agent.models.traffic_analysis import PeakWindow
# pyrefly: ignore [missing-import]
from scipy.signal import find_peaks, peak_widths  # noqa: E402


class PeakDetector:
    """End-to-end peak-detection pipeline using scipy.signal.find_peaks.

    The threshold used for peak prominence is **data-derived** via the
    IQR-based ``compute_threshold`` method (Tukey fence with a percentile
    fallback).  This value is passed directly to ``scipy.signal.find_peaks``
    as the ``prominence`` argument, so only peaks that rise significantly
    above the local baseline are retained.

    Parameters
    ----------
    timestamps : list[datetime]
        Bucket timestamps (10-second intervals).
    bps, pps : list[float]
        Corresponding bits-per-second and packets-per-second values.
    scope : str
        Label for the scope: ``"overall"`` or an SC name.

    Usage
    -----
        detector = PeakDetector(timestamps, bps, pps, scope="overall")
        peaks    = detector.detect(metric="bps")  # returns list[PeakWindow]
    """

    def __init__(self, timestamps, bps, pps, *,
                 scope: str = "overall",
                 min_gap: int = MIN_GAP_BUCKETS,
                 top_n: int = TOP_N,
                 bucket_seconds: int = BUCKET_SECONDS):
        self.timestamps = timestamps
        self.bps = bps
        self.pps = pps
        self.scope = scope
        self.min_gap = min_gap
        self.top_n = top_n
        self.bucket_seconds = bucket_seconds

    # ── 1. threshold (IQR-based) ─────────────────────────────────

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

    def pack_top_peaks(self, peak_indices, left_ips, right_ips, series, metric: str):
        """Turn detected peaks into the top-N typed PeakWindow objects.

        Parameters
        ----------
        peak_indices : array-like of int
            Indexes of the detected peaks in *series*.
        left_ips, right_ips : array-like of float
            Fractional left/right boundaries from ``peak_widths``.
        series : array-like
            The metric series used for ranking (bps or pps).
        metric : str
            ``"bps"`` or ``"pps"``.

        Returns
        -------
        list[PeakWindow]
        """
        if len(peak_indices) == 0:
            return []

        n_ts = len(self.timestamps)
        packed = []

        for i, pidx in enumerate(peak_indices):
            # Clamp fractional boundaries to valid indexes.
            left_idx  = max(0, int(np.floor(left_ips[i])))
            right_idx = min(n_ts - 1, int(np.ceil(right_ips[i])))

            packed.append({
                "start_ts":  self.timestamps[left_idx],
                "end_ts":    self.timestamps[right_idx] + timedelta(seconds=self.bucket_seconds),
                "total_bps": self.bps[pidx],
                "total_pps": self.pps[pidx],
                "_strength": series[pidx],
            })

        top = sorted(packed, key=lambda p: p["_strength"], reverse=True)[:self.top_n]
        top.sort(key=lambda p: p["start_ts"])

        peaks = []
        for n, p in enumerate(top, start=1):
            peaks.append(PeakWindow(
                peak_id=f"{self.scope}_{metric}_{n}",
                scope=self.scope,
                metric=metric,
                start_ts=p["start_ts"],
                end_ts=p["end_ts"],
                total_bps=p["total_bps"],
                total_pps=p["total_pps"],
            ))

        return peaks

    # ── full pipeline ────────────────────────────────────────────

    def detect(self, metric: str = "bps") -> list[PeakWindow]:
        """Run the complete peak-detection pipeline and return top peaks.

        Parameters
        ----------
        metric : str
            ``'bps'`` or ``'pps'`` — which series to threshold/rank on.

        Returns
        -------
        list[PeakWindow]
        """
        series = self.bps if metric == "bps" else self.pps

        peak_indices, left_ips, right_ips = self._find_peaks_scipy(series)
        return self.pack_top_peaks(peak_indices, left_ips, right_ips, series, metric)


class PeakDecomposer:
    """Decompose a detected peak into multiple traffic views using ClickHouse queries."""

    def __init__(self, target: str, device_ips: list[str] | None = None):
        from repositories.clickhouse_repo import ClickHouseRepository
        self.target = target
        self.device_ips = device_ips
        self.repo = ClickHouseRepository()

    def decompose(self, peak: PeakWindow) -> dict:
        """Return all views for one peak.

        Returns
        -------
        dict with keys: overall, by_sc, by_ethernet_type, by_protocol, by_port
            Each value is a list of dicts (one dict per row).
        """
        start_ns = int(peak.start_ts.timestamp() * 1_000_000_000)
        end_ns   = int(peak.end_ts.timestamp() * 1_000_000_000)

        return {
            "overall": self.repo.query_as_dicts(
                self.repo.build_overall_query(self.target, start_ns, end_ns, self.device_ips)),
            "by_sc": self.repo.query_as_dicts(
                self.repo.build_by_sc_query(self.target, start_ns, end_ns, self.device_ips)),
            "by_ethernet_type": self.repo.query_as_dicts(
                self.repo.build_by_ethernet_type_query(self.target, start_ns, end_ns, self.device_ips)),
            "by_protocol": self.repo.query_as_dicts(
                self.repo.build_by_protocol_query(self.target, start_ns, end_ns, self.device_ips)),
            "by_port": self.repo.query_as_dicts(
                self.repo.build_by_port_query(self.target, start_ns, end_ns, self.device_ips)),
        }
