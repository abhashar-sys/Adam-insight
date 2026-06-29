"""Tests for PeakDetector with 10-second bucket granularity."""

from datetime import datetime, timedelta
from services.traffic_analyzer import PeakDetector
from models.traffic_analysis import PeakWindow


# ─── helpers ──────────────────────────────────────────────────────

def make_detector(timestamps=None, bps=None, pps=None, **kwargs):
    """Build a PeakDetector; unused series default to empty."""
    return PeakDetector(
        timestamps=timestamps or [],
        bps=bps or [],
        pps=pps or [],
        **kwargs,
    )


def make_timestamps(n):
    """n consecutive 10-second timestamps starting at a fixed time."""
    base = datetime(2026, 6, 11, 8, 0, 0)
    return [base + timedelta(seconds=10 * i) for i in range(n)]


# ─── compute_threshold (unchanged) ───────────────────────────────

def test_threshold_normal_spread():
    # clear baseline with one spike → threshold sits above the baseline
    values = [400, 400, 400, 400, 2000]
    threshold = PeakDetector.compute_threshold(values)
    assert 400 < threshold < 2000          # baseline passes, spike flagged


def test_threshold_flat_baseline_fallback():
    # all identical → IQR is 0, fallback returns max+1 so nothing is an outlier
    values = [400, 400, 400, 400]
    threshold = PeakDetector.compute_threshold(values)
    assert threshold >= 400                 # no value can exceed it


# ─── detect() — full scipy pipeline ──────────────────────────────

def test_detect_single_spike():
    """A single prominent spike in a flat baseline is detected."""
    n = 20
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    # place a big spike at index 10
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, scope="overall")
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert isinstance(peaks[0], PeakWindow)
    assert peaks[0].total_bps == 5000
    assert peaks[0].total_pps == 500
    assert peaks[0].peak_id == "overall_bps_1"
    assert peaks[0].scope == "overall"
    assert peaks[0].metric == "bps"


def test_detect_two_spikes_far_apart():
    """Two spikes separated by more than min_gap are both detected."""
    n = 60  # 60 × 10s = 10 minutes
    timestamps = make_timestamps(n)
    # Use varied baseline so IQR > 0 and Tukey fence is meaningful
    bps = [100 + (i % 5) * 20 for i in range(n)]  # 100–180 range
    pps = [10 + (i % 5) * 2 for i in range(n)]
    bps[10] = 5000
    pps[10] = 500
    bps[40] = 4000
    pps[40] = 400

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, min_gap=12, scope="test_sc")
    peaks = d.detect(metric="bps")

    assert len(peaks) == 2
    # peaks returned in time order
    assert peaks[0].total_bps == 5000
    assert peaks[1].total_bps == 4000
    assert peaks[0].peak_id == "test_sc_bps_1"
    assert peaks[1].peak_id == "test_sc_bps_2"


def test_detect_close_spikes_distance_keeps_stronger():
    """Two spikes within min_gap distance — find_peaks keeps only the stronger."""
    n = 30
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    # two spikes only 1 apart, min_gap=12 → only the stronger survives
    bps[10] = 5000
    pps[10] = 500
    bps[11] = 3000
    pps[11] = 300

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, min_gap=12)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert peaks[0].total_bps == 5000


def test_detect_flat_baseline_no_peaks():
    """A perfectly flat series produces no peaks."""
    n = 20
    timestamps = make_timestamps(n)
    bps = [400] * n
    pps = [10] * n

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps)
    peaks = d.detect(metric="bps")

    assert peaks == []


def test_detect_empty_series():
    """Empty input series produces no peaks."""
    d = make_detector(timestamps=[], bps=[], pps=[])
    peaks = d.detect(metric="bps")
    assert peaks == []


def test_detect_uses_pps_metric():
    """detect(metric='pps') ranks by the pps series, not bps."""
    n = 20
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    # spike only in pps
    bps[10] = 100    # bps stays flat
    pps[10] = 5000   # pps spikes

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps)
    peaks = d.detect(metric="pps")

    assert len(peaks) == 1
    assert peaks[0].total_pps == 5000
    assert peaks[0].metric == "pps"


# ─── output contract ─────────────────────────────────────────────

def test_detect_contract_shape():
    """Each peak is a PeakWindow with all required fields."""
    n = 30
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    bps[5] = 5000
    pps[5] = 500
    bps[25] = 4000
    pps[25] = 400

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, min_gap=12)
    peaks = d.detect(metric="bps")

    for peak in peaks:
        assert isinstance(peak, PeakWindow)
        assert peak.peak_id
        assert peak.scope
        assert peak.metric == "bps"
        assert peak.start_ts
        assert peak.end_ts
        assert peak.total_bps > 0
        assert peak.total_pps > 0


def test_detect_peak_window_spans_time():
    """Peak start_ts < end_ts, spanning the width of the spike."""
    n = 20
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert peaks[0].start_ts < peaks[0].end_ts


def test_detect_top_n_limits_output():
    """When there are more peaks than top_n, only the strongest top_n survive."""
    n = 120  # 120 × 10s = 20 minutes
    timestamps = make_timestamps(n)
    # Use varied baseline so IQR > 0
    bps = [100 + (i % 5) * 20 for i in range(n)]
    pps = [10 + (i % 5) * 2 for i in range(n)]
    # place 5 well-separated spikes (gap > 12 buckets)
    for idx, val in [(10, 5000), (30, 4000), (50, 3000), (70, 2000), (90, 1500)]:
        bps[idx] = val
        pps[idx] = val // 10

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, top_n=3, min_gap=12)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 3
    # top 3 by strength: 5000, 4000, 3000
    strengths = [p.total_bps for p in peaks]
    assert sorted(strengths, reverse=True) == [5000, 4000, 3000]


def test_detect_fewer_than_top_n():
    """When fewer peaks exist than top_n, all are returned without error."""
    n = 20
    timestamps = make_timestamps(n)
    bps = [100] * n
    pps = [10] * n
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(timestamps=timestamps, bps=bps, pps=pps, top_n=5)
    peaks = d.detect(metric="bps")

    assert len(peaks) <= 5
    assert len(peaks) >= 1