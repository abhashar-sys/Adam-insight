from datetime import datetime, timedelta
from services.traffic_analyzer import PeakDetector


# ─── helpers ──────────────────────────────────────────────────────

def make_detector(minutes=None, bps=None, pps=None, **kwargs):
    """Build a PeakDetector; unused series default to empty."""
    return PeakDetector(
        minutes=minutes or [],
        bps=bps or [],
        pps=pps or [],
        **kwargs,
    )


def make_minutes(n):
    """n consecutive 1-minute timestamps starting at a fixed time."""
    base = datetime(2026, 6, 11, 8, 0, 0)
    return [base + timedelta(minutes=i) for i in range(n)]


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
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    # place a big spike at index 10
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(minutes=minutes, bps=bps, pps=pps)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert peaks[0]["total_bps"] == 5000
    assert peaks[0]["total_pps"] == 500
    assert peaks[0]["peak_id"] == 1


def test_detect_two_spikes_far_apart():
    """Two spikes separated by more than min_gap are both detected."""
    n = 30
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    bps[5] = 5000
    pps[5] = 500
    bps[20] = 4000
    pps[20] = 400

    d = make_detector(minutes=minutes, bps=bps, pps=pps, min_gap=3)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 2
    # peaks returned in time order
    assert peaks[0]["total_bps"] == 5000
    assert peaks[1]["total_bps"] == 4000
    assert peaks[0]["peak_id"] == 1
    assert peaks[1]["peak_id"] == 2


def test_detect_close_spikes_distance_keeps_stronger():
    """Two spikes within min_gap distance — find_peaks keeps only the stronger."""
    n = 20
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    # two spikes only 1 apart, min_gap=3 → only the stronger survives
    bps[10] = 5000
    pps[10] = 500
    bps[11] = 3000
    pps[11] = 300

    d = make_detector(minutes=minutes, bps=bps, pps=pps, min_gap=3)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert peaks[0]["total_bps"] == 5000


def test_detect_flat_baseline_no_peaks():
    """A perfectly flat series produces no peaks."""
    n = 20
    minutes = make_minutes(n)
    bps = [400] * n
    pps = [10] * n

    d = make_detector(minutes=minutes, bps=bps, pps=pps)
    peaks = d.detect(metric="bps")

    assert peaks == []


def test_detect_empty_series():
    """Empty input series produces no peaks."""
    d = make_detector(minutes=[], bps=[], pps=[])
    peaks = d.detect(metric="bps")
    assert peaks == []


def test_detect_uses_pps_metric():
    """detect(metric='pps') ranks by the pps series, not bps."""
    n = 20
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    # spike only in pps
    bps[10] = 100    # bps stays flat
    pps[10] = 5000   # pps spikes

    d = make_detector(minutes=minutes, bps=bps, pps=pps)
    peaks = d.detect(metric="pps")

    assert len(peaks) == 1
    assert peaks[0]["total_pps"] == 5000


# ─── output contract ─────────────────────────────────────────────

def test_detect_contract_shape():
    """Each peak dict has exactly the 5 required keys, no extras."""
    n = 20
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    bps[5] = 5000
    pps[5] = 500
    bps[15] = 4000
    pps[15] = 400

    d = make_detector(minutes=minutes, bps=bps, pps=pps, min_gap=3)
    peaks = d.detect(metric="bps")

    for peak in peaks:
        assert set(peak.keys()) == {
            "peak_id", "start_ts", "end_ts", "total_bps", "total_pps"
        }


def test_detect_peak_window_spans_multiple_minutes():
    """Peak start_ts < end_ts, spanning the width of the spike not just one minute."""
    n = 20
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(minutes=minutes, bps=bps, pps=pps)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 1
    assert peaks[0]["start_ts"] < peaks[0]["end_ts"]


def test_detect_top_n_limits_output():
    """When there are more peaks than top_n, only the strongest top_n survive."""
    n = 50
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    # place 5 well-separated spikes
    for idx, val in [(5, 5000), (15, 4000), (25, 3000), (35, 2000), (45, 1500)]:
        bps[idx] = val
        pps[idx] = val // 10

    d = make_detector(minutes=minutes, bps=bps, pps=pps, top_n=3, min_gap=3)
    peaks = d.detect(metric="bps")

    assert len(peaks) == 3
    # top 3 by strength: 5000, 4000, 3000
    strengths = [p["total_bps"] for p in peaks]
    assert sorted(strengths, reverse=True) == [5000, 4000, 3000]
    # returned in time order
    assert peaks[0]["peak_id"] == 1


def test_detect_fewer_than_top_n():
    """When fewer peaks exist than top_n, all are returned without error."""
    n = 20
    minutes = make_minutes(n)
    bps = [100] * n
    pps = [10] * n
    bps[10] = 5000
    pps[10] = 500

    d = make_detector(minutes=minutes, bps=bps, pps=pps, top_n=5)
    peaks = d.detect(metric="bps")

    assert len(peaks) <= 5
    assert len(peaks) >= 1