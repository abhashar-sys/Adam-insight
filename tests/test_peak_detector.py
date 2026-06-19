from datetime import datetime, timedelta
from utils.peak_detector import PeakDetector


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


# ─── compute_threshold ────────────────────────────────────────────

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


# ─── flag_outliers ────────────────────────────────────────────────

def test_flag_outliers_basic():
    # only 1600 (index 1) is above 500
    assert PeakDetector.flag_outliers([400, 1600, 400], 500) == [1]


def test_flag_outliers_none_above():
    assert PeakDetector.flag_outliers([100, 200, 300], 500) == []


# ─── weld_events (the anti-trap mechanism) ────────────────────────

def test_weld_consecutive():
    # 2,3,4 adjacent → ONE event; 8 separate → another
    assert PeakDetector.weld_events([2, 3, 4, 8]) == [[2, 3, 4], [8]]


def test_weld_all_separate():
    assert PeakDetector.weld_events([1, 5, 9]) == [[1], [5], [9]]


def test_weld_all_together():
    assert PeakDetector.weld_events([4, 5, 6]) == [[4, 5, 6]]


def test_weld_empty():
    assert PeakDetector.weld_events([]) == []


# ─── enforce_min_gap ──────────────────────────────────────────────

def test_min_gap_drops_close_weaker_event():
    # peaks at index 3 (strong) and 4 (weak), gap 1 < min_gap 2 → weak dropped
    values = [0, 0, 0, 1600, 900, 0]
    d = make_detector(bps=values, min_gap=2)
    result = d.enforce_min_gap([[3], [4]], values)
    assert result == [[3]]


def test_min_gap_keeps_far_apart_events():
    # peaks far apart → both kept
    values = [0] * 25
    values[3] = 1600
    values[20] = 1200
    d = make_detector(bps=values, min_gap=2)
    result = d.enforce_min_gap([[3], [20]], values)
    assert len(result) == 2


def test_min_gap_empty():
    d = make_detector(min_gap=2)
    assert d.enforce_min_gap([], []) == []


# ─── pack_top_peaks ───────────────────────────────────────────────

def test_pack_contract_shape():
    minutes = make_minutes(5)
    bps = [400, 1600, 400, 900, 400]
    pps = [10, 50, 10, 30, 10]
    d = make_detector(minutes=minutes, bps=bps, pps=pps)

    result = d.pack_top_peaks([[1], [3]], bps)

    # two peaks, exact contract keys, no leaked _strength
    assert len(result) == 2
    assert set(result[0].keys()) == {
        "peak_id", "start_ts", "end_ts", "total_bps", "total_pps"
    }


def test_pack_ranks_and_limits_to_top_n():
    minutes = make_minutes(6)
    bps = [100, 200, 300, 400, 500, 600]
    pps = [0] * 6
    # six single-index events, top_n=3 → only the 3 biggest survive
    d = make_detector(minutes=minutes, bps=bps, pps=pps, top_n=3)
    events = [[0], [1], [2], [3], [4], [5]]

    result = d.pack_top_peaks(events, bps)
    assert len(result) == 3                              # limited to top 3
    # they come back in TIME order (peak_id 1 is earliest of the kept)
    assert result[0]["peak_id"] == 1


def test_pack_empty():
    d = make_detector()
    assert d.pack_top_peaks([], []) == []