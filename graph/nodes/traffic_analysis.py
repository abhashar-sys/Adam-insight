from services.traffic_analyzer import PeakDetector
from repositories.clickhouse_repo import clickhouse_repo


def find_peaks(target_ip):
    """Fetch the last hour of traffic for *target_ip* and detect peaks.

    Returns
    -------
    list[dict]
        Top-N peaks, each {peak_id, start_ts, end_ts, total_bps, total_pps},
        sorted chronologically. Empty list when no data or no peaks.
    """
    repo = clickhouse_repo

    # find the data's actual time range for this target
    range_q = f"""SELECT min(time_received_ns), max(time_received_ns)
    FROM owl_bronze.sflowsPostmit
    WHERE dst_addr = '{target_ip}'"""
    range_rows = repo.query(range_q).result_rows

    if not range_rows or range_rows[0][0] is None:
        return []                       # no data for this target at all

    start_ns, end_ns = range_rows[0]

    # fetch the per-minute bps/pps curve, gaps zero-filled
    res = repo.query(repo.build_curve_query(target_ip, start_ns, end_ns + 1))
    if not res.result_rows:
        return []

    minutes = [row[0] for row in res.result_rows]
    bps     = [row[1] for row in res.result_rows]
    pps     = [row[2] for row in res.result_rows]

    # detect peaks for both metrics
    detector = PeakDetector(minutes, bps, pps)
    return {
        "bps_peaks": detector.detect(metric="bps"),
        "pps_peaks": detector.detect(metric="pps"),
    }
