# utils/peak_decomposer.py
from tools.client import client
from tools.database.query_builder import (
    build_overall_query,
    build_breakdown_query,
    build_by_protocol_query,
    build_by_port_query,
)


class PeakDecomposer:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def decompose_all_views(self, peak):
        """Return all four views for one peak.

        Returns
        -------
        dict with keys: overall, by_sc, by_protocol, by_port
            Each value is a list of dicts (one dict per row).
        """
        start_ns = int(peak["start_ts"].timestamp() * 1_000_000_000)
        end_ns   = int(peak["end_ts"].timestamp() * 1_000_000_000)

        def run(query):
            res = client.query(query)
            cols = res.column_names
            return [dict(zip(cols, row)) for row in res.result_rows]

        return {
            "overall":     run(build_overall_query(self.target_ip, start_ns, end_ns)),
            "by_sc":       run(build_breakdown_query(self.target_ip, start_ns, end_ns)),
            "by_protocol": run(build_by_protocol_query(self.target_ip, start_ns, end_ns)),
            "by_port":     run(build_by_port_query(self.target_ip, start_ns, end_ns)),
        }