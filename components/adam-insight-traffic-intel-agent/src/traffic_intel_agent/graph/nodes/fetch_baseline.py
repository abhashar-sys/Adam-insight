"""Graph node: fetch the trailing 6-day baseline from Cassandra.

Reads : ``detection_target``, ``scrub_centers``
Writes: ``baseline``  (PooledBaseline)
"""

import logging

from traffic_intel_agent.models.traffic_analysis import TrafficIntelState
from traffic_intel_agent.repositories.cassandra_repo import CassandraRepository
from traffic_intel_agent.services.baseline_pooler import pool_baseline

logger = logging.getLogger(__name__)


def fetch_baseline(state: TrafficIntelState) -> dict:
    """Pull 6-day daily_profiles from Cassandra and pool into a baseline."""
    target = state["detection_target"]
    sc_names = state.get("scrub_centers", [])

    try:
        repo = CassandraRepository()
    except Exception as e:
        logger.error("Failed to connect to Cassandra: %s", e)
        return {"baseline": None}

    try:
        raw_profiles = repo.fetch_6_day_baseline(
            target_ip=target,
            locations=sc_names if sc_names else None,
        )
    except Exception as e:
        logger.error("Failed to fetch baseline for %s: %s", target, e)
        return {"baseline": None}
    finally:
        repo.close()

    if not raw_profiles:
        logger.warning("No baseline profiles found for %s", target)
        return {"baseline": None}

    baseline = pool_baseline(raw_profiles)
    logger.info(
        "Baseline for %s: %.2f Mbps, %.0f pps (%d days, %d profiles)",
        target,
        baseline.baseline_bps / 1e6,
        baseline.baseline_pps,
        baseline.num_days,
        len(raw_profiles),
    )

    return {"baseline": baseline}
