"""Graph node: resolve scrub center names → device IPs (sampler_address).

Uses ``owl_gold.scrubCenterNetworks_dict`` via a ClickHouse scan to
reverse-map SC names to the device IPs that belong to each SC.

Reads : ``scrub_centers``
Writes: ``device_ips``  (dict[str, list[str]])
"""

import logging
from collections import defaultdict

from models.traffic_analysis import TrafficIntelState
from repositories.clickhouse_repo import ClickHouseRepository

logger = logging.getLogger(__name__)


def resolve_scrub_centers(state: TrafficIntelState) -> dict:
    """Map input SC names → device IPs via ClickHouse dict lookup."""
    sc_names = state.get("scrub_centers", [])

    if not sc_names:
        logger.info("No scrub centers specified; skipping resolution")
        return {"device_ips": {}}

    repo = ClickHouseRepository()
    sql = repo.build_resolve_sc_query(sc_names)

    try:
        rows = repo.query_as_dicts(sql)
    except Exception as e:
        logger.error("Failed to resolve scrub centers: %s", e)
        return {"device_ips": {}}

    device_ips: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        sc_name = row["sc_name"]
        sampler = row["sampler_address"]
        device_ips[sc_name].append(sampler)

    device_ips_dict = dict(device_ips)

    # Log what we resolved
    for sc, ips in device_ips_dict.items():
        logger.info("SC '%s' → %d device(s)", sc, len(ips))

    # Warn about any requested SCs that weren't found
    missing = set(sc_names) - set(device_ips_dict.keys())
    if missing:
        logger.warning("Scrub centers not found in data: %s", missing)

    return {"device_ips": device_ips_dict}
