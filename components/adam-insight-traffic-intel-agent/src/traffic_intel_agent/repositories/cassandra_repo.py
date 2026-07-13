"""Cassandra data access — daily baseline profile fetcher."""

import json
import logging
from datetime import datetime, timedelta, timezone

# pyrefly: ignore [missing-import]
from cassandra.cluster import Cluster
# pyrefly: ignore [missing-import]
from cassandra.query import PreparedStatement

from traffic_intel_agent.config.settings import (
    CASSANDRA_CONTACT_POINTS,
    CASSANDRA_PORT,
    CASSANDRA_KEYSPACE,
)
from traffic_intel_agent.config.constants import TRAILING_BASELINE_DAYS

logger = logging.getLogger(__name__)


class CassandraRepository:
    """Manages connection and queries against Cassandra's touchstone_ks."""

    def __init__(
        self,
        contact_points: list[str] | None = None,
        port: int | None = None,
    ):
        """Connect to Cassandra using configured or overridden settings."""
        contact_points = contact_points or CASSANDRA_CONTACT_POINTS
        port = port or CASSANDRA_PORT

        self.cluster = Cluster(contact_points, port=port)
        self.session = self.cluster.connect(CASSANDRA_KEYSPACE)

        # Prepared statement for 6-day baseline lookup
        self.profile_stmt: PreparedStatement = self.session.prepare(
            """
            SELECT location, profile_data, profile_ts
            FROM touchstone_ks.daily_profiles
            WHERE destination = ?
              AND data_type = ?
              AND profile_ts >= ?
            ALLOW FILTERING
            """
        )
        logger.info("Connected to Cassandra at %s:%s", contact_points, port)

    def fetch_6_day_baseline(
        self,
        target_ip: str,
        locations: list[str] | None = None,
        mock_today: datetime | None = None,
    ) -> list[dict]:
        """Pull raw baseline JSONs for the target IP over the trailing window.

        Parameters
        ----------
        target_ip : str
            The detection target (destination column in Cassandra).
        locations : list[str] | None
            If provided, only return profiles matching these location values
            (scrub center names).  An empty-string location (``''``) is the
            "overall" row and is always included.
        mock_today : datetime | None
            Override ``now()`` for testing with historical local data.

        Returns
        -------
        list[dict]
            Each entry: ``{"location": str, "profile_ts": datetime, "data": dict}``
        """
        raw_profiles: list[dict] = []
        data_types = ['border_flow', 'access_flow']

        now = mock_today or datetime.now(timezone.utc)
        cutoff_date = now - timedelta(days=TRAILING_BASELINE_DAYS)

        for dt in data_types:
            try:
                rows = self.session.execute(
                    self.profile_stmt, [target_ip, dt, cutoff_date]
                )

                for row in rows:
                    # Optionally filter by location (SC name)
                    if locations is not None:
                        # Always include the overall row (empty location)
                        if row.location and row.location not in locations:
                            continue

                    try:
                        parsed_data = json.loads(row.profile_data)
                        raw_profiles.append({
                            "location": row.location,
                            "profile_ts": row.profile_ts,
                            "data": parsed_data,
                        })
                    except json.JSONDecodeError:
                        logger.warning(
                            "Corrupted JSON in Cassandra for %s at location '%s'",
                            target_ip, row.location,
                        )
                        continue

            except Exception as e:
                logger.error("Cassandra query failed for %s (%s): %s", target_ip, dt, e)

        return raw_profiles

    def close(self):
        """Shutdown the connection cleanly."""
        self.cluster.shutdown()