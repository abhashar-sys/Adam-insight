# pyrefly: ignore [missing-import]
import clickhouse_connect

from config.settings import (
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USERNAME,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_DATABASE,
)


def create_client():
    """Create a ClickHouse client using settings from config.settings."""
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USERNAME,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )


client = create_client()