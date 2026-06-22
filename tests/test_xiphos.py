import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from ipaddress import ip_network
from unittest.mock import patch, MagicMock
from models import MitigationNetworkEntry, MitigationItem, MitigationResponse
from tools.xiphos import (
    _network_cidr,
    _date_sort_key,
    _find_best_match,
    _extract_locations,
    _format_output,
    find_mitigation_context,
)


# ---------------------------------------------------------------------------
# _network_cidr
# ---------------------------------------------------------------------------

class TestNetworkCidr:
    def test_returns_network_when_present(self):
        entry = MitigationNetworkEntry(network="10.0.0.0/8")
        assert _network_cidr(entry) == "10.0.0.0/8"

    def test_network_takes_priority_over_prefix(self):
        entry = MitigationNetworkEntry(network="10.0.0.0/8", prefix="192.168.1.0/24")
        assert _network_cidr(entry) == "10.0.0.0/8"

    def test_returns_prefix_when_cidr_formatted_and_no_network(self):
        entry = MitigationNetworkEntry(prefix="192.168.1.0/24")
        assert _network_cidr(entry) == "192.168.1.0/24"

    def test_returns_none_when_prefix_is_plain_int(self):
        entry = MitigationNetworkEntry(prefix=12345)
        assert _network_cidr(entry) is None

    def test_returns_none_when_prefix_has_no_slash(self):
        entry = MitigationNetworkEntry(prefix="192.168.1.1")
        assert _network_cidr(entry) is None

    def test_returns_none_when_both_absent(self):
        entry = MitigationNetworkEntry()
        assert _network_cidr(entry) is None


# ---------------------------------------------------------------------------
# _date_sort_key
# ---------------------------------------------------------------------------

class TestDateSortKey:
    def test_none_returns_lowest_priority(self):
        assert _date_sort_key(None) == (0, 0)

    def test_integer_returns_numeric_tuple(self):
        assert _date_sort_key(1700000000) == (2, 1700000000)

    def test_float_is_truncated_to_int(self):
        assert _date_sort_key(1700000000.9) == (2, 1700000000)

    def test_numeric_string_returns_numeric_tuple(self):
        assert _date_sort_key("1700000000") == (2, 1700000000)

    def test_non_numeric_string_returns_string_tuple(self):
        key = _date_sort_key("2024-01-15T10:00:00Z")
        assert key == (1, "2024-01-15T10:00:00Z")

    def test_unknown_type_returns_lowest_priority(self):
        assert _date_sort_key([]) == (0, 0)

    def test_ordering_int_greater_than_string(self):
        # numeric epoch should sort higher than an ISO string
        assert _date_sort_key(1700000000) > _date_sort_key("2024-01-15T10:00:00Z")

    def test_ordering_string_greater_than_none(self):
        assert _date_sort_key("2024-01-15") > _date_sort_key(None)


# ---------------------------------------------------------------------------
# _find_best_match
# ---------------------------------------------------------------------------

def _make_item(cidr: str, start_date=None, item_id: str = "item-1") -> MitigationItem:
    entry = MitigationNetworkEntry(network=cidr)
    return MitigationItem(id=item_id, networks=[entry], startDate=start_date)


class TestFindBestMatch:
    def test_returns_none_when_no_items(self):
        target = ip_network("10.0.1.0/24")
        assert _find_best_match(target, []) is None

    def test_returns_none_when_no_subnet_match(self):
        target = ip_network("10.0.1.0/24")
        item = _make_item("192.168.0.0/16")
        assert _find_best_match(target, [item]) is None

    def test_returns_matching_item(self):
        target = ip_network("10.0.1.0/24")
        item = _make_item("10.0.0.0/8")
        result = _find_best_match(target, [item])
        assert result is not None
        assert result["item"] is item

    def test_prefers_longer_prefix(self):
        target = ip_network("10.0.1.0/24")
        broad = _make_item("10.0.0.0/8", item_id="broad")
        narrow = _make_item("10.0.1.0/16", item_id="narrow")
        result = _find_best_match(target, [broad, narrow])
        assert result["item"].id == "narrow"

    def test_tiebreaks_on_start_date(self):
        target = ip_network("10.0.1.0/24")
        older = _make_item("10.0.0.0/16", start_date=1000, item_id="older")
        newer = _make_item("10.0.0.0/16", start_date=2000, item_id="newer")
        result = _find_best_match(target, [older, newer])
        assert result["item"].id == "newer"

    def test_skips_entry_with_invalid_cidr(self):
        target = ip_network("10.0.1.0/24")
        bad_entry = MitigationNetworkEntry(network="not-a-cidr")
        good_entry = MitigationNetworkEntry(network="10.0.0.0/8")
        item = MitigationItem(id="x", networks=[bad_entry, good_entry])
        result = _find_best_match(target, [item])
        assert result is not None
        assert result["network_entry"] is good_entry

    def test_skips_entry_with_no_cidr_source(self):
        target = ip_network("10.0.1.0/24")
        entry = MitigationNetworkEntry()  # no network, no prefix
        item = MitigationItem(id="x", networks=[entry])
        assert _find_best_match(target, [item]) is None


# ---------------------------------------------------------------------------
# _extract_locations
# ---------------------------------------------------------------------------

def _make_network_entry_with_configs(configs: list) -> MitigationNetworkEntry:
    entry = MitigationNetworkEntry(network="10.0.0.0/8")
    entry.configs = configs
    return entry


class TestExtractLocations:
    def _sample_config(self, location: str, is_suppressed: bool = False):
        return {
            "functions": [{"function": "rate-limit", "config": {"rate": 100}}],
            "locations": [{"location": location, "isSuppressed": is_suppressed}],
        }

    def test_returns_empty_when_no_matching_locations(self):
        entry = _make_network_entry_with_configs([self._sample_config("nyc1")])
        result = _extract_locations(entry, ["fll1"])
        assert result == []

    def test_returns_matching_location(self):
        entry = _make_network_entry_with_configs([self._sample_config("fll1")])
        result = _extract_locations(entry, ["fll1"])
        assert len(result) == 1
        assert result[0]["location"] == "fll1"
        assert result[0]["isSuppressed"] is False

    def test_deduplicates_locations(self):
        config = self._sample_config("fll1")
        entry = _make_network_entry_with_configs([config, config])
        result = _extract_locations(entry, ["fll1"])
        assert len(result) == 1

    def test_returns_suppressed_flag_correctly(self):
        entry = _make_network_entry_with_configs([self._sample_config("fll1", is_suppressed=True)])
        result = _extract_locations(entry, ["fll1"])
        assert result[0]["isSuppressed"] is True

    def test_includes_functions_in_result(self):
        entry = _make_network_entry_with_configs([self._sample_config("fll1")])
        result = _extract_locations(entry, ["fll1"])
        assert result[0]["functions"] == [{"function": "rate-limit", "config": {"rate": 100}}]

    def test_returns_empty_when_no_configs(self):
        entry = MitigationNetworkEntry(network="10.0.0.0/8")
        result = _extract_locations(entry, ["fll1"])
        assert result == []

    def test_returns_multiple_distinct_locations(self):
        configs = [self._sample_config("fll1"), self._sample_config("ips9")]
        entry = _make_network_entry_with_configs(configs)
        result = _extract_locations(entry, ["fll1", "ips9"])
        locations = {r["location"] for r in result}
        assert locations == {"fll1", "ips9"}


# ---------------------------------------------------------------------------
# _format_output
# ---------------------------------------------------------------------------

class TestFormatOutput:
    def _sample_item(self) -> MitigationItem:
        return MitigationItem(
            id="evt-1",
            version=3,
            customer="acme",
            accountId="acc-123",
            accountName="Acme Corp",
            isAutoMitigation=True,
            state="ACTIVE",
        )

    def test_returns_expected_keys(self):
        item = self._sample_item()
        network_entry = MitigationNetworkEntry(network="10.0.0.0/8")
        location_details = [{"location": "fll1", "isSuppressed": False, "functions": []}]
        result = _format_output(item, network_entry, location_details)
        assert set(result.keys()) == {
            "matched_cidr", "lifecycle_state", "event_id", "event_version",
            "event_customer", "account_id", "account_name", "is_auto_mitigation", "locations",
        }

    def test_matched_cidr_is_normalized(self):
        item = self._sample_item()
        entry = MitigationNetworkEntry(network="10.0.1.5/8")  # host bits set
        result = _format_output(item, entry, [])
        assert result["matched_cidr"] == "10.0.0.0/8"

    def test_matched_cidr_none_when_no_cidr(self):
        item = self._sample_item()
        entry = MitigationNetworkEntry()
        result = _format_output(item, entry, [])
        assert result["matched_cidr"] is None

    def test_maps_item_fields_correctly(self):
        item = self._sample_item()
        entry = MitigationNetworkEntry(network="10.0.0.0/8")
        result = _format_output(item, entry, [])
        assert result["lifecycle_state"] == "ACTIVE"
        assert result["event_id"] == "evt-1"
        assert result["event_version"] == 3
        assert result["event_customer"] == "acme"
        assert result["account_id"] == "acc-123"
        assert result["account_name"] == "Acme Corp"
        assert result["is_auto_mitigation"] is True


# ---------------------------------------------------------------------------
# find_mitigation_context (integration with mocked API)
# ---------------------------------------------------------------------------

class TestFindMitigationContext:
    def _make_response(self, items):
        return MitigationResponse(items=items)

    @patch("tools.xiphos.get_mitigation_events")
    def test_returns_empty_result_when_no_match(self, mock_api):
        mock_api.return_value = self._make_response([_make_item("192.168.0.0/16")])
        result = find_mitigation_context("10.0.1.0/24", ["fll1"])
        assert result["matched_cidr"] is None
        assert result["lifecycle_state"] is None
        assert result["locations"] == []

    @patch("tools.xiphos.get_mitigation_events")
    def test_returns_matched_result(self, mock_api):
        item = MitigationItem(
            id="evt-1",
            state="ACTIVE",
            networks=[MitigationNetworkEntry(
                network="10.0.0.0/8",
                configs=[{
                    "functions": [],
                    "locations": [{"location": "fll1", "isSuppressed": False}],
                }]
            )],
        )
        mock_api.return_value = self._make_response([item])
        result = find_mitigation_context("10.0.1.0/24", ["fll1"])
        assert result["matched_cidr"] == "10.0.0.0/8"
        assert result["lifecycle_state"] == "ACTIVE"
        assert any(loc["location"] == "fll1" for loc in result["locations"])

    @patch("tools.xiphos.get_mitigation_events")
    def test_returns_empty_result_when_no_items(self, mock_api):
        mock_api.return_value = self._make_response([])
        result = find_mitigation_context("10.0.1.0/24", ["fll1"])
        assert result["matched_cidr"] is None

    @patch("tools.xiphos.get_mitigation_events")
    def test_requested_locations_not_present_returns_empty_locations(self, mock_api):
        item = MitigationItem(
            id="evt-2",
            state="ACTIVE",
            networks=[MitigationNetworkEntry(
                network="10.0.0.0/8",
                configs=[{
                    "functions": [],
                    "locations": [{"location": "nyc1", "isSuppressed": False}],
                }]
            )],
        )
        mock_api.return_value = self._make_response([item])
        result = find_mitigation_context("10.0.1.0/24", ["fll1"])
        assert result["locations"] == []
