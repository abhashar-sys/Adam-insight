import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from ipaddress import ip_network
from unittest.mock import patch
from models import Customer
from tools.customer_api import (
    _matches_network,
    _format_customer,
    find_customer_context,
)


# ---------------------------------------------------------------------------
# _matches_network
# ---------------------------------------------------------------------------

class TestMatchesNetwork:
    def test_target_subnet_of_candidate(self):
        target = ip_network("10.0.1.0/24")
        assert _matches_network(target, "10.0.0.0/8") is True

    def test_candidate_subnet_of_target(self):
        # target broader than candidate should not match containment semantics
        target = ip_network("10.0.0.0/8")
        assert _matches_network(target, "10.0.1.0/24") is False

    def test_exact_match(self):
        target = ip_network("10.0.1.0/24")
        assert _matches_network(target, "10.0.1.0/24") is True

    def test_no_overlap(self):
        target = ip_network("10.0.1.0/24")
        assert _matches_network(target, "192.168.0.0/16") is False

    def test_invalid_cidr_returns_false(self):
        target = ip_network("10.0.1.0/24")
        assert _matches_network(target, "not-a-cidr") is False

    def test_host_address_in_cidr(self):
        target = ip_network("10.0.1.5/32")
        assert _matches_network(target, "10.0.0.0/8") is True

    def test_adjacent_but_non_overlapping_networks(self):
        target = ip_network("10.0.2.0/24")
        assert _matches_network(target, "10.0.1.0/24") is False


# ---------------------------------------------------------------------------
# _format_customer
# ---------------------------------------------------------------------------

class TestFormatCustomer:
    def _make_customer(self, **kwargs) -> Customer:
        defaults = dict(
            id=42,
            customer="acme",
            accountId="acc-1",
            accountName="Acme Corp",
            region="US-EAST",
            location="nyc1",
            inUse=True,
            networks=["10.0.0.0/8"],
            vips=[],
        )
        defaults.update(kwargs)
        return Customer(**defaults)

    def test_returns_all_expected_keys(self):
        customer = self._make_customer()
        result = _format_customer(customer, "10.0.0.0/8")
        assert set(result.keys()) == {
            "customer_id", "customer", "account_id", "account_name",
            "matched_cidr", "region", "location", "in_use",
        }

    def test_maps_fields_correctly(self):
        customer = self._make_customer()
        result = _format_customer(customer, "10.0.0.0/8")
        assert result["customer_id"] == 42
        assert result["customer"] == "acme"
        assert result["account_id"] == "acc-1"
        assert result["account_name"] == "Acme Corp"
        assert result["matched_cidr"] == "10.0.0.0/8"
        assert result["region"] == "US-EAST"
        assert result["location"] == "nyc1"
        assert result["in_use"] is True

    def test_optional_fields_can_be_none(self):
        customer = self._make_customer(accountId=None, accountName=None, region=None, location=None, inUse=None)
        result = _format_customer(customer, "10.0.0.0/8")
        assert result["account_id"] is None
        assert result["account_name"] is None
        assert result["region"] is None
        assert result["location"] is None
        assert result["in_use"] is None


# ---------------------------------------------------------------------------
# find_customer_context
# ---------------------------------------------------------------------------

def _make_customer(customer_id: int, name: str, networks: list[str]) -> Customer:
    return Customer(id=customer_id, customer=name, networks=networks, vips=[])


class TestFindCustomerContext:
    @patch("tools.customer_api.get_customers")
    def test_returns_empty_when_no_customers(self, mock_api):
        mock_api.return_value = []
        result = find_customer_context("10.0.1.0/24")
        assert result == []

    @patch("tools.customer_api.get_customers")
    def test_returns_empty_when_no_network_matches(self, mock_api):
        mock_api.return_value = [_make_customer(1, "acme", ["192.168.0.0/16"])]
        result = find_customer_context("10.0.1.0/24")
        assert result == []

    @patch("tools.customer_api.get_customers")
    def test_returns_matching_customer(self, mock_api):
        mock_api.return_value = [_make_customer(1, "acme", ["10.0.0.0/8"])]
        result = find_customer_context("10.0.1.0/24")
        assert len(result) == 1
        assert result[0]["customer"] == "acme"
        assert result[0]["matched_cidr"] == "10.0.0.0/8"

    @patch("tools.customer_api.get_customers")
    def test_returns_only_first_matching_cidr_per_customer(self, mock_api):
        # Customer has two CIDRs that both match; should only produce one entry
        customer = _make_customer(1, "acme", ["10.0.0.0/8", "10.0.1.0/24"])
        mock_api.return_value = [customer]
        result = find_customer_context("10.0.1.0/24")
        assert len(result) == 1

    @patch("tools.customer_api.get_customers")
    def test_returns_multiple_matching_customers(self, mock_api):
        mock_api.return_value = [
            _make_customer(1, "acme", ["10.0.0.0/8"]),
            _make_customer(2, "beta", ["10.0.1.0/24"]),
            _make_customer(3, "gamma", ["192.168.0.0/16"]),
        ]
        result = find_customer_context("10.0.1.0/24")
        names = {r["customer"] for r in result}
        assert names == {"acme", "beta"}

    @patch("tools.customer_api.get_customers")
    def test_customer_with_no_networks_is_skipped(self, mock_api):
        mock_api.return_value = [_make_customer(1, "acme", [])]
        result = find_customer_context("10.0.1.0/24")
        assert result == []

    @patch("tools.customer_api.get_customers")
    def test_host_route_matches_supernet(self, mock_api):
        mock_api.return_value = [_make_customer(1, "acme", ["10.0.0.0/8"])]
        result = find_customer_context("10.0.1.5/32")
        assert len(result) == 1
