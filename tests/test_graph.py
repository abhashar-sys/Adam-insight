import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch
from graph import build_graph


SAMPLE_NETWORK = "10.0.1.0/24"
SAMPLE_LOCATIONS = ["fll1", "ips9"]

MOCK_MITIGATION = {
    "matched_cidr": "10.0.0.0/8",
    "lifecycle_state": "ACTIVE",
    "event_id": "evt-1",
    "event_version": 1,
    "event_customer": "acme",
    "account_id": "acc-1",
    "account_name": "Acme Corp",
    "is_auto_mitigation": False,
    "locations": [{"location": "fll1", "isSuppressed": False, "functions": []}],
}

MOCK_CUSTOMERS = [
    {
        "customer_id": 1,
        "customer": "acme",
        "account_id": "acc-1",
        "account_name": "Acme Corp",
        "matched_cidr": "10.0.0.0/8",
        "region": "US-EAST",
        "location": "nyc1",
        "in_use": True,
    }
]

MOCK_ATTACK = {
    "customer_name": "acme",
    "kept_events": [],
    "has_recent_attacks": False,
    "message": "No recent attack events targeted this network",
    "historical_pattern": {
        "summary": "No historical attacks recorded against this network in the last 90 days",
        "recurrence": None,
        "vectors": None,
        "magnitude": None,
        "mitigation_effectiveness": None,
        "duration": None,
    },
}


@pytest.fixture
def graph():
    return build_graph()


class TestBuildGraph:
    def test_graph_compiles(self):
        g = build_graph()
        assert g is not None

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_graph_invoke_returns_customer_context_key(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        assert "customer_context" in result

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_customer_context_has_expected_sections(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]
        assert "mitigation" in ctx
        assert "customers" in ctx
        assert "attack_reports" in ctx

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_mitigation_section_contains_matched_cidr(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        assert result["customer_context"]["mitigation"]["matched_cidr"] == "10.0.0.0/8"

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_customers_section_contains_matches(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        matches = result["customer_context"]["customers"]["matches"]
        assert len(matches) == 1
        assert matches[0]["customer"] == "acme"

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_no_customers_returns_empty_matches_and_no_attacks(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = []

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]
        assert ctx["customers"]["matches"] == []
        assert ctx["attack_reports"] == []
        mock_attack.assert_not_called()

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_mitigation_error_reflected_in_output(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.side_effect = Exception("API timeout")
        mock_customer.return_value = []

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        assert "error" in result["customer_context"]["mitigation"]

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_input_state_fields_preserved(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        assert result["network"] == SAMPLE_NETWORK
        assert result["locations"] == SAMPLE_LOCATIONS
