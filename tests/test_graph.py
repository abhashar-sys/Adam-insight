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


class TestErrorHandling:
    """Test error cases critical for LLM context reliability"""

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_customer_api_error_returns_error_key(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When customer lookup fails, error should be in customers section"""
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.side_effect = Exception("Customer API unavailable")
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        assert "error" in result["customer_context"]["customers"]
        assert result["customer_context"]["customers"]["matches"] == []

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_attack_context_error_per_customer(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When single customer's attack lookup fails, error should be captured per customer"""
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.side_effect = Exception("Chakra-RS timeout")

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        attack_reports = result["customer_context"]["attack_reports"]
        assert len(attack_reports) == 1
        assert attack_reports[0]["chakra_rs_failure"] is True
        assert "chakra_rs_error" in attack_reports[0]
        assert "attack lookup failed" in attack_reports[0]["chakra_rs_error"]

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_multiple_customers_with_partial_attack_failures(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When multiple customers found, but attack lookup fails for some"""
        mock_customers_multi = MOCK_CUSTOMERS + [
            {
                "customer_id": 2,
                "customer": "beta-corp",
                "account_id": "acc-2",
                "account_name": "Beta Corp",
                "matched_cidr": "10.1.0.0/8",
                "region": "US-WEST",
                "location": "sjc1",
                "in_use": True,
            }
        ]
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = mock_customers_multi
        mock_attack.side_effect = [MOCK_ATTACK, Exception("API error")]

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        attack_reports = result["customer_context"]["attack_reports"]
        assert len(attack_reports) == 2
        assert attack_reports[0].get("kept_events") is not None  # First succeeded
        assert attack_reports[1]["chakra_rs_failure"] is True  # Second failed

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_all_three_tools_fail_gracefully(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When all 3 tools fail, output structure should still be valid"""
        mock_mitigation.side_effect = Exception("Xiphos down")
        mock_customer.side_effect = Exception("Customer API down")
        mock_attack.side_effect = Exception("Chakra-RS down")

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]
        
        # Structure must remain consistent for LLM
        assert "error" in ctx["mitigation"]
        assert "error" in ctx["customers"]
        assert isinstance(ctx["attack_reports"], list)
        assert ctx["customers"]["matches"] == []

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_mitigation_success_with_customer_and_attack_failures(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """Partial success: Xiphos works but APIs fail - LLM still gets mitigation context"""
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.side_effect = Exception("Customer lookup failed")
        mock_attack.side_effect = Exception("Attack lookup failed")

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]
        
        # LLM should still get mitigation data
        assert ctx["mitigation"]["matched_cidr"] == "10.0.0.0/8"
        assert ctx["mitigation"]["lifecycle_state"] == "ACTIVE"
        # But customer data missing
        assert "error" in ctx["customers"]
        assert ctx["attack_reports"] == []

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_empty_locations_list(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """Empty locations list should still return valid context"""
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": []})
        ctx = result["customer_context"]
        assert "mitigation" in ctx
        assert "customers" in ctx

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_customer_not_found_returns_clean_empty_state(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When no customers match, output should signal 'not found' clearly"""
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = []
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]
        
        # Attack lookup should not be called if no customers
        mock_attack.assert_not_called()
        # But structure is still valid
        assert ctx["customers"]["error"] is None
        assert ctx["customers"]["matches"] == []
        assert ctx["attack_reports"] == []

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_mitigation_not_found_returns_null_state(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """When mitigation not found (but API succeeds), mitigation section should be absent"""
        mock_mitigation.return_value = {
            "matched_cidr": None,
            "lifecycle_state": None,
            "locations": [],
        }
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]

        assert ctx["mitigation"] is None
