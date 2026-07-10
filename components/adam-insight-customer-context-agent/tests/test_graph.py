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
    "mitigation_state": "ACTIVE",
    "event_id": "evt-1",
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
        assert result["customer_context"]["mitigation"]["mitigated_network"] == "10.0.0.0/8"

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
        assert ctx["mitigation"]["mitigated_network"] == "10.0.0.0/8"
        assert ctx["mitigation"]["mitigation_state"] == "ACTIVE"
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
            "mitigation_state": None,
            "locations": [],
        }
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        result = graph.invoke({"network": SAMPLE_NETWORK, "locations": SAMPLE_LOCATIONS})
        ctx = result["customer_context"]

        assert ctx["mitigation"] is None


class TestEndToEndFlow:
    """
    Comprehensive end-to-end test demonstrating complete data flow:
    INPUT (network + locations) → PROCESSING → OUTPUT (complete state)
    """

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_complete_flow_from_inputs_to_state(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """
        END-TO-END TEST: Complete flow from 3 inputs to final state
        
        Flow:
        1. INPUT: network = "10.0.1.0/24", locations = ["fll1", "ips9"]
        2. PROCESSING: Graph invokes customer_context_node
           - Looks up mitigation via Xiphos API
           - Looks up customers via Customer API
           - Looks up attack reports via Chakra-RS API
        3. OUTPUT: AgentState is updated with customer_context containing:
           - mitigation data
           - matching customers
           - attack reports for those customers
        """
        # Setup mocks for all 3 external dependencies
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.return_value = MOCK_ATTACK

        # INPUT: Initial state with network and locations
        input_state = {
            "network": SAMPLE_NETWORK,
            "locations": SAMPLE_LOCATIONS,
        }

        # PROCESSING: Invoke graph
        output_state = graph.invoke(input_state)

        # VALIDATION 1: Input fields are preserved
        assert output_state["network"] == SAMPLE_NETWORK
        assert output_state["locations"] == SAMPLE_LOCATIONS

        # VALIDATION 2: Customer context is populated
        assert "customer_context" in output_state
        customer_context = output_state["customer_context"]

        # VALIDATION 3: Mitigation section is complete
        assert customer_context["mitigation"] is not None
        mitigation = customer_context["mitigation"]
        assert mitigation["mitigated_network"] == "10.0.0.0/8"
        assert mitigation["mitigation_state"] == "ACTIVE"
        assert mitigation["event_customer"] == "acme"
        assert "account_name" not in mitigation
        assert "account_id" not in mitigation
        assert len(mitigation["locations"]) == 1
        assert mitigation["locations"][0]["location"] == "fll1"

        # VALIDATION 4: Customers section is complete
        assert customer_context["customers"]["error"] is None
        assert len(customer_context["customers"]["matches"]) == 1
        customer_match = customer_context["customers"]["matches"][0]
        assert customer_match["customer"] == "acme"
        assert customer_match["account_name"] == "Acme Corp"
        assert customer_match["matched_cidr"] == "10.0.0.0/8"

        # VALIDATION 5: Attack reports section is complete
        assert len(customer_context["attack_reports"]) == 1
        attack_report = customer_context["attack_reports"][0]
        assert attack_report["customer_name"] == "acme"
        assert attack_report["has_recent_attacks"] is False
        assert "historical_pattern" in attack_report
        assert "kept_events" in attack_report

        # Verify all mocks were called exactly once
        mock_mitigation.assert_called_once_with(SAMPLE_NETWORK, SAMPLE_LOCATIONS)
        mock_customer.assert_called_once_with(SAMPLE_NETWORK)
        mock_attack.assert_called_once()

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_e2e_multiple_customers_flow(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """
        END-TO-END TEST: Multiple customers found and all get attack reports
        
        Flow:
        INPUT (1 network) → Find 2 customers → Get attack reports for both
        """
        # Create mock data for 2 customers
        mock_customers_data = [
            {
                "customer_id": 1,
                "customer": "acme",
                "account_id": "acc-1",
                "account_name": "Acme Corp",
                "matched_cidr": "10.0.0.0/8",
            },
            {
                "customer_id": 2,
                "customer": "globex",
                "account_id": "acc-2",
                "account_name": "Globex Inc",
                "matched_cidr": "10.1.0.0/8",
            },
        ]

        mock_attack_reports = [
            {
                "customer_name": "acme",
                "kept_events": [
                    {
                        "event_id": 101,
                        "attack_id": 1001,
                        "start_time": "2026-06-24T10:00:00Z",
                        "end_time": "2026-06-24T10:15:00Z",
                        "attack_vectors": ["UDP Flood"],
                        "agr_peak_bps": 500000000,
                        "agr_peak_pps": 1000000,
                        "is_active_attack": False,
                        "mitigation_successful": True,
                        "non_mitigated_vectors": [],
                    }
                ],
                "has_recent_attacks": True,
                "message": "Recent attacks detected",
                "historical_pattern": {
                    "summary": "Recurring UDP flood attacks",
                    "vectors": {"dominant_vectors": [{"vector": "UDP Flood"}]},
                    "mitigation_effectiveness": {"success_rate_percent": 95},
                    "duration": {"ongoing_count": 0},
                },
                "chakra_rs_failure": False,
                "chakra_rs_errors": None,
            },
            {
                "customer_name": "globex",
                "kept_events": [],
                "has_recent_attacks": False,
                "message": "No recent attacks",
                "historical_pattern": {
                    "summary": "No attacks in 90 days",
                },
                "chakra_rs_failure": False,
                "chakra_rs_errors": None,
            },
        ]

        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = mock_customers_data
        mock_attack.side_effect = mock_attack_reports

        # INPUT: Network and locations
        result = graph.invoke({
            "network": SAMPLE_NETWORK,
            "locations": SAMPLE_LOCATIONS,
        })

        # VALIDATION: Both customers found
        customers = result["customer_context"]["customers"]["matches"]
        assert len(customers) == 2
        assert customers[0]["customer"] == "acme"
        assert customers[1]["customer"] == "globex"

        # VALIDATION: Attack reports generated for both
        attack_reports = result["customer_context"]["attack_reports"]
        assert len(attack_reports) == 2
        
        # VALIDATION: First customer has recent attacks
        assert attack_reports[0]["customer_name"] == "acme"
        assert attack_reports[0]["has_recent_attacks"] is True
        assert len(attack_reports[0]["kept_events"]) == 1
        assert attack_reports[0]["kept_events"][0]["agr_peak_bps"] == 500000000

        # VALIDATION: Second customer has no recent attacks
        assert attack_reports[1]["customer_name"] == "globex"
        assert attack_reports[1]["has_recent_attacks"] is False
        assert len(attack_reports[1]["kept_events"]) == 0

        # Verify attack lookup called for each customer
        assert mock_attack.call_count == 2

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_e2e_handles_partial_failures_gracefully(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """
        END-TO-END TEST: Graceful degradation when 1 or 2 services fail
        
        Flow:
        INPUT → Some services fail → OUTPUT still contains partial results
        """
        mock_mitigation.return_value = MOCK_MITIGATION
        mock_customer.return_value = MOCK_CUSTOMERS
        mock_attack.side_effect = Exception("Chakra-RS service unavailable")

        result = graph.invoke({
            "network": SAMPLE_NETWORK,
            "locations": SAMPLE_LOCATIONS,
        })

        ctx = result["customer_context"]

        # VALIDATION: Mitigation and customer data still available
        assert ctx["mitigation"]["mitigated_network"] == "10.0.0.0/8"
        assert len(ctx["customers"]["matches"]) == 1

        # VALIDATION: Attack reports contain error for the failed customer
        assert len(ctx["attack_reports"]) == 1
        assert ctx["attack_reports"][0]["chakra_rs_failure"] is True
        assert "chakra_rs_error" in ctx["attack_reports"][0]

    @patch("nodes.customer_context_node.find_attack_context")
    @patch("nodes.customer_context_node.find_customer_context")
    @patch("nodes.customer_context_node.find_mitigation_context")
    def test_e2e_all_services_fail_returns_valid_structure(
        self, mock_mitigation, mock_customer, mock_attack, graph
    ):
        """
        END-TO-END TEST: All 3 services fail but output structure remains valid
        
        Flow:
        INPUT → All services error → OUTPUT maintains consistent schema
        """
        mock_mitigation.side_effect = Exception("Xiphos down")
        mock_customer.side_effect = Exception("Customer API down")
        mock_attack.side_effect = Exception("Chakra-RS down")

        result = graph.invoke({
            "network": SAMPLE_NETWORK,
            "locations": SAMPLE_LOCATIONS,
        })

        # VALIDATION: Input preserved
        assert result["network"] == SAMPLE_NETWORK
        assert result["locations"] == SAMPLE_LOCATIONS

        # VALIDATION: Output structure is still present and valid
        ctx = result["customer_context"]
        assert "mitigation" in ctx
        assert "customers" in ctx
        assert "attack_reports" in ctx

        # VALIDATION: Errors are properly recorded
        assert "error" in ctx["mitigation"]
        assert "error" in ctx["customers"]
        assert ctx["customers"]["matches"] == []
        assert isinstance(ctx["attack_reports"], list)
