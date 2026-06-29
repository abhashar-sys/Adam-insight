import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

from app import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@patch("app.customer_context_node")
def test_customer_context_node_endpoint(mock_node):
    mock_node.return_value = {
        "network": "10.0.1.0/24",
        "locations": ["fll1"],
        "customer_context": {
            "mitigation": None,
            "customers": {"error": None, "matches": []},
            "attack_reports": [],
        },
    }

    response = client.post(
        "/nodes/customer-context",
        json={"network": "10.0.1.0/24", "locations": ["fll1"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert "customer_context" in body
    assert body["customer_context"]["customers"]["matches"] == []


@patch("app.graph")
def test_graph_invoke_endpoint(mock_graph):
    graph_result = {
        "network": "10.0.1.0/24",
        "locations": ["fll1", "ips9"],
        "customer_context": {
            "mitigation": {"matched_cidr": "10.0.0.0/8"},
            "customers": {"error": None, "matches": []},
            "attack_reports": [],
        },
    }

    graph_mock = Mock()
    graph_mock.invoke.return_value = graph_result
    mock_graph.invoke = graph_mock.invoke

    response = client.post(
        "/graph/invoke",
        json={"network": "10.0.1.0/24", "locations": ["fll1", "ips9"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["network"] == "10.0.1.0/24"
    assert body["locations"] == ["fll1", "ips9"]
    assert body["customer_context"]["mitigation"]["matched_cidr"] == "10.0.0.0/8"
