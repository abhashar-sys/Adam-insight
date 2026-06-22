import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime, timezone
from ipaddress import ip_network
from unittest.mock import patch, MagicMock
from models import SingleAttack, AttackEvent, AttackVector, DestinationIP, SuccessStatement
from tools.chakra_rs import (
    _build_active_event_ids,
    _covers_target,
    _parse_time,
    _compute_duration_hours,
    _analyse_recurrence,
    _analyse_vectors,
    _analyse_magnitude,
    _analyse_mitigation_effectiveness,
    _analyse_duration,
    analyse_historical_pattern,
    _interpret_success,
    _format_event,
    find_attack_context,
    find_attack_context_for_all_customers,
)


# ---------------------------------------------------------------------------
# _build_active_event_ids
# ---------------------------------------------------------------------------

class TestBuildActiveEventIds:
    def test_empty_attacks(self):
        assert _build_active_event_ids([]) == set()

    def test_single_attack_single_event(self):
        attack = SingleAttack(id=1, customerId=10, startTime="2024-01-01T00:00:00Z", events=[42])
        assert _build_active_event_ids([attack]) == {42}

    def test_multiple_attacks_multiple_events(self):
        a1 = SingleAttack(id=1, customerId=10, startTime="2024-01-01T00:00:00Z", events=[1, 2])
        a2 = SingleAttack(id=2, customerId=10, startTime="2024-01-02T00:00:00Z", events=[3])
        assert _build_active_event_ids([a1, a2]) == {1, 2, 3}

    def test_deduplicates_event_ids(self):
        a1 = SingleAttack(id=1, customerId=10, startTime="2024-01-01T00:00:00Z", events=[5])
        a2 = SingleAttack(id=2, customerId=10, startTime="2024-01-02T00:00:00Z", events=[5])
        result = _build_active_event_ids([a1, a2])
        assert result == {5}


# ---------------------------------------------------------------------------
# _covers_target
# ---------------------------------------------------------------------------

def _make_dest(ip_address: str, net_mask: int) -> DestinationIP:
    return DestinationIP(id=1, ipAddress=ip_address, netMask=net_mask)


class TestCoversTarget:
    def test_destination_covers_target(self):
        target = ip_network("10.0.1.0/24")
        dest = _make_dest("10.0.0.0", 8)
        assert _covers_target([dest], target) is True

    def test_destination_does_not_cover_target(self):
        target = ip_network("10.0.1.0/24")
        dest = _make_dest("192.168.0.0", 16)
        assert _covers_target([dest], target) is False

    def test_empty_destination_list(self):
        target = ip_network("10.0.1.0/24")
        assert _covers_target([], target) is False

    def test_invalid_ip_is_skipped(self):
        target = ip_network("10.0.1.0/24")
        bad_dest = DestinationIP(id=2, ipAddress="not-an-ip", netMask=24)
        good_dest = _make_dest("10.0.0.0", 8)
        assert _covers_target([bad_dest, good_dest], target) is True

    def test_exact_match(self):
        target = ip_network("10.0.1.0/24")
        dest = _make_dest("10.0.1.0", 24)
        assert _covers_target([dest], target) is True

    def test_host_route_covered_by_supernet(self):
        target = ip_network("10.0.1.5/32")
        dest = _make_dest("10.0.0.0", 8)
        assert _covers_target([dest], target) is True


# ---------------------------------------------------------------------------
# _parse_time
# ---------------------------------------------------------------------------

class TestParseTime:
    def test_parses_valid_time_string(self):
        result = _parse_time("2024-01-15T10:30:00Z")
        assert result == datetime(2024, 1, 15, 10, 30, 0)

    def test_raises_on_invalid_format(self):
        with pytest.raises(ValueError):
            _parse_time("not-a-time")


# ---------------------------------------------------------------------------
# _compute_duration_hours
# ---------------------------------------------------------------------------

class TestComputeDurationHours:
    def test_returns_none_when_no_end_time(self):
        event = {"start_time": "2024-01-01T00:00:00Z", "end_time": None}
        assert _compute_duration_hours(event) is None

    def test_computes_correct_duration(self):
        event = {"start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-01T02:00:00Z"}
        assert _compute_duration_hours(event) == 2.0

    def test_fractional_hours_rounded(self):
        event = {"start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-01T01:30:00Z"}
        assert _compute_duration_hours(event) == 1.5

    def test_missing_end_time_key_returns_none(self):
        event = {"start_time": "2024-01-01T00:00:00Z"}
        assert _compute_duration_hours(event) is None


# ---------------------------------------------------------------------------
# _analyse_recurrence
# ---------------------------------------------------------------------------

class TestAnalyseRecurrence:
    def test_empty_events(self):
        result = _analyse_recurrence([])
        assert result["total_attacks"] == 0
        assert result["average_gap_days"] is None

    def test_single_event(self):
        events = [{"start_time": "2024-01-01T00:00:00Z"}]
        result = _analyse_recurrence(events)
        assert result["total_attacks"] == 1
        assert result["average_gap_days"] is None

    def test_two_events_one_day_apart(self):
        events = [
            {"start_time": "2024-01-01T00:00:00Z"},
            {"start_time": "2024-01-02T00:00:00Z"},
        ]
        result = _analyse_recurrence(events)
        assert result["total_attacks"] == 2
        assert result["average_gap_days"] == 1.0
        assert result["longest_quiet_period_days"] == 1.0
        assert result["shortest_gap_days"] == 1.0

    def test_multiple_events_statistics(self):
        events = [
            {"start_time": "2024-01-01T00:00:00Z"},
            {"start_time": "2024-01-04T00:00:00Z"},   # gap = 3 days
            {"start_time": "2024-01-06T00:00:00Z"},   # gap = 2 days
        ]
        result = _analyse_recurrence(events)
        assert result["total_attacks"] == 3
        assert result["average_gap_days"] == 2.5
        assert result["longest_quiet_period_days"] == 3.0
        assert result["shortest_gap_days"] == 2.0


# ---------------------------------------------------------------------------
# _analyse_vectors
# ---------------------------------------------------------------------------

class TestAnalyseVectors:
    def test_empty_events(self):
        result = _analyse_vectors([])
        assert result["dominant_vectors"] == []
        assert result["vector_diversity"] == 0

    def test_counts_vectors(self):
        events = [
            {"attack_vectors": ["UDP-FLOOD", "TCP-SYN"]},
            {"attack_vectors": ["UDP-FLOOD"]},
        ]
        result = _analyse_vectors(events)
        assert result["vector_diversity"] == 2
        assert result["dominant_vectors"][0]["vector"] == "UDP-FLOOD"
        assert result["dominant_vectors"][0]["occurrences"] == 2

    def test_share_percent_sums_to_100(self):
        events = [{"attack_vectors": ["A", "B"]}]
        result = _analyse_vectors(events)
        total = sum(v["share_percent"] for v in result["dominant_vectors"])
        assert round(total, 1) == 100.0

    def test_events_with_no_vectors(self):
        events = [{"attack_vectors": []}, {"attack_vectors": []}]
        result = _analyse_vectors(events)
        assert result["dominant_vectors"] == []
        assert result["vector_diversity"] == 0


# ---------------------------------------------------------------------------
# _analyse_magnitude
# ---------------------------------------------------------------------------

class TestAnalyseMagnitude:
    def test_empty_bps_values(self):
        result = _analyse_magnitude([{"start_time": "2024-01-01T00:00:00Z", "agr_peak_bps": None}])
        assert result["max_peak_bps"] is None
        assert result["average_peak_bps"] is None

    def test_computes_max_and_average_bps(self):
        events = [
            {"start_time": "2024-01-01T00:00:00Z", "agr_peak_bps": 100, "agr_peak_pps": 10},
            {"start_time": "2024-01-02T00:00:00Z", "agr_peak_bps": 200, "agr_peak_pps": 20},
        ]
        result = _analyse_magnitude(events)
        assert result["max_peak_bps"] == 200
        assert result["average_peak_bps"] == 150.0
        assert result["max_peak_pps"] == 20

    def test_largest_attack_recent_true_when_trend_up(self):
        # Later events (second half) have higher bps than first half
        events = [
            {"start_time": "2024-01-01T00:00:00Z", "agr_peak_bps": 100},
            {"start_time": "2024-01-02T00:00:00Z", "agr_peak_bps": 100},
            {"start_time": "2024-01-03T00:00:00Z", "agr_peak_bps": 300},
            {"start_time": "2024-01-04T00:00:00Z", "agr_peak_bps": 300},
        ]
        result = _analyse_magnitude(events)
        assert result["largest_attack_recent"] is True

    def test_pps_none_when_no_pps_values(self):
        events = [{"start_time": "2024-01-01T00:00:00Z", "agr_peak_bps": 100}]
        result = _analyse_magnitude(events)
        assert result["max_peak_pps"] is None


# ---------------------------------------------------------------------------
# _analyse_mitigation_effectiveness
# ---------------------------------------------------------------------------

class TestAnalyseMitigationEffectiveness:
    def test_all_successful(self):
        events = [{"mitigation_successful": True, "non_mitigation_vectors": []} for _ in range(4)]
        result = _analyse_mitigation_effectiveness(events)
        assert result["success_rate_percent"] == 100.0
        assert result["successful_count"] == 4
        assert result["failed_count"] == 0

    def test_all_failed(self):
        events = [{"mitigation_successful": False, "non_mitigation_vectors": []} for _ in range(3)]
        result = _analyse_mitigation_effectiveness(events)
        assert result["success_rate_percent"] == 0.0
        assert result["failed_count"] == 3

    def test_unknown_outcome_counted(self):
        events = [{"mitigation_successful": None, "non_mitigation_vectors": []}]
        result = _analyse_mitigation_effectiveness(events)
        assert result["unknown_outcome_count"] == 1
        assert result["success_rate_percent"] == 0.0

    def test_empty_events_returns_none_rate(self):
        result = _analyse_mitigation_effectiveness([])
        assert result["success_rate_percent"] is None

    def test_recurring_unmitigated_vectors_top_3(self):
        vectors = ["UDP"] * 5 + ["TCP"] * 3 + ["ICMP"] * 2 + ["HTTP"] * 1
        events = [{"mitigation_successful": False, "non_mitigation_vectors": [v]} for v in vectors]
        result = _analyse_mitigation_effectiveness(events)
        top3 = result["recurring_unmitigated_vectors"]
        assert len(top3) <= 3
        assert "UDP" in top3


# ---------------------------------------------------------------------------
# _analyse_duration
# ---------------------------------------------------------------------------

class TestAnalyseDuration:
    def test_no_events_with_end_time(self):
        events = [{"start_time": "2024-01-01T00:00:00Z", "end_time": None, "is_active_attack": True}]
        result = _analyse_duration(events)
        assert result["average_duration_hours"] is None
        assert result["longest_duration_hours"] is None

    def test_computes_average_and_longest(self):
        events = [
            {"start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-01T02:00:00Z", "is_active_attack": False},
            {"start_time": "2024-01-02T00:00:00Z", "end_time": "2024-01-02T04:00:00Z", "is_active_attack": False},
        ]
        result = _analyse_duration(events)
        assert result["average_duration_hours"] == 3.0
        assert result["longest_duration_hours"] == 4.0

    def test_ongoing_count(self):
        events = [
            {"start_time": "2024-01-01T00:00:00Z", "end_time": None, "is_active_attack": True},
            {"start_time": "2024-01-02T00:00:00Z", "end_time": "2024-01-02T01:00:00Z", "is_active_attack": False},
        ]
        result = _analyse_duration(events)
        assert result["ongoing_count"] == 1


# ---------------------------------------------------------------------------
# analyse_historical_pattern
# ---------------------------------------------------------------------------

class TestAnalyseHistoricalPattern:
    def test_empty_events_returns_no_history_message(self):
        result = analyse_historical_pattern([])
        assert "No historical" in result["summary"]
        assert result["recurrence"] is None
        assert result["vectors"] is None

    def test_non_empty_events_returns_all_sections(self):
        events = [{
            "start_time": "2024-01-01T00:00:00Z",
            "end_time": "2024-01-01T01:00:00Z",
            "attack_vectors": ["UDP-FLOOD"],
            "agr_peak_bps": 500,
            "agr_peak_pps": 50,
            "mitigation_successful": True,
            "non_mitigation_vectors": [],
            "is_active_attack": False,
        }]
        result = analyse_historical_pattern(events)
        assert result["recurrence"] is not None
        assert result["vectors"] is not None
        assert result["magnitude"] is not None
        assert result["mitigation_effectiveness"] is not None
        assert result["duration"] is not None
        assert "1 attack(s)" in result["summary"]


# ---------------------------------------------------------------------------
# _interpret_success
# ---------------------------------------------------------------------------

class TestInterpretSuccess:
    def test_none_returns_none(self):
        assert _interpret_success(None) is None

    def test_success_description(self):
        stmt = SuccessStatement(successStatementId=1, successStatementDescription="Fully mitigated")
        assert _interpret_success(stmt) is True

    def test_fail_description(self):
        stmt = SuccessStatement(successStatementId=2, successStatementDescription="Not mitigated")
        assert _interpret_success(stmt) is False

    def test_ambiguous_description_returns_none(self):
        stmt = SuccessStatement(successStatementId=3, successStatementDescription="Partial action taken")
        assert _interpret_success(stmt) is None

    def test_empty_description_returns_none(self):
        stmt = SuccessStatement(successStatementId=4, successStatementDescription="")
        assert _interpret_success(stmt) is None

    def test_no_description_returns_none(self):
        stmt = SuccessStatement(successStatementId=5)
        assert _interpret_success(stmt) is None


# ---------------------------------------------------------------------------
# _format_event
# ---------------------------------------------------------------------------

def _make_attack_event(**kwargs) -> AttackEvent:
    defaults = dict(
        id=1,
        attackId=10,
        startTime="2024-01-01T00:00:00Z",
        endTime=None,
        attackVectors=[],
        nonMitigatedAttackVectors=[],
        agrPeakBps=None,
        agrPeakPps=None,
        successStatement=None,
        destinationIPs=[],
    )
    defaults.update(kwargs)
    return AttackEvent(**defaults)


class TestFormatEvent:
    def test_basic_fields(self):
        event = _make_attack_event()
        result = _format_event(event, active_event_ids=set())
        assert result["event_id"] == 1
        assert result["attack_id"] == 10
        assert result["start_time"] == "2024-01-01T00:00:00Z"
        assert result["end_time"] is None
        assert result["is_active_attack"] is False

    def test_is_active_attack_true(self):
        event = _make_attack_event(id=99)
        result = _format_event(event, active_event_ids={99})
        assert result["is_active_attack"] is True

    def test_attack_vectors_extracted(self):
        vectors = [AttackVector(type="UDP-FLOOD", id=1), AttackVector(type="TCP-SYN", id=2)]
        event = _make_attack_event(attackVectors=vectors)
        result = _format_event(event, active_event_ids=set())
        assert result["attack_vectors"] == ["UDP-FLOOD", "TCP-SYN"]

    def test_mitigation_successful_mapped(self):
        stmt = SuccessStatement(successStatementId=1, successStatementDescription="Successfully mitigated")
        event = _make_attack_event(successStatement=stmt)
        result = _format_event(event, active_event_ids=set())
        assert result["mitigation_successful"] is True

    def test_non_mitigated_vectors_extracted(self):
        event = _make_attack_event(nonMitigatedAttackVectors=[{"type": "ICMP"}, {"type": "DNS"}])
        result = _format_event(event, active_event_ids=set())
        assert result["non_mitigated_vectors"] == ["ICMP", "DNS"]


# ---------------------------------------------------------------------------
# find_attack_context
# ---------------------------------------------------------------------------

class TestFindAttackContext:
    def _make_dest_ip(self, ip_address: str, net_mask: int) -> DestinationIP:
        return DestinationIP(id=1, ipAddress=ip_address, netMask=net_mask)

    def _make_event(self, dest_ip: DestinationIP, event_id: int = 1) -> AttackEvent:
        return AttackEvent(
            id=event_id,
            attackId=100,
            startTime="2024-01-01T00:00:00Z",
            endTime="2024-01-01T01:00:00Z",
            attackVectors=[AttackVector(type="UDP-FLOOD", id=1)],
            nonMitigatedAttackVectors=[],
            destinationIPs=[dest_ip],
        )

    @patch("tools.chakra_rs.get_attack_events")
    @patch("tools.chakra_rs.get_customer_attacks")
    def test_no_matching_events(self, mock_attacks, mock_events):
        mock_attacks.return_value = []
        mock_events.return_value = [
            self._make_event(self._make_dest_ip("192.168.0.0", 16))
        ]
        result = find_attack_context(1, "acme", "10.0.1.0/24")
        assert result["has_recent_attacks"] is False
        assert result["kept_events"] == []
        assert result["message"] is not None

    @patch("tools.chakra_rs.get_attack_events")
    @patch("tools.chakra_rs.get_customer_attacks")
    def test_matching_events_are_kept(self, mock_attacks, mock_events):
        mock_attacks.return_value = []
        mock_events.return_value = [
            self._make_event(self._make_dest_ip("10.0.0.0", 8), event_id=5)
        ]
        result = find_attack_context(1, "acme", "10.0.1.0/24")
        assert result["has_recent_attacks"] is True
        assert len(result["kept_events"]) == 1
        assert result["kept_events"][0]["event_id"] == 5
        assert result["message"] is None

    @patch("tools.chakra_rs.get_attack_events")
    @patch("tools.chakra_rs.get_customer_attacks")
    def test_active_attack_flag_propagated(self, mock_attacks, mock_events):
        active_attack = SingleAttack(
            id=1, customerId=10, startTime="2024-01-01T00:00:00Z", events=[5]
        )
        mock_attacks.return_value = [active_attack]
        mock_events.return_value = [
            self._make_event(self._make_dest_ip("10.0.0.0", 8), event_id=5)
        ]
        result = find_attack_context(1, "acme", "10.0.1.0/24")
        assert result["kept_events"][0]["is_active_attack"] is True


# ---------------------------------------------------------------------------
# find_attack_context_for_all_customers
# ---------------------------------------------------------------------------

class TestFindAttackContextForAllCustomers:
    def test_empty_customers_returns_empty(self):
        result = find_attack_context_for_all_customers([], "10.0.1.0/24")
        assert result == []

    @patch("tools.chakra_rs.find_attack_context")
    def test_calls_find_attack_context_per_customer(self, mock_find):
        mock_find.return_value = {"customer_name": "acme", "kept_events": []}
        customers = [
            {"customer_id": 1, "customer": "acme"},
            {"customer_id": 2, "customer": "beta"},
        ]
        result = find_attack_context_for_all_customers(customers, "10.0.1.0/24")
        assert mock_find.call_count == 2
        assert len(result) == 2
