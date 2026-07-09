from __future__ import annotations
from ipaddress import ip_network
from datetime import datetime,timedelta,timezone
from services.api_client import get_customer_attacks, get_attack_events
from collections import Counter
from statistics import mean

def _build_active_event_ids(active_attacks)->set:
    active_ids=set()
    for attack in active_attacks:
        for event_id in attack.events:
            active_ids.add(event_id)
    return active_ids

def _get_time_window():
    time_max=datetime.now(timezone.utc)
    time_min=time_max-timedelta(days=90)
    fmt="%Y-%m-%dT%H:%M:%SZ"
    return time_min.strftime(fmt),time_max.strftime(fmt)

def _covers_target(destination_ips,target_net)->bool:
    for dest in destination_ips:
        try:
            dest_cidr=ip_network(f"{dest.ipAddress}/{dest.netMask}",strict=False)
            if target_net.subnet_of(dest_cidr):
                return True
        except ValueError:
            continue
    return False

def _parse_time(time_str:str)->datetime:
    return datetime.strptime(time_str,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

def _compute_duration_hours(event:dict)->float|None:
    if not event.get("end_time"):
        return None
    start=_parse_time(event["start_time"])
    end=_parse_time(event["end_time"])
    return round((end-start).total_seconds()/3600,2)

def _analyse_recurrence(events:list[dict])->dict:
    start_times=sorted(_parse_time(e["start_time"]) for e in events)
    if len(start_times)<2:
        return {
            "total_attacks":len(events),
            "average_gap_days":None,
            "longest_quiet_period_days":None,
            "shortest_gap_days":None
        }
    gaps=[
        round((start_times[i]-start_times[i-1]).total_seconds()/86400,2)
        for i in range(1,len(start_times))
    ]
    return {
        "total_attacks":len(events),
        "average_gap_days":round(mean(gaps),2),
        "longest_quiet_period_days":max(gaps),
        "shortest_gap_days":min(gaps)
    }

def _analyse_vectors(events:list[dict])->dict:
    all_vectors=[v for e in events for v in e.get("attack_vectors",[])]
    if not all_vectors:
        return {"dominant_vectors":[],"vector_diversity":0}
    counts=Counter(all_vectors)
    total=len(all_vectors)
    return {
        "dominant_vectors":[
            {"vector":v,"occurrences":c,"share_percent":round(c/total*100,2)}
            for v,c in counts.most_common()
        ],
        "vector_diversity":len(counts)
    }

def _analyse_magnitude(events:list[dict])->dict:
    sorted_events=sorted(events,key=lambda e:e["start_time"])
    bps_values=[e["agr_peak_bps"] for e in sorted_events if e.get("agr_peak_bps")]
    pps_values=[e["agr_peak_pps"] for e in sorted_events if e.get("agr_peak_pps")]

    if not bps_values:
        return {"max_peak_bps":None,"average_peak_bps":None,"largest_attack_recent":None}
    midpoint=len(bps_values)//2
    recent_avg=mean(bps_values[midpoint:] or bps_values)
    overall_avg=mean(bps_values)

    return {
        "max_peak_bps":max(bps_values),
        "average_peak_bps":round(overall_avg,2),
        "max_peak_pps":max(pps_values) if pps_values else None,
        "largest_attack_recent":recent_avg>=overall_avg
    }

def _analyse_mitigation_effectiveness(events:list[dict])->dict:
    total=len(events)
    successful=sum(1 for e in events if e.get("mitigation_successful") is True)
    failed=sum(1 for e in events if e.get("mitigation_successful") is False)
    unknown=total-successful-failed
    recurring_unmitigated_vectors=Counter(
        v for e in events for v in e.get("non_mitigated_vectors", e.get("non_mitigation_vectors",[]))
    )
    return {
        "success_rate_percent":round(successful/total*100,1) if total else None,
        "successful_count":successful,
        "failed_count":failed,
        "unknown_outcome_count":unknown,
        "recurring_unmitigated_vectors":[v for v,_ in recurring_unmitigated_vectors.most_common(3)]
    }

def _analyse_duration(events:list[dict])->dict:
    durations=[_compute_duration_hours(e) for e in events]
    durations=[d for d in durations if d is not None]
    if not durations:
        return {"average_duration_hours":None,"longest_duration_hours":None}
    return {
        "average_duration_hours":round(mean(durations),2),
        "longest_duration_hours":max(durations),
        "ongoing_count":sum(1 for e in events if e.get("is_active_attack"))
    }

def analyse_historical_pattern(events:list[dict])->dict:
    if not events:
        return {
            "summary":"No historical attacks recorded against this network in the last 90 days",
            "recurrence":None,
            "vectors":None,
            "magnitude":None,
            "mitigation_effectiveness":None,
            "duration":None
        }
    recurrence=_analyse_recurrence(events)
    vectors=_analyse_vectors(events)
    magnitude=_analyse_magnitude(events)
    effectiveness=_analyse_mitigation_effectiveness(events)
    duration=_analyse_duration(events)
    top_vector=vectors["dominant_vectors"][0]["vector"] if vectors["dominant_vectors"] else "unknown"
    summary=(
        f"{recurrence['total_attacks']} attack(s) in the last 90 days "
        f"Dominant vector:{top_vector} ({vectors['vector_diversity']} distinct vector types seen) "
        f"Historical mitigation success rate:{effectiveness['success_rate_percent']}%"
        f"{duration['ongoing_count']} attack(s) currently ongoing"
    )
    return {
        "summary":summary,
        "recurrence":recurrence,
        "vectors":vectors,
        "magnitude":magnitude,
        "mitigation_effectiveness":effectiveness,
        "duration":duration
    }
def _interpret_success(success_statement)->bool|None:
    if not success_statement:
        return None
    description=(success_statement.successStatementDescription or "").lower()
    if "fail" in description or "not mitigated" in description:
        return False
    if "success" in description or "mitigated" in description:
        return True
    return None

def _format_event(event,active_event_ids)->dict:
    return {
        "event_id":event.id,
        "attack_id":event.attackId,
        "start_time":event.startTime,
        "end_time":event.endTime,
        "attack_vectors":[av.type for av in event.attackVectors],
        "agr_peak_bps":event.agrPeakBps,
        "agr_peak_pps":event.agrPeakPps,
        "is_active_attack":event.id in active_event_ids,
        "mitigation_successful":_interpret_success(event.successStatement),
        "non_mitigated_vectors":[v.get("type") for v in event.nonMitigatedAttackVectors]
    }

def find_attack_context(customer_id:int, customer_name:str, target_network:str)-> dict:
    target_net=ip_network(target_network, strict=False)
    active_event_ids=set()
    active_attacks_error=None
    attack_events_error=None

    try:
        active_attacks=get_customer_attacks(customer_id)
        active_event_ids=_build_active_event_ids(active_attacks)
    except Exception as e:
        active_attacks_error=str(e)

    time_min,time_max=_get_time_window()
    try:
        attack_events=get_attack_events(customer_name,time_min,time_max)
    except Exception as e:
        attack_events=[]
        attack_events_error=str(e)

    kept_events=[
        _format_event(event,active_event_ids)
        for event in attack_events
        if _covers_target(event.destinationIPs,target_net)
    ]
    historical_pattern=analyse_historical_pattern(kept_events)
    chakra_rs_failure=active_attacks_error is not None or attack_events_error is not None
    return {
        "customer_name":customer_name,
        "historical_pattern":historical_pattern,
        "kept_events":kept_events,
        "has_recent_attacks":len(kept_events)>0,
        "message":None if kept_events else "No recent attack events targeted this network",
        "chakra_rs_failure":chakra_rs_failure,
        "chakra_rs_errors":{
            "active_attacks_error":active_attacks_error,
            "attack_events_error":attack_events_error
        }

    }
    

def find_attack_context_for_all_customers(customers:list[dict],target_network:str)->list[dict]:
    if not customers:
        return []
    return [
        find_attack_context(c["customer_id"],c["customer"],target_network)
        for c in customers
    ]
    



