from ipaddress import ip_network
from datetime import datetime,timedelta,timezone
from services.api_client import get_customer_attacks, get_attack_events

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

def _format_event(event,active_event_ids)->dict:
    return {
        "event_id":event.id,
        "attack_id":event.attackId,
        "start_time":event.startTime,
        "end_time":event.endTime,
        "attack_vectors":[av.dict() for av in event.attackVectors],
        "agr_peak_bps":event.agrPeakBps,
        "agr_peak_pps":event.agrPeakPps,
        "akamai_case_id":event.akamaiCaseId,
        "is_active_attack":event.id in active_event_ids
    }

def find_attack_context(customer_id:int, customer_name:str, target_network:str)-> dict:
    target_net=ip_network(target_network, strict=False)
    active_attacks=get_customer_attacks(customer_id)
    active_event_ids=_build_active_event_ids(active_attacks)
    time_min,time_max=_get_time_window()
    attack_events=get_attack_events(customer_name,time_min,time_max)
    kept_events=[
        _format_event(event,active_event_ids)
        for event in attack_events
        if _covers_target(event.destinationIPs,target_net)
    ]
    return {
        "customer_id":customer_id,
        "customer_name":customer_name,
        "kept_events":kept_events,
        "has_recent_attacks":len(kept_events)>0,
        "message":None if kept_events else "No recent attack events targeted this network"

    }
    

def find_attack_context_for_all_customers(customers:list[dict],target_network:str)->list[dict]:
    if not customers:
        return []
    return [
        find_attack_context(c["customer_id"],c["customer"],target_network)
        for c in customers
    ]
    



