from ipaddress import ip_network
from services.api_client import get_mitigation_events
from models import MitigationItem,MitigationNetworkEntry

def _network_cidr(network_entry: MitigationNetworkEntry) -> str|None:
    if network_entry.network:
        return network_entry.network
    return None

def _date_sort_key(value) -> tuple[int, int|str]:
    if value is None:
        return (0, 0)
    if isinstance(value, (int, float)):
        return (2, int(value))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return (2, int(stripped))
        return (1, stripped)
    return (0, 0)

def _find_best_match(target_net,items):
    best_match=None
    best_prefix_len=-1
    best_start_date=(0, 0)

    for item in items:
        for network_entry in item.networks:
            try:
                candidate_source=_network_cidr(network_entry)
                if not candidate_source:
                    continue
                candidate_net=ip_network(candidate_source,strict=False)
                if not target_net.subnet_of(candidate_net):
                    continue
                prefix_len=candidate_net.prefixlen
                start_date=_date_sort_key(item.startDate)
                if (prefix_len>best_prefix_len) or (prefix_len==best_prefix_len and start_date>best_start_date):
                    best_prefix_len=prefix_len
                    best_start_date=start_date
                    best_match={"item":item,"network_entry":network_entry}
            except ValueError:
                continue
    return best_match

def _extract_locations(network_entry,requested_locations):
    location_details=[]
    for requested_location in requested_locations:
        matched=None
        for config in network_entry.configs:
            for loc in config.get("locations",[]):
                if loc.get("location") != requested_location:
                    continue
                matched={
                    "location":requested_location,
                    "isSuppressed":loc.get("isSuppressed",False),
                    "functions":[
                        {
                            "function":fn.get("function"),
                            "config":fn.get("config")
                        }
                        for fn in config.get("functions",[])
                    ]
                }
                break
            if matched:
                break
        if matched:
            location_details.append(matched)
    return location_details

def _format_output(item,network_entry,location_details):
    matched_cidr = _network_cidr(network_entry)
    return {
        "matched_cidr":str(ip_network(matched_cidr,strict=False)) if matched_cidr else None,
        "lifecycle_state":item.state,
        "event_id":item.id,
        "event_version":item.version,
        "event_customer":item.customer,
        "account_id":item.accountId,
        "account_name":item.accountName,
        "is_auto_mitigation":item.isAutoMitigation,
        "locations":location_details
    }

def find_mitigation_context(target_network:str, requested_locations:list[str])->dict:
    response=get_mitigation_events()
    target_net=ip_network(target_network,strict=False)
    best_match=_find_best_match(target_net,response.items)
    if not best_match:
        return {
            "matched_cidr":None,
            "lifecycle_state":None,
            "locations":[]
        }
    return _format_output(
        best_match["item"],
        best_match["network_entry"],
        _extract_locations(best_match["network_entry"],requested_locations)
    )