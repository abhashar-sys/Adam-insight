from __future__ import annotations
from ipaddress import ip_network
from customer_context.services.api_client import get_customers

def _matches_network(target_net, cidr_item: str | dict) -> bool:
    try:
        # Extract the string if the API returns networks as objects instead of plain strings
        cidr_str = cidr_item.get("cidr") if isinstance(cidr_item, dict) else cidr_item
        if not cidr_str:
            return False
            
        candidate_net = ip_network(cidr_str, strict=False)
        if target_net.version != candidate_net.version:
            return False
        return target_net.subnet_of(candidate_net)
    except (ValueError, AttributeError):
        return False
    
def _format_customer(customer, matched_cidr: str) -> dict:
    return {
        "customer_id": customer.id,
        "customer": customer.customer,
        "account_id": customer.accountId,
        "account_name": customer.accountName,
        "matched_cidr": matched_cidr,
        "region": customer.region,
        "location": customer.location,
        "in_use": customer.inUse
    }

def find_customer_context(target_network: str, mitigation_customer_name: str | None = None) -> list[dict]:
    customers = get_customers()
    target_net = ip_network(target_network, strict=False)
    matches = []
    
    # Normalize fallback string name just in case (e.g., "lloyds_preprod_dir_conn" -> "lloyds")
    base_mitigation_name = mitigation_customer_name.split("_")[0].lower() if mitigation_customer_name else None

    for customer in customers:
        matched = False
        
        # 1. Primary Check: Inspect network subnets
        for cidr_item in customer.networks:
            if _matches_network(target_net, cidr_item):
                # Safely parse matching string out for the formatting payload
                cidr_str = cidr_item.get("cidr") if isinstance(cidr_item, dict) else cidr_item
                matches.append(_format_customer(customer, cidr_str))
                matched = True
                break
                
        # 2. Secondary Fallback Check: Match based on mitigation identity strings if IP list is out of sync
        if not matched and base_mitigation_name:
            cust_name = getattr(customer, "customer", "") or getattr(customer, "accountName", "") or ""
            if base_mitigation_name in cust_name.lower():
                print(f"[DEBUG] Fallback Name Match Found for: {cust_name}")
                matches.append(_format_customer(customer, target_network))
                
    return matches