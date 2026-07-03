from ipaddress import ip_network
from services.api_client import get_customers

def _matches_network(target_net,cidr:str) ->bool:
    try:
        candidate_net=ip_network(cidr,strict=False)
        if target_net.version != candidate_net.version:
            return False
        return target_net.subnet_of(candidate_net)
    except ValueError:
        return False
    
def _format_customer(customer,matched_cidr:str)->dict:
    return {
        "customer_id":customer.id,
        "customer":customer.customer,
        "account_id":customer.accountId,
        "account_name":customer.accountName,
        "matched_cidr":matched_cidr,
        "region":customer.region,
        "location":customer.location,
        "in_use":customer.inUse

    }
def find_customer_context(target_network:str)->list[dict]:
    customers=get_customers()
    target_net=ip_network(target_network,strict=False)
    matches=[]
    for customer in customers:
        for cidr in customer.networks:
            if _matches_network(target_net,cidr):
                matches.append(_format_customer(customer,cidr))
                break
    return matches