from concurrent.futures import ThreadPoolExecutor, as_completed
from tools.xiphos import find_mitigation_context
from tools.customer_api import find_customer_context
from tools.chakra_rs import find_attack_context
from states import AgentState, AttackReportOutput, MitigationOutput, CustomersOutput

def _run_mitigation_and_customer_lookup(network:str,locations:list[str]):
    mitigation_result,mitigation_error=None,None
    customer_result,customer_error=[],None
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures={
            executor.submit(find_mitigation_context,network,locations): 'mitigation',
            executor.submit(find_customer_context,network): 'customer'
        }
        for future in as_completed(futures):
            key=futures[future]
            try:
                result=future.result()
                if key=='mitigation':
                    mitigation_result=result
                else:
                    customer_result=result
            except Exception as e:
                if key=='mitigation':
                    mitigation_error=str(e)
                else:
                    customer_error=str(e)
    return mitigation_result,mitigation_error,customer_result,customer_error

def _run_attack_reports(customers:list[dict],network:str)->list[AttackReportOutput]:
    if not customers:
        return []

    attack_results=[]
    with ThreadPoolExecutor(max_workers=min(8, len(customers))) as executor:
        futures={
            executor.submit(
                find_attack_context,
                customer.get("customer_id"),
                customer.get("customer"),
                network,
            ): customer
            for customer in customers
        }
        for future in as_completed(futures):
            customer=futures[future]
            customer_id=customer.get("customer_id")
            customer_name=customer.get("customer")
            try:
                attack_results.append(future.result())
            except Exception as e:
                attack_results.append({
                    "customer_id":customer_id,
                    "customer_name":customer_name,
                    "chakra_rs_failure":True,
                    "chakra_rs_error":f"attack lookup failed for customer {customer_id} - {customer_name}: {str(e)}"
                })

    return attack_results

def _format_mitigation_output(mitigation_result: dict | None, mitigation_error: str | None) -> MitigationOutput | None:
    if mitigation_error:
        return {"error": mitigation_error}
    if not mitigation_result or not mitigation_result.get("matched_cidr"):
        return None
    return {
        "matched_cidr": mitigation_result.get("matched_cidr"),
        "event_id": mitigation_result.get("event_id"),
        "event_version": mitigation_result.get("event_version"),
        "event_customer": mitigation_result.get("event_customer"),
        "lifecycle_state": mitigation_result.get("lifecycle_state"),
        "account_id": mitigation_result.get("account_id"),
        "account_name": mitigation_result.get("account_name"),
        "is_auto_mitigation": mitigation_result.get("is_auto_mitigation"),
        "locations": mitigation_result.get("locations", [])
    }

def _format_customer_output(customer_result: list[dict], customer_error: str | None) -> CustomersOutput:
    if customer_error:
        return {"error": customer_error, "matches": []}
    clean_matches = [
        {
            "customer": c.get("customer"),
            "account_id": c.get("account_id"),
            "account_name": c.get("account_name"),
            "matched_cidr": c.get("matched_cidr")
        }
        for c in customer_result
    ]
    return {"error": None, "matches": clean_matches}

def customer_context_node(state: AgentState) -> AgentState:
    network = state["network"]
    locations = state["locations"]
    mitigation_result, mitigation_error, customer_result, customer_error = _run_mitigation_and_customer_lookup(network, locations)
    attack_results = _run_attack_reports(customer_result, network)
    state["customer_context"] = {
        "mitigation": _format_mitigation_output(mitigation_result, mitigation_error),
        "customers": _format_customer_output(customer_result, customer_error),
        "attack_reports": attack_results
    }
    return state