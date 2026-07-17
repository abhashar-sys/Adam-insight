from concurrent.futures import ThreadPoolExecutor, as_completed
from customer_context.tools.xiphos import find_mitigation_context
from customer_context.tools.customer_api import find_customer_context
from customer_context.tools.chakra_rs import find_attack_context
from customer_context.states import AgentState, AttackReportOutput, MitigationOutput, CustomersOutput

def _run_mitigation_and_customer_lookup(network: str, locations: list[str]):
    mitigation_result, mitigation_error = None, None
    customer_result, customer_error = [], None
    
    # 1. First, fetch the mitigation information to secure the customer identity string
    try:
        mitigation_result = find_mitigation_context(network, locations)
    except Exception as e:
        mitigation_error = str(e)

    # 2. Extract the name fallback anchor from the mitigation if it exists
    mitigation_name = None
    if mitigation_result and isinstance(mitigation_result, dict):
        mitigation_name = mitigation_result.get("event_customer")

    # 3. Fetch the customers, passing the target mitigation string forward as a fallback check
    try:
        # NOTE: Make sure your find_customer_context tool matches the updated signature 
        # that accepts mitigation_customer_name as the second parameter!
        customer_result = find_customer_context(network, mitigation_customer_name=mitigation_name)
    except Exception as e:
        customer_error = str(e)

    return mitigation_result, mitigation_error, customer_result, customer_error


def _run_attack_reports(customers: list[dict], network: str) -> list[AttackReportOutput]:
    if not customers:
        return []

    attack_results = []
    with ThreadPoolExecutor(max_workers=min(8, len(customers))) as executor:
        futures = {
            executor.submit(
                find_attack_context,
                customer.get("customer_id"),
                customer.get("customer"),
                network,
            ): customer
            for customer in customers
        }
        for future in as_completed(futures):
            customer = futures[future]
            customer_id = customer.get("customer_id")
            customer_name = customer.get("customer")
            try:
                attack_results.append(future.result())
            except Exception as e:
                attack_results.append({
                    "customer_id": customer_id,
                    "customer_name": customer_name,
                    "chakra_rs_failure": True,
                    "chakra_rs_error": f"attack lookup failed for customer {customer_id} - {customer_name}: {str(e)}"
                })

    return attack_results


def _format_mitigation_output(mitigation_result: dict | None, mitigation_error: str | None) -> MitigationOutput | None:
    if mitigation_error:
        return {"error": mitigation_error}
    # Relax validation slightly to match against either explicit key variant
    if not mitigation_result or (not mitigation_result.get("matched_cidr") and not mitigation_result.get("mitigated_network")):
        return None
    return {
        "mitigated_network": mitigation_result.get("matched_cidr") or mitigation_result.get("mitigated_network"),
        "event_id": mitigation_result.get("event_id"),
        "event_customer": mitigation_result.get("event_customer"),
        "mitigation_state": mitigation_result.get("mitigation_state"),
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
    
    # Run the corrected sequential dependency lookups
    mitigation_result, mitigation_error, customer_result, customer_error = _run_mitigation_and_customer_lookup(network, locations)
    
    # Because customer_result is now populated via our string-name fallback, 
    # attack reports will automatically spin up for the matched customer!
    attack_results = _run_attack_reports(customer_result, network)
    
    state["customer_context"] = {
        "mitigation": _format_mitigation_output(mitigation_result, mitigation_error),
        "customers": _format_customer_output(customer_result, customer_error),
        "attack_reports": attack_results
    }
    return state