from langgraph.graph import StateGraph, END
from customer_context.states import AgentState
from customer_context.nodes.customer_context_node import customer_context_node

def build_graph():
    graph=StateGraph(AgentState)
    graph.add_node("customer_context",customer_context_node)
    graph.set_entry_point("customer_context")
    #for now this node leads to END, later the other nodes of traffic analysis, mitigation, and attack context will be added
    graph.add_edge("customer_context",END)
    return graph.compile()
