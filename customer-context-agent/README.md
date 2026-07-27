# Adam Insight

```text
adam-insight/
├── app.py - FastAPI app exposing health, node, and graph invocation endpoints.
├── connect.py - Loads base URLs, tokens, and other environment configuration.
├── demo.py - Command-line demo runner that invokes the graph and prints JSON output.
├── graph.py - Builds the LangGraph workflow and connects the available nodes.
├── requirements.txt - Python dependencies needed to run and test the project.
├── models/
│   ├── __init__.py - Re-exports the domain models used across the project.
│   ├── chakra_rs.py - Schemas for Chakra RS attack context and related responses.
│   ├── customer.py - Schemas for customer lookup and customer context data.
│   └── xiphos.py - Schemas for Xiphos mitigation event data.
├── nodes/
│   ├── customer_context_node.py - Builds customer context from mitigation, customer, and attack data.
│   └── integration_node.py - Orchestrates downstream integration calls for the combined demo flow.
├── services/
│   └── api_client.py - Shared HTTP client helpers for calling the external APIs.
├── states/
│   ├── __init__.py - Package marker for state definitions.
│   └── agent.py - TypedDict state and output contracts used by the graph and node code.
├── tests/
│   ├── test_app.py - Verifies the FastAPI endpoints and graph invocation behavior.
│   ├── test_chakra_rs.py - Tests Chakra RS lookup behavior.
│   ├── test_customer_api.py - Tests customer API lookup behavior.
│   ├── test_graph.py - Tests graph assembly and graph-level behavior.
│   └── test_xiphos.py - Tests Xiphos mitigation lookup behavior.
└── tools/
    ├── chakra_rs.py - Tool layer for calling Chakra RS endpoints.
    ├── customer_api.py - Tool layer for calling customer service endpoints.
    └── xiphos.py - Tool layer for calling Xiphos endpoints.
```

## MCP Server

- [mcp_server/server.py](mcp_server/server.py) - MCP tool server that calls only this branch orchestrator service.
- [mcp_server/schemas.py](mcp_server/schemas.py) - Input schemas shared by the MCP tools.
- [mcp_server/__main__.py](mcp_server/__main__.py) - Entry point for starting the MCP server with `python -m mcp_server`.

### Environment variables

- `ORCHESTRATOR_URL` - Base URL for this branch's FastAPI orchestrator.
- `MCP_TRANSPORT` - Must be `stdio` for this server.

### Available MCP tools

- `health_check_orchestrator` - Checks only this branch orchestrator health endpoint.
- `invoke_full_graph` - Calls this branch's orchestrator and returns the result.
- `run_alert_pipeline` - Demo alias that still routes only to this branch orchestrator.

### Local run notes

- This MCP server is intentionally isolated: it does not call other intern services directly.
- Ownership model is strict: MCP -> your orchestrator only.

### Suggested single-laptop start order

```bash
# from the main repo checkout
python -m mcp_server
```

Set only `ORCHESTRATOR_URL` and call the MCP tools. Any fan-out to other services happens inside your orchestrator implementation.