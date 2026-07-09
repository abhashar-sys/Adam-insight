from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from .schemas import SharedInvocationInput

mcp = FastMCP("customer-context-agent")


def _orchestrator_url() -> str:
    value = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000").strip()
    if not value:
        raise RuntimeError("Missing required environment variable: ORCHESTRATOR_URL")
    return value.rstrip("/")


async def _post_json(url: str, payload: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        if not response.content:
            return {"status": "success", "data": None}
        return response.json()


@mcp.tool()
async def health_check_orchestrator() -> dict[str, Any]:
    """Checks only this branch orchestrator health endpoint."""
    url = f"{_orchestrator_url()}/health"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url)
            body: dict[str, Any]
            try:
                body = response.json() if response.content else {}
            except Exception:
                body = {}
            return {
                "service": "orchestrator",
                "ok": response.is_success,
                "status_code": response.status_code,
                "body": body,
            }
        except Exception as exc:
            return {
                "service": "orchestrator",
                "ok": False,
                "error": str(exc),
            }


@mcp.tool()
async def invoke_full_graph(request: SharedInvocationInput) -> dict[str, Any]:
    """Invokes only this branch orchestrator graph endpoint."""
    url = f"{_orchestrator_url()}/graph/invoke"
    return await _post_json(url, request.model_dump())


@mcp.tool()
async def run_alert_pipeline(request: SharedInvocationInput) -> dict[str, Any]:
    """Demo alias routed only through this branch orchestrator.

    This keeps strict ownership isolation: MCP -> orchestrator only.
    """
    result = await invoke_full_graph(request)
    return {
        "pipeline_mode": "orchestrator-only",
        "result": result,
    }


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport != "stdio":
        raise RuntimeError("This MCP server is configured for stdio transport only")
    mcp.run()
