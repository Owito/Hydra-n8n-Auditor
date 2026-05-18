"""
Hydra-n8n-Auditor — MCP Server for Agentic n8n Workflow Auditing & Auto-Patching.

Acts as a sensor/actuator for LLMs to read, audit, and mutate n8n workflows
in-memory with zero downtime. Implements "Active Immunity" and "Agentic Self-Defense"
concepts for n8n workflow security.

Transport: stdio (native OpenCode integration)
Auth:     N8N_API_KEY env var, X-N8N-API-KEY header
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

import httpx
from fastmcp import FastMCP

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[hydra] %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("hydra")

# ── Constants ────────────────────────────────────────────────────────────────
DEFAULT_BASE_URL = "http://localhost:5678/api/v1"
REQUEST_TIMEOUT = 30.0

# ── MCP Server ───────────────────────────────────────────────────────────────
mcp = FastMCP("Hydra-n8n-Auditor")


# ── Helpers ──────────────────────────────────────────────────────────────────
def _check_env() -> tuple[str, str]:
    """Read N8N_BASE_URL and N8N_API_KEY from environment. Raises on missing key."""
    base_url = os.environ.get("N8N_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    api_key = os.environ.get("N8N_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "N8N_API_KEY environment variable is not set. "
            "Export it before launching the MCP server."
        )
    return base_url, api_key


def _get_client() -> httpx.AsyncClient:
    """Build a fresh httpx.AsyncClient with auth headers and timeout."""
    base_url, api_key = _check_env()
    return httpx.AsyncClient(
        base_url=base_url,
        headers={
            "X-N8N-API-KEY": api_key,
            "Content-Type": "application/json",
        },
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
    )


def _format_http_error(status: int, body: str) -> str:
    """Produce a human-readable HTTP error message."""
    return f"HTTP {status}: {body[:500]}"


# ── Tools ────────────────────────────────────────────────────────────────────


@mcp.tool
async def list_active_workflows() -> str:
    """List all ACTIVE workflows from the n8n instance.

    Makes a GET request to /workflows and filters for workflows where
    'active' is true. Returns a formatted JSON array with only:
    - id: The workflow unique identifier
    - name: The human-readable workflow name
    - updatedAt: Last modification timestamp

    Use this tool FIRST during an audit to identify which workflows are
    running and could be potential attack vectors.
    """
    try:
        async with _get_client() as client:
            resp = await client.get("/workflows")

        if resp.status_code != 200:
            return _format_http_error(resp.status_code, resp.text)

        payload = resp.json()
        workflows = payload.get("data", [])

        active = [
            {
                "id": w.get("id"),
                "name": w.get("name"),
                "updatedAt": w.get("updatedAt"),
            }
            for w in workflows
            if w.get("active") is True
        ]

        if not active:
            return json.dumps(
                {"count": 0, "message": "No active workflows found.", "workflows": []},
                indent=2,
                ensure_ascii=False,
            )

        return json.dumps(
            {"count": len(active), "workflows": active},
            indent=2,
            ensure_ascii=False,
        )

    except httpx.ConnectError:
        return "CONNECTION REFUSED: Cannot reach n8n API. Is n8n running on the configured N8N_BASE_URL?"
    except httpx.TimeoutException:
        return f"TIMEOUT: Request exceeded {REQUEST_TIMEOUT}s. n8n may be overloaded or unreachable."
    except Exception as exc:
        log.exception("Unexpected error in list_active_workflows")
        return f"UNEXPECTED ERROR: {exc}"


@mcp.tool
async def get_workflow_definition(workflow_id: str) -> str:
    """Retrieve the COMPLETE raw JSON definition of a specific n8n workflow.

    Returns the full unmodified JSON of the workflow including all nodes,
    connections, and settings.

    SECURITY AUDIT INSTRUCTIONS — when reviewing the returned JSON, look for:
    1. WEBHOOK NODES WITHOUT AUTHENTICATION: Search for nodes with
       type="n8n-nodes-base.webhook" and check if "authentication" is
       "none" or missing. These are unauthenticated entry points to the
       workflow engine.
    2. COMMAND EXECUTION NODES (RCE): Look for nodes with
       type="n8n-nodes-base.executeCommand". Check if the 'command'
       field interpolates user-controlled data (e.g., from webhook
       payload or file names). This is a critical RCE vector.
    3. HARDCODED SECRETS: Scan all 'parameters' objects for strings
       resembling API keys, passwords, tokens, or connection strings.
    4. HTTP REQUEST NODES WITH SENSITIVE URLS: Check HttpRequest nodes
       for internal IPs, metadata endpoints (169.254.169.254), or
       SSRF-vulnerable URL patterns.

    The raw JSON is returned as a string for LLM analysis.
    """
    try:
        async with _get_client() as client:
            resp = await client.get(f"/workflows/{workflow_id}")

        if resp.status_code == 404:
            return f"WORKFLOW NOT FOUND: No workflow with id '{workflow_id}' exists."
        if resp.status_code == 401 or resp.status_code == 403:
            return "AUTHENTICATION FAILED: Check your N8N_API_KEY. The API rejected the credentials."
        if resp.status_code != 200:
            return _format_http_error(resp.status_code, resp.text)

        return json.dumps(resp.json(), indent=2, ensure_ascii=False)

    except httpx.ConnectError:
        return "CONNECTION REFUSED: Cannot reach n8n API. Is n8n running on the configured N8N_BASE_URL?"
    except httpx.TimeoutException:
        return f"TIMEOUT: Request exceeded {REQUEST_TIMEOUT}s."
    except Exception as exc:
        log.exception("Unexpected error in get_workflow_definition")
        return f"UNEXPECTED ERROR: {exc}"


@mcp.tool
async def patch_workflow(
    workflow_id: str,
    new_workflow_json_string: str,
    dry_run: bool = False,
) -> str:
    """Overwrite an existing n8n workflow with a modified (patched) version.

    This is the WRITE/MUTATION tool. After the LLM has analyzed a workflow
    and identified vulnerabilities, it constructs a corrected JSON and
    applies it using this tool.

    IMPORTANT: new_workflow_json_string must be a valid JSON string
    representing the COMPLETE workflow object. Do NOT send partial diffs.
    The entire workflow will be replaced.

    Args:
        workflow_id: The UUID of the workflow to patch.
        new_workflow_json_string: Complete workflow JSON as a string.
            Must include at minimum: id, name, nodes, connections.
        dry_run: If True, validates the JSON structure and required keys
            WITHOUT writing to n8n. Use this to verify your patch before
            committing. Defaults to False.

    Returns:
        Success message with workflow name and ID, or error details.
    """
    # ── Phase 1: JSON Parsing ──────────────────────────────────────────
    try:
        new_workflow: dict[str, Any] = json.loads(new_workflow_json_string)
    except json.JSONDecodeError as exc:
        return (
            f"INVALID JSON: The provided string is not valid JSON.\n"
            f"Error: {exc.msg} at line {exc.lineno}, column {exc.colno}.\n"
            f"Please fix the JSON syntax and retry."
        )

    # ── Phase 2: Schema Validation ─────────────────────────────────────
    missing = []
    if "id" not in new_workflow:
        missing.append("id")
    if "name" not in new_workflow:
        missing.append("name")
    if "nodes" not in new_workflow:
        missing.append("nodes")
    if "connections" not in new_workflow:
        missing.append("connections")

    if missing:
        return (
            f"SCHEMA VALIDATION FAILED: The workflow JSON is missing required keys: {missing}.\n"
            f"The workflow must include at least: id, name, nodes, connections.\n"
            f"Dry-run mode is active by default — no changes were made."
        )

    node_count = len(new_workflow.get("nodes", []))
    workflow_name = new_workflow.get("name", "unnamed")

    if dry_run:
        return (
            f"DRY-RUN OK: Workflow '{workflow_name}' ({workflow_id}) is valid JSON "
            f"with {node_count} nodes and all required keys present.\n"
            f"No changes were made to n8n. Set dry_run=False to apply the patch."
        )

    # ── Phase 3: Apply the Patch ───────────────────────────────────────
    try:
        async with _get_client() as client:
            resp = await client.put(
                f"/workflows/{workflow_id}",
                content=json.dumps(new_workflow, ensure_ascii=False),
            )

        if resp.status_code == 404:
            return f"WORKFLOW NOT FOUND: No workflow with id '{workflow_id}' exists."
        if resp.status_code == 401 or resp.status_code == 403:
            return "AUTHENTICATION FAILED: Check your N8N_API_KEY."
        if resp.status_code == 400:
            return f"BAD REQUEST: n8n rejected the workflow JSON.\nResponse: {resp.text[:500]}"
        if resp.status_code != 200:
            return _format_http_error(resp.status_code, resp.text)

        updated: dict[str, Any] = resp.json()
        return (
            f"PATCH APPLIED SUCCESSFULLY.\n"
            f"Workflow: '{updated.get('name', workflow_name)}' ({workflow_id})\n"
            f"Nodes: {node_count} | Active: {updated.get('active', 'unknown')}"
        )

    except httpx.ConnectError:
        return "CONNECTION REFUSED: Cannot reach n8n API. Is n8n running?"
    except httpx.TimeoutException:
        return f"TIMEOUT: Request exceeded {REQUEST_TIMEOUT}s."
    except Exception as exc:
        log.exception("Unexpected error in patch_workflow")
        return f"UNEXPECTED ERROR: {exc}"


@mcp.tool
async def deactivate_workflow(workflow_id: str) -> str:
    """Emergency KILL-SWITCH: Immediately deactivate a running n8n workflow.

    Use this tool when a critical vulnerability is detected and the workflow
    must be stopped immediately before a proper patch can be applied.

    This tool:
    1. Fetches the current workflow definition from n8n.
    2. Sets active = false.
    3. PUTs the modified definition back, stopping execution.

    Returns:
        Confirmation message with workflow name and previous active state,
        or error details.
    """
    try:
        async with _get_client() as client:
            # ── Step 1: Get current workflow ────────────────────────
            get_resp = await client.get(f"/workflows/{workflow_id}")

            if get_resp.status_code == 404:
                return f"WORKFLOW NOT FOUND: No workflow with id '{workflow_id}' exists."
            if get_resp.status_code == 401 or get_resp.status_code == 403:
                return "AUTHENTICATION FAILED: Check your N8N_API_KEY."
            if get_resp.status_code != 200:
                return _format_http_error(get_resp.status_code, get_resp.text)

            workflow: dict[str, Any] = get_resp.json()
            was_active = workflow.get("active", False)

            if not was_active:
                return (
                    f"ALREADY INACTIVE: Workflow '{workflow.get('name', 'unnamed')}' "
                    f"({workflow_id}) is already deactivated. No action needed."
                )

            # ── Step 2: Deactivate ──────────────────────────────────
            workflow["active"] = False

            put_resp = await client.put(
                f"/workflows/{workflow_id}",
                content=json.dumps(workflow, ensure_ascii=False),
            )

            if put_resp.status_code != 200:
                return _format_http_error(put_resp.status_code, put_resp.text)

            return (
                f"DEACTIVATED: Workflow '{workflow.get('name', 'unnamed')}' "
                f"({workflow_id}) has been stopped.\n"
                f"Previous state: active=true → now active=false."
            )

    except httpx.ConnectError:
        return "CONNECTION REFUSED: Cannot reach n8n API. Is n8n running?"
    except httpx.TimeoutException:
        return f"TIMEOUT: Request exceeded {REQUEST_TIMEOUT}s."
    except Exception as exc:
        log.exception("Unexpected error in deactivate_workflow")
        return f"UNEXPECTED ERROR: {exc}"


# ── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("Hydra-n8n-Auditor MCP Server starting on stdio transport")
    try:
        _check_env()
    except RuntimeError as exc:
        log.critical(str(exc))
        sys.exit(1)
    mcp.run()
