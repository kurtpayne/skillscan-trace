"""
Canary MCP server for skillscan-trace.

Exposes a realistic tool surface but intercepts every call, logs it to a
shared TraceLog, and returns synthetic responses.  Nothing is ever executed.

Tool definitions and synthetic response generators are loaded from per-tool
YAML files under ``canary/tools/`` via ``tools_config.py``.

The server is designed to be used in two ways:
  1. In-process (for testing): instantiate CanaryServer directly and call
     handle_tool_call() to simulate tool calls.
  2. As an MCP server subprocess: run server.py as __main__ to start a stdio
     MCP server that the harness connects to via the MCP SDK.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from skillscan_trace.canary.detectors import run_detectors
from skillscan_trace.canary.tools_config import SYNTHETIC_RESPONSE_GENERATORS
from skillscan_trace.models import Finding, TraceEvent

logger = logging.getLogger("skillscan_trace.canary")


# ---------------------------------------------------------------------------
# Trace log (shared between server and harness)
# ---------------------------------------------------------------------------


@dataclass
class TraceLog:
    """Accumulates trace events during a single run."""

    events: list[TraceEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    _turn: int = field(default=0, repr=False)

    def next_turn(self) -> None:
        self._turn += 1

    @property
    def current_turn(self) -> int:
        return self._turn

    def add_event(self, event: TraceEvent) -> None:
        self.events.append(event)
        self.findings.extend(event.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "findings": [f.to_dict() for f in self.findings],
            "total_tool_calls": len(self.events),
            "total_findings": len(self.findings),
        }


# ---------------------------------------------------------------------------
# Canary server (in-process)
# ---------------------------------------------------------------------------


class CanaryServer:
    """
    In-process canary MCP server.

    Used by the harness to intercept tool calls during a trace run.
    The harness calls handle_tool_call() for each tool_call in the model's
    response; the server logs the event, runs detectors, and returns a
    synthetic response string.
    """

    def __init__(
        self,
        trace_log: TraceLog,
        allowed_domains: set[str] | None = None,
    ):
        self.trace_log = trace_log
        self.allowed_domains = allowed_domains or set()

    def handle_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        turn: int | None = None,
    ) -> str:
        """
        Intercept a tool call, log it, run detectors, return synthetic response.

        Returns the synthetic response string to pass back to the model.
        """
        if turn is None:
            turn = self.trace_log.current_turn

        # Generate synthetic response
        generator = SYNTHETIC_RESPONSE_GENERATORS.get(tool)
        if generator:
            synthetic_response: str = generator(arguments)
        else:
            synthetic_response = f"# unknown tool: {tool}\n"
            logger.warning("Unknown tool called: %s", tool)

        # Create event (without findings yet)
        event = TraceEvent(
            turn=turn,
            tool=tool,
            arguments=arguments,
            synthetic_response=synthetic_response,
        )

        # Run detectors
        findings = run_detectors(
            tool=tool,
            arguments=arguments,
            event=event,
            allowed_domains=self.allowed_domains,
        )
        event.findings = findings

        # Log
        self.trace_log.add_event(event)
        if findings:
            for f in findings:
                logger.warning(
                    "[%s] Finding: %s (%s) — %s",
                    tool,
                    f.rule_id,
                    f.severity.value,
                    f.message,
                )
        else:
            logger.debug("[%s] Tool call logged, no findings", tool)

        return synthetic_response


# ---------------------------------------------------------------------------
# MCP stdio server (subprocess mode)
# ---------------------------------------------------------------------------


async def run_mcp_server(
    trace_log: TraceLog,
    allowed_domains: set[str] | None = None,
) -> None:
    """
    Run the canary server as an MCP stdio server.

    This is used when the harness launches the server as a subprocess and
    communicates via the MCP protocol over stdin/stdout.
    """
    from mcp.server.fastmcp import FastMCP

    mcp_server = FastMCP("skillscan-canary")
    canary = CanaryServer(trace_log=trace_log, allowed_domains=allowed_domains)

    # ------------------------------------------------------------------
    # Filesystem / network (original)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def bash(command: str) -> str:
        """Execute a bash command and return its output."""
        return canary.handle_tool_call("bash", {"command": command})

    @mcp_server.tool()
    def read_file(path: str) -> str:
        """Read the contents of a file."""
        return canary.handle_tool_call("read_file", {"path": path})

    @mcp_server.tool()
    def write_file(path: str, content: str) -> str:
        """Write content to a file."""
        return canary.handle_tool_call("write_file", {"path": path, "content": content})

    @mcp_server.tool()
    def http_fetch(
        url: str,
        method: str = "GET",
        headers: dict[str, Any] | None = None,
        body: str | None = None,
    ) -> str:
        """Make an HTTP request and return the response."""
        return canary.handle_tool_call(
            "http_fetch",
            {
                "url": url,
                "method": method,
                "headers": headers or {},
                "body": body or "",
            },
        )

    @mcp_server.tool()
    def list_directory(path: str) -> str:
        """List the contents of a directory."""
        return canary.handle_tool_call("list_directory", {"path": path})

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def email_send(
        to: str,
        subject: str,
        body: str,
        cc: str | None = None,
        attachments: list[Any] | None = None,
    ) -> str:
        """Send an email message."""
        return canary.handle_tool_call(
            "email_send",
            {
                "to": to,
                "subject": subject,
                "body": body,
                "cc": cc,
                "attachments": attachments,
            },
        )

    @mcp_server.tool()
    def gmail_send(
        to: str,
        subject: str,
        body: str,
        cc: str | None = None,
        thread_id: str | None = None,
    ) -> str:
        """Send an email via the Gmail API."""
        return canary.handle_tool_call(
            "gmail_send",
            {
                "to": to,
                "subject": subject,
                "body": body,
                "cc": cc,
                "thread_id": thread_id,
            },
        )

    # ------------------------------------------------------------------
    # Calendar
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def calendar_create(
        title: str,
        start: str,
        end: str,
        description: str | None = None,
        attendees: list[Any] | None = None,
        calendar_id: str | None = None,
    ) -> str:
        """Create a calendar event."""
        return canary.handle_tool_call(
            "calendar_create",
            {
                "title": title,
                "start": start,
                "end": end,
                "description": description,
                "attendees": attendees,
                "calendar_id": calendar_id,
            },
        )

    @mcp_server.tool()
    def calendar_list(
        calendar_id: str | None = None,
        time_min: str | None = None,
        time_max: str | None = None,
        max_results: int = 10,
    ) -> str:
        """List upcoming calendar events."""
        return canary.handle_tool_call(
            "calendar_list",
            {
                "calendar_id": calendar_id,
                "time_min": time_min,
                "time_max": time_max,
                "max_results": max_results,
            },
        )

    # ------------------------------------------------------------------
    # GitHub
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def github_create_issue(
        repo: str,
        title: str,
        body: str,
        labels: list[Any] | None = None,
    ) -> str:
        """Create a GitHub issue in a repository."""
        return canary.handle_tool_call(
            "github_create_issue",
            {"repo": repo, "title": title, "body": body, "labels": labels},
        )

    @mcp_server.tool()
    def github_push_file(
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str = "main",
    ) -> str:
        """Create or update a file in a GitHub repository."""
        return canary.handle_tool_call(
            "github_push_file",
            {
                "repo": repo,
                "path": path,
                "content": content,
                "message": message,
                "branch": branch,
            },
        )

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def slack_post_message(
        channel: str,
        text: str,
        thread_ts: str | None = None,
        blocks: list[Any] | None = None,
    ) -> str:
        """Post a message to a Slack channel or DM."""
        return canary.handle_tool_call(
            "slack_post_message",
            {
                "channel": channel,
                "text": text,
                "thread_ts": thread_ts,
                "blocks": blocks,
            },
        )

    # ------------------------------------------------------------------
    # Notion
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def notion_create_page(
        parent_id: str,
        title: str,
        content: str | None = None,
    ) -> str:
        """Create a new page in Notion."""
        return canary.handle_tool_call(
            "notion_create_page",
            {"parent_id": parent_id, "title": title, "content": content},
        )

    @mcp_server.tool()
    def notion_append_block(
        page_id: str,
        content: str,
        block_type: str = "paragraph",
    ) -> str:
        """Append a content block to an existing Notion page."""
        return canary.handle_tool_call(
            "notion_append_block",
            {"page_id": page_id, "content": content, "block_type": block_type},
        )

    # ------------------------------------------------------------------
    # Cloud CLI (P0 Batch 2)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def call_aws_cli(command: str) -> str:
        """Execute an AWS CLI command and return the output."""
        return canary.handle_tool_call("call_aws_cli", {"command": command})

    @mcp_server.tool()
    def call_kubectl(command: str) -> str:
        """Execute a kubectl command against the current Kubernetes cluster."""
        return canary.handle_tool_call("call_kubectl", {"command": command})

    # ------------------------------------------------------------------
    # Code execution (P0 Batch 2)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def python(code: str) -> str:  # noqa: A001
        """Execute Python code and return the output."""
        return canary.handle_tool_call("python", {"code": code})

    @mcp_server.tool()
    def computer(
        action: str,
        coordinate: list[int] | None = None,
        text: str | None = None,
    ) -> str:
        """Perform a computer-use action (screenshot, click, type, key)."""
        return canary.handle_tool_call(
            "computer",
            {"action": action, "coordinate": coordinate, "text": text},
        )

    # ------------------------------------------------------------------
    # Agent memory (P0 Batch 2)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def memory_write(key: str, value: str) -> str:
        """Write a key-value pair to the agent's persistent memory."""
        return canary.handle_tool_call("memory_write", {"key": key, "value": value})

    @mcp_server.tool()
    def memory_read(key: str) -> str:
        """Read a value from the agent's persistent memory."""
        return canary.handle_tool_call("memory_read", {"key": key})

    @mcp_server.tool()
    def context_write(content: str, namespace: str | None = None) -> str:
        """Write content to the agent's context/scratchpad."""
        return canary.handle_tool_call(
            "context_write", {"content": content, "namespace": namespace}
        )

    # ------------------------------------------------------------------
    # Web (P0 Batch 2)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def web_search(query: str, max_results: int = 5) -> str:
        """Search the web and return results."""
        return canary.handle_tool_call("web_search", {"query": query, "max_results": max_results})

    @mcp_server.tool()
    def web_fetch(url: str) -> str:
        """Fetch the content of a URL and return it."""
        return canary.handle_tool_call("web_fetch", {"url": url})

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def execute_sql(query: str, database: str | None = None) -> str:
        """Execute a SQL query against a database and return the results."""
        return canary.handle_tool_call("execute_sql", {"query": query, "database": database})

    @mcp_server.tool()
    def list_tables(database: str | None = None) -> str:
        """List all tables in a database."""
        return canary.handle_tool_call("list_tables", {"database": database})

    @mcp_server.tool()
    def describe_table(table: str, database: str | None = None) -> str:
        """Get the schema (column definitions) of a database table."""
        return canary.handle_tool_call("describe_table", {"table": table, "database": database})

    # ------------------------------------------------------------------
    # Secrets / Vault
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def read_secret(path: str, vault: str | None = None) -> str:
        """Read a secret value from a secrets vault."""
        return canary.handle_tool_call("read_secret", {"path": path, "vault": vault})

    @mcp_server.tool()
    def list_secrets(path: str | None = None, vault: str | None = None) -> str:
        """List available secrets in a vault."""
        return canary.handle_tool_call("list_secrets", {"path": path, "vault": vault})

    @mcp_server.tool()
    def get_vault_item(item: str, vault: str | None = None) -> str:
        """Get an item from a password manager vault."""
        return canary.handle_tool_call("get_vault_item", {"item": item, "vault": vault})

    # ------------------------------------------------------------------
    # Email Read
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def search_emails(query: str, max_results: int = 10) -> str:
        """Search the email inbox for messages matching a query."""
        return canary.handle_tool_call(
            "search_emails", {"query": query, "max_results": max_results}
        )

    @mcp_server.tool()
    def read_email(message_id: str) -> str:
        """Read the full contents of a specific email message."""
        return canary.handle_tool_call("read_email", {"message_id": message_id})

    # ------------------------------------------------------------------
    # GitHub Read
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def get_file_contents(repo: str, path: str, branch: str | None = None) -> str:
        """Read the contents of a file from a GitHub repository."""
        return canary.handle_tool_call(
            "get_file_contents",
            {"repo": repo, "path": path, "branch": branch},
        )

    @mcp_server.tool()
    def search_code(query: str, repo: str | None = None) -> str:
        """Search for code across GitHub repositories."""
        return canary.handle_tool_call("search_code", {"query": query, "repo": repo})

    @mcp_server.tool()
    def create_pull_request(
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str | None = None,
    ) -> str:
        """Create a pull request in a GitHub repository."""
        return canary.handle_tool_call(
            "create_pull_request",
            {
                "repo": repo,
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
        )

    @mcp_server.tool()
    def merge_pull_request(repo: str, pull_number: int) -> str:
        """Merge a pull request in a GitHub repository."""
        return canary.handle_tool_call(
            "merge_pull_request",
            {"repo": repo, "pull_number": pull_number},
        )

    @mcp_server.tool()
    def get_secret_scanning_alert(repo: str, alert_number: int) -> str:
        """Get details of a secret scanning alert."""
        return canary.handle_tool_call(
            "get_secret_scanning_alert",
            {"repo": repo, "alert_number": alert_number},
        )

    # ------------------------------------------------------------------
    # Browser Automation (P1)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def browser_navigate(url: str) -> str:
        """Navigate the browser to a URL and return page information."""
        return canary.handle_tool_call("browser_navigate", {"url": url})

    @mcp_server.tool()
    def browser_screenshot(selector: str | None = None) -> str:
        """Take a screenshot of the current browser page."""
        return canary.handle_tool_call("browser_screenshot", {"selector": selector})

    @mcp_server.tool()
    def browser_click(selector: str) -> str:
        """Click an element on the page identified by a CSS selector."""
        return canary.handle_tool_call("browser_click", {"selector": selector})

    @mcp_server.tool()
    def browser_fill(selector: str, value: str) -> str:
        """Fill a form field with a value."""
        return canary.handle_tool_call("browser_fill", {"selector": selector, "value": value})

    @mcp_server.tool()
    def browser_evaluate(script: str) -> str:
        """Evaluate a JavaScript expression in the browser."""
        return canary.handle_tool_call("browser_evaluate", {"script": script})

    # ------------------------------------------------------------------
    # Slack Read (P1)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def slack_search_messages(query: str, max_results: int = 10) -> str:
        """Search Slack messages matching a query."""
        return canary.handle_tool_call(
            "slack_search_messages",
            {"query": query, "max_results": max_results},
        )

    @mcp_server.tool()
    def slack_read_channel(channel: str, limit: int = 20) -> str:
        """Read recent messages from a Slack channel."""
        return canary.handle_tool_call("slack_read_channel", {"channel": channel, "limit": limit})

    @mcp_server.tool()
    def slack_read_thread(channel: str, thread_ts: str) -> str:
        """Read messages in a Slack thread."""
        return canary.handle_tool_call(
            "slack_read_thread",
            {"channel": channel, "thread_ts": thread_ts},
        )

    @mcp_server.tool()
    def slack_list_channels(limit: int = 100) -> str:
        """List available Slack channels."""
        return canary.handle_tool_call("slack_list_channels", {"limit": limit})

    # ------------------------------------------------------------------
    # Advanced Filesystem (P1)
    # ------------------------------------------------------------------

    @mcp_server.tool()
    def search_files(pattern: str, path: str | None = None) -> str:
        """Search for files matching a pattern."""
        return canary.handle_tool_call("search_files", {"pattern": pattern, "path": path})

    @mcp_server.tool()
    def edit_file(path: str, old_text: str, new_text: str) -> str:
        """Edit a file by replacing occurrences of old_text with new_text."""
        return canary.handle_tool_call(
            "edit_file",
            {"path": path, "old_text": old_text, "new_text": new_text},
        )

    @mcp_server.tool()
    def move_file(source: str, destination: str) -> str:
        """Move or rename a file."""
        return canary.handle_tool_call("move_file", {"source": source, "destination": destination})

    @mcp_server.tool()
    def directory_tree(path: str | None = None, depth: int | None = None) -> str:
        """Show the directory tree structure."""
        return canary.handle_tool_call("directory_tree", {"path": path, "depth": depth})

    @mcp_server.tool()
    def read_multiple_files(paths: list[str]) -> str:
        """Read the contents of multiple files at once."""
        return canary.handle_tool_call("read_multiple_files", {"paths": paths})

    await mcp_server.run_stdio_async()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    log = TraceLog()
    asyncio.run(run_mcp_server(log))
