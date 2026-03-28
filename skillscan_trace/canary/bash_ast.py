"""
Trace-A5: AST-based bash command analysis using bashlex.

Replaces the regex-only BASH_PATTERNS approach in detectors.py with a
structural analysis of the parsed command tree.  Falls back to the original
regex patterns when bashlex cannot parse the command (e.g. heavily obfuscated
or invalid syntax), so detection coverage is never reduced.

Design principles:
  - Walk the AST to find structural patterns (pipe chains, eval, command
    substitution, redirect targets) rather than matching raw text.
  - Extract all command words and URLs from the tree for secondary checks.
  - Graceful degradation: parse errors → fall back to regex.
  - No side effects; pure functions only.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

try:
    import bashlex

    _BASHLEX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _BASHLEX_AVAILABLE = False

from skillscan_trace.models import Severity


# ---------------------------------------------------------------------------
# AST node visitor helpers
# ---------------------------------------------------------------------------


def _collect_nodes(node: Any, kind: str) -> list[Any]:
    """Recursively collect all AST nodes of the given kind."""
    results: list[Any] = []
    if node.kind == kind:
        results.append(node)
    for child in getattr(node, "parts", []):
        results.extend(_collect_nodes(child, kind))
    return results


def _collect_command_words(node: Any) -> list[str]:
    """Return all word values from command nodes in the tree."""
    words: list[str] = []
    if node.kind == "command":
        for part in getattr(node, "parts", []):
            if part.kind == "word":
                words.append(getattr(part, "word", ""))
    for child in getattr(node, "parts", []):
        words.extend(_collect_command_words(child))
    return words


def _collect_all_words(node: Any) -> list[str]:
    """Return every word value in the entire AST."""
    words: list[str] = []
    if node.kind == "word":
        w = getattr(node, "word", "")
        if w:
            words.append(w)
    for child in getattr(node, "parts", []):
        words.extend(_collect_all_words(child))
    return words


def _pipeline_commands(node: Any) -> list[list[str]]:
    """
    Return a list of command-word-lists for each command in a pipeline.
    E.g. 'base64 -d x | bash' → [['base64', '-d', 'x'], ['bash']]
    """
    if node.kind != "pipeline":
        return []
    cmds: list[list[str]] = []
    for child in getattr(node, "parts", []):
        if child.kind == "command":
            words = [p.word for p in getattr(child, "parts", []) if p.kind == "word"]
            cmds.append(words)
    return cmds


# ---------------------------------------------------------------------------
# AST-based detection rules
# ---------------------------------------------------------------------------

_SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
_ENCODE_TOOLS = {"base64", "openssl", "xxd", "od", "python", "python3", "perl", "ruby"}
_FETCH_TOOLS = {"curl", "wget", "fetch", "aria2c", "axel", "httpie", "http"}
_REVERSE_SHELL_FLAGS = {"-e", "--exec", "-c", "--sh-exec"}


def _check_pipeline(pipeline_node: Any) -> list[tuple[str, Severity, str]]:
    """
    Detect dangerous pipeline patterns:
      - encode_tool | shell  (base64 -d | bash)
      - fetch_tool | shell   (curl url | bash)
      - echo | shell         (echo payload | sh)
    Returns list of (rule_id, severity, message).
    """
    hits: list[tuple[str, Severity, str]] = []
    cmds = _pipeline_commands(pipeline_node)
    if len(cmds) < 2:
        return hits

    # Walk consecutive pairs in the pipeline
    for i in range(len(cmds) - 1):
        left_cmd = cmds[i][0].lower() if cmds[i] else ""
        right_cmd = cmds[i + 1][0].lower() if cmds[i + 1] else ""

        if right_cmd in _SHELL_INTERPRETERS:
            if left_cmd in _ENCODE_TOOLS or left_cmd == "base64":
                hits.append(
                    (
                        "CMD-TRACE-003",
                        Severity.CRITICAL,
                        f"Encoded payload execution: {left_cmd} piped to {right_cmd}",
                    )
                )
            elif left_cmd in _FETCH_TOOLS:
                hits.append(
                    (
                        "CMD-TRACE-003",
                        Severity.CRITICAL,
                        f"Remote payload execution: {left_cmd} piped to {right_cmd}",
                    )
                )
            elif left_cmd == "echo":
                hits.append(
                    (
                        "CMD-TRACE-003",
                        Severity.HIGH,
                        f"Encoded payload execution: echo piped to {right_cmd}",
                    )
                )
            elif left_cmd == "cat":
                hits.append(
                    (
                        "CMD-TRACE-003",
                        Severity.HIGH,
                        f"File content piped to {right_cmd}",
                    )
                )

    return hits


def _check_eval(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect eval with command substitution: eval $(...)"""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    first_word = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if first_word != "eval":
        return hits

    # Look for commandsubstitution nodes in the eval arguments
    for part in parts[1:]:
        if part.kind == "word":
            subs = _collect_nodes(part, "commandsubstitution")
            if subs:
                hits.append(
                    (
                        "CMD-TRACE-001",
                        Severity.CRITICAL,
                        "Suspicious bash: eval with command substitution $(...)",
                    )
                )
                break
        elif part.kind == "commandsubstitution":
            hits.append(
                (
                    "CMD-TRACE-001",
                    Severity.CRITICAL,
                    "Suspicious bash: eval with command substitution $(...)",
                )
            )
            break

    return hits


def _check_fetch_commands(command_node: Any) -> list[tuple[str, Severity, str, str]]:
    """
    Detect curl/wget calls and extract the URL.
    Returns (rule_id, severity, message, url).
    """
    hits: list[tuple[str, Severity, str, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if cmd not in _FETCH_TOOLS:
        return hits

    # Extract URL arguments (words starting with http/https/ftp)
    for part in parts[1:]:
        if part.kind == "word":
            w = getattr(part, "word", "")
            if re.match(r"https?://|ftp://", w, re.I):
                hits.append(
                    (
                        "EXF-TRACE-001",
                        Severity.HIGH,
                        f"Outbound HTTP request via bash ({cmd})",
                        w,
                    )
                )

    return hits


def _check_netcat(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect netcat reverse/bind shell patterns."""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if cmd not in {"nc", "ncat", "netcat", "nc.traditional"}:
        return hits

    flags = {getattr(p, "word", "") for p in parts if p.kind == "word"}
    if flags & _REVERSE_SHELL_FLAGS:
        hits.append(
            (
                "EXF-TRACE-001",
                Severity.CRITICAL,
                f"Reverse shell or bind shell via {cmd} with -e/-c flag",
            )
        )
    return hits


def _check_persistence(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect crontab manipulation and shell startup file writes."""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""

    if cmd == "crontab":
        hits.append(
            (
                "CMD-TRACE-002",
                Severity.HIGH,
                "crontab invocation — potential persistence mechanism",
            )
        )
        return hits

    # Check redirect targets for shell startup files
    redirects = _collect_nodes(command_node, "redirect")
    for r in redirects:
        for part in getattr(r, "parts", []):
            if part.kind == "word":
                w = getattr(part, "word", "")
                if re.search(r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/cron)", w, re.I):
                    hits.append(
                        (
                            "CMD-TRACE-002",
                            Severity.MEDIUM,
                            f"Write to shell startup/cron file: {w}",
                        )
                    )

    return hits


def _check_sensitive_reads(command_node: Any) -> list[tuple[str, Severity, str, str]]:
    """
    Detect reads of sensitive files via cat/head/tail/less/more.
    Returns (rule_id, severity, message, path).
    """
    hits: list[tuple[str, Severity, str, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if cmd not in {"cat", "head", "tail", "less", "more", "tee", "grep"}:
        return hits

    _SENSITIVE = re.compile(
        r"(\.ssh/(id_rsa|id_ed25519|authorized_keys)|\.aws/(credentials|config)"
        r"|\.env\b|\.npmrc|\.netrc|/etc/(passwd|shadow|sudoers)"
        r"|(api[_-]?key|secret|token|password))",
        re.I,
    )
    for part in parts[1:]:
        if part.kind == "word":
            w = getattr(part, "word", "")
            if _SENSITIVE.search(w):
                hits.append(
                    (
                        "EXF-TRACE-003",
                        Severity.HIGH,
                        f"Read of sensitive file via {cmd}: {w}",
                        w,
                    )
                )

    return hits


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class BashFinding(NamedTuple):
    rule_id: str
    severity: Severity
    message: str
    evidence: str


def analyze_bash_ast(command: str) -> list[BashFinding]:
    """
    Parse `command` with bashlex and return a list of BashFindings.

    Returns an empty list if the command is empty or contains no suspicious
    patterns.  Raises BashParseError if bashlex cannot parse the command so
    the caller can fall back to regex.
    """
    if not command or not command.strip():
        return []

    if not _BASHLEX_AVAILABLE:
        raise BashParseError("bashlex not installed")

    try:
        parts = bashlex.parse(command)
    except Exception as e:
        raise BashParseError(str(e)) from e

    findings: list[BashFinding] = []

    for node in parts:
        findings.extend(_walk_node(node, command))

    return findings


def _walk_node(node: Any, raw_command: str) -> list[BashFinding]:
    """Recursively walk an AST node and collect findings."""
    results: list[BashFinding] = []

    if node.kind == "pipeline":
        for rule_id, severity, message in _check_pipeline(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

    if node.kind == "command":
        for rule_id, severity, message in _check_eval(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message, url in _check_fetch_commands(node):
            results.append(BashFinding(rule_id, severity, message, url))

        for rule_id, severity, message in _check_netcat(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message in _check_persistence(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message, path in _check_sensitive_reads(node):
            results.append(BashFinding(rule_id, severity, message, path))

    # Recurse into children
    for child in getattr(node, "parts", []):
        results.extend(_walk_node(child, raw_command))

    return results


class BashParseError(Exception):
    """Raised when bashlex cannot parse the command string."""

    pass
