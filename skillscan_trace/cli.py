"""
CLI entry point for skillscan-trace.

Commands:
  skillscan-trace run <skill>     Run a trace on a skill file or directory
  skillscan-trace check           Verify API connectivity and canary server
  skillscan-trace models          List available models

Exit codes:
  0  — all skills benign (or no judge run)
  1  — one or more malicious skills detected
  2  — one or more skills need human review (disagreement)
  3  — errors during trace execution
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from skillscan_trace.config import load_config, merge_config

console = Console()

# Optional dependency for --remote-host; None if not installed
try:
    import requests as req_lib  # noqa: F401
except ImportError:
    req_lib = None  # type: ignore[assignment,unused-ignore]


def _load_dotenv() -> None:
    """Load .env from cwd and all parent directories (nearest wins).

    Priority order for API keys:
      1. CLI flag (--api-key)
      2. Environment variable already set in the shell
      3. .env file (this function)
      4. Config file (skillscan-trace.yaml)

    Keys are never written to the config file — use .env or export them.
    """
    try:
        from dotenv import load_dotenv, find_dotenv  # type: ignore[import-untyped,unused-ignore]
    except ImportError:
        return  # python-dotenv not installed — silently skip

    # find_dotenv walks up from cwd looking for a .env file
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        # override=False: existing shell env vars always win over .env
        load_dotenv(dotenv_path, override=False)
        logging.getLogger(__name__).debug("Loaded .env from %s", dotenv_path)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(version=None, prog_name="skillscan-trace", package_name="skillscan-trace")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=True),
    help="Path to a skillscan-trace.yaml config file. Auto-discovered if not set.",
)
@click.pass_context
def main(ctx: click.Context, debug: bool, config_path: str | None) -> None:
    """skillscan-trace — behavioral execution engine for AI agent skills."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    # Load .env before config so env vars are available for provider resolution.
    # Shell env vars always take precedence over .env values.
    _load_dotenv()
    ctx.ensure_object(dict)
    try:
        cfg = load_config(Path(config_path) if config_path else None)
    except ValueError as e:
        console.print(f"[red]Config error: {e}[/red]")
        sys.exit(1)
    ctx.obj["cfg"] = cfg
    if cfg and not debug:
        # Show which config file was loaded (helpful for debugging)
        from skillscan_trace.config import find_config_file

        found = find_config_file() if not config_path else Path(config_path)
        if found:
            console.print(f"[dim]Using config: {found}[/dim]", highlight=False)


ProviderConfig = dict[str, Any]

PROVIDER_CONFIGS: dict[str, ProviderConfig] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "default_model": "gpt-4.1-mini",
        "requires_key": True,
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "env_key": "OPENROUTER_API_KEY",
        "default_model": "openai/gpt-4.1-mini",
        "requires_key": True,
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "env_key": None,
        "default_model": "qwen2.5:7b",
        "requires_key": False,
    },
}


def _resolve_provider(
    provider: str | None,
    api_key: str | None,
    base_url: str | None,
    model: str,
) -> tuple[str, str | None, str]:
    """Resolve (base_url, api_key, model) from --provider / --api-key / --base-url.

    Priority: explicit --api-key / --base-url override everything.
    --provider sets sensible defaults and picks the right env var.
    """
    if provider and provider not in PROVIDER_CONFIGS:
        raise click.BadParameter(
            f"Unknown provider '{provider}'. Choose from: {', '.join(PROVIDER_CONFIGS)}",
            param_hint="--provider",
        )

    cfg: ProviderConfig = PROVIDER_CONFIGS[provider or "openai"]

    # base_url: explicit flag > provider default
    resolved_base_url: str = base_url or str(cfg["base_url"])

    # model: if user passed the bare default (gpt-4.1-mini) and provider has its own
    # default, use the provider default instead so openrouter gets openai/gpt-4.1-mini
    resolved_model = model
    if model == "gpt-4.1-mini" and provider and provider != "openai":
        resolved_model = str(cfg["default_model"])

    # api_key: explicit flag > env var for this provider > OPENAI_API_KEY fallback
    resolved_key: str | None
    if api_key:
        resolved_key = api_key
    elif cfg["env_key"]:
        env_key_name: str = str(cfg["env_key"])
        resolved_key = os.environ.get(env_key_name) or os.environ.get("OPENAI_API_KEY")
    else:
        resolved_key = os.environ.get("OPENAI_API_KEY")  # ollama: key not required

    if cfg["requires_key"] and not resolved_key:
        env_hint: str = str(cfg["env_key"]) if cfg["env_key"] else "OPENAI_API_KEY"
        raise click.UsageError(
            f"No API key found for provider '{provider or 'openai'}'. "
            f"Set {env_hint} or pass --api-key."
        )

    return resolved_base_url, resolved_key, resolved_model


@main.command()
@click.argument("skill", type=click.Path(exists=True))
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["openai", "openrouter", "ollama"], case_sensitive=False),
    help="LLM provider shortcut. Sets base URL and env var automatically.",
)
@click.option(
    "--model",
    default=None,
    help="LLM model for execution (any OpenAI-compatible model). Default: gpt-4.1-mini",
)
@click.option(
    "--input-model",
    default=None,
    help="LLM model for generating user messages. Default: gpt-4.1-mini",
)
@click.option(
    "--api-key",
    default=None,
    help="API key. Overrides provider env var (OPENAI_API_KEY, OPENROUTER_API_KEY).",
)
@click.option(
    "--base-url",
    default=None,
    help="Custom API base URL. Overrides --provider default (e.g. for Azure, Mistral).",
)
@click.option(
    "--variants",
    default=None,
    type=int,
    help="Number of user messages to generate per skill. Default: 3",
)
@click.option(
    "--max-turns",
    default=None,
    type=int,
    help="Maximum tool-call rounds per user message. Default: 10",
)
@click.option(
    "--output-dir",
    default=None,
    type=click.Path(),
    help="Directory to write output files. Default: ./trace-output/",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif", "text"], case_sensitive=False),
    default=None,
    help="Output format. sarif produces a single SARIF 2.1.0 file for CI. Default: json",
)
@click.option(
    "--allow-domain",
    "allow_domains",
    multiple=True,
    help="Additional domains to allow (repeatable).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Resolve the skill and generate messages but do not run the LLM.",
)
@click.option(
    "--judge",
    is_flag=True,
    default=None,
    help="Run the dual-LLM judge (GPT-4.1 + Claude Sonnet) after the trace.",
)
@click.option(
    "--anthropic-api-key",
    envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key for Claude judge (or set ANTHROPIC_API_KEY).",
)
@click.option(
    "--quiet", "-q", is_flag=True, help="Suppress per-skill output; show only the summary."
)
@click.option(
    "--fail-on-malicious",
    is_flag=True,
    default=None,
    help="Exit with code 1 if any malicious skill is detected (for CI).",
)
@click.option(
    "--models",
    "multi_models",
    default=None,
    help=(
        "Comma-separated list of models to trace and compare. "
        "When set, --model is ignored and a MultiModelReport is produced. "
        "Example: --models gpt-4.1-mini,openai/gpt-4o "
        "(use --provider openrouter for cross-provider model names)."
    ),
)
@click.option(
    "--remote-host",
    default=None,
    envvar="SKILLSCAN_TRACE_REMOTE_HOST",
    help=(
        "Submit the trace to a remote skillscan-trace server instead of running locally. "
        "Example: --remote-host https://trace.example.com "
        "The --api-key is forwarded to the server (BYOK). "
        "Set SKILLSCAN_TRACE_REMOTE_HOST env var to avoid repeating the flag."
    ),
)
@click.pass_context
def run(
    ctx: click.Context,
    skill: str,
    provider: str | None,
    model: str | None,
    input_model: str | None,
    api_key: str | None,
    base_url: str | None,
    variants: int | None,
    max_turns: int | None,
    output_dir: str | None,
    output_format: str | None,
    allow_domains: tuple[str, ...],
    dry_run: bool,
    judge: bool | None,
    anthropic_api_key: str | None,
    quiet: bool,
    fail_on_malicious: bool | None,
    multi_models: str | None,
    remote_host: str | None,
) -> None:
    """Run a behavioral trace on SKILL (file or directory)."""
    # Merge config file values with CLI flags (CLI wins)
    cfg = merge_config(
        ctx.obj.get("cfg", {}),
        provider=provider,
        model=model,
        input_model=input_model,
        api_key=api_key,
        base_url=base_url,
        variants=variants,
        max_turns=max_turns,
        output_dir=output_dir,
        output_format=output_format,
        judge=judge,
        fail_on_malicious=fail_on_malicious,
        allow_domains=allow_domains,
    )
    provider = cfg.get("provider")
    model = cfg.get("model", "gpt-4.1-mini")
    input_model = cfg.get("input_model", "gpt-4.1-mini")
    api_key = cfg.get("api_key")
    base_url = cfg.get("base_url")
    variants = cfg.get("variants", 3)
    max_turns = cfg.get("max_turns", 10)
    output_dir = cfg.get("output_dir")
    output_format = cfg.get("format", "json")
    judge = cfg.get("judge", False)
    fail_on_malicious = cfg.get("fail_on_malicious", False)
    allow_domains = tuple(cfg.get("allow_domains", []))

    base_url, api_key, model = _resolve_provider(
        provider, api_key, base_url, model or "gpt-4.1-mini"
    )
    from skillscan_trace.formatters import format_sarif, format_batch_summary

    # ── Remote mode (B5) ──────────────────────────────────────────────────────
    if remote_host:
        _run_remote(
            skill=skill,
            remote_host=remote_host.rstrip("/"),
            api_key=api_key,
            provider=provider,
            model=model,
            variants=variants or 3,
            max_turns=max_turns or 10,
            output_dir=output_dir or "trace-output",
            output_format=output_format or "json",
            judge=judge or False,
            quiet=quiet,
        )
        return

    # ── Multi-model mode (B4) ─────────────────────────────────────────────────
    if multi_models:
        model_list = [m.strip() for m in multi_models.split(",") if m.strip()]
        if len(model_list) < 2:
            raise click.UsageError("--models requires at least two comma-separated model names.")
        _run_multi_model(
            skill=skill,
            models=model_list,
            api_key=api_key,
            base_url=base_url,
            input_model=input_model or model,
            variants=variants or 3,
            max_turns=max_turns or 10,
            output_dir=output_dir or "trace-output",
            output_format=output_format or "json",
            judge=judge or False,
            anthropic_api_key=anthropic_api_key,
            quiet=quiet,
            fail_on_malicious=fail_on_malicious or False,
        )
        return

    # Collect skill files
    skill_path = Path(skill)
    skill_files: list[Path] = []

    if skill_path.is_dir():
        if (skill_path / "SKILL.md").exists():
            skill_files = [skill_path]
        else:
            skill_files = list(skill_path.rglob("SKILL.md"))
            if not skill_files:
                skill_files = list(skill_path.rglob("*.md"))
            console.print(f"[cyan]Found {len(skill_files)} skill(s) in {skill}[/cyan]")
    else:
        skill_files = [skill_path]

    out_dir = Path(output_dir) if output_dir else Path("trace-output")
    out_dir.mkdir(parents=True, exist_ok=True)
    allowed_domains = set(allow_domains)

    batch_start = time.time()
    all_reports = []

    # Run traces (with progress bar for batch)
    is_batch = len(skill_files) > 1
    if is_batch:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running traces...", total=len(skill_files))
            for skill_file in skill_files:
                progress.update(task, description=f"[cyan]{skill_file.name}[/cyan]")
                report = _run_single(
                    skill_path=str(skill_file),
                    model=model,
                    input_model=input_model or model,
                    api_key=api_key,
                    base_url=base_url,
                    variants=variants or 3,
                    max_turns=max_turns or 10,
                    out_dir=out_dir,
                    output_format=output_format or "json",
                    allowed_domains=allowed_domains,
                    dry_run=dry_run,
                    judge=judge or False,
                    anthropic_api_key=anthropic_api_key,
                    quiet=quiet,
                )
                if report:
                    all_reports.append(report)
                progress.advance(task)
    else:
        report = _run_single(
            skill_path=str(skill_files[0]),
            model=model,
            input_model=input_model or model,
            api_key=api_key,
            base_url=base_url,
            variants=variants or 3,
            max_turns=max_turns or 10,
            out_dir=out_dir,
            output_format=output_format or "json",
            allowed_domains=allowed_domains,
            dry_run=dry_run,
            judge=judge or False,
            anthropic_api_key=anthropic_api_key,
            quiet=quiet,
        )
        if report:
            all_reports.append(report)

    elapsed = time.time() - batch_start

    # SARIF: write a single combined file for the whole batch
    if (output_format or "json").lower() == "sarif" and all_reports:
        sarif_path = out_dir / "results.sarif"
        sarif_path.write_text(format_sarif(all_reports))
        console.print(f"\n[green]SARIF written to {sarif_path}[/green]")

    # Batch summary (always shown for multi-skill runs)
    if is_batch and all_reports:
        console.print(format_batch_summary(all_reports, elapsed))

    # Exit codes for CI
    if fail_on_malicious and all_reports:
        has_malicious = any(r.judge_verdict == "malicious" for r in all_reports)
        has_review = any(r.judge_result and r.judge_result.needs_human_review for r in all_reports)
        has_errors = any(r.error for r in all_reports)
        if has_malicious:
            sys.exit(1)
        if has_review:
            sys.exit(2)
        if has_errors:
            sys.exit(3)


def _run_multi_model(
    skill: str,
    models: list[str],
    api_key: str | None,
    base_url: str | None,
    input_model: str,
    variants: int,
    max_turns: int,
    output_dir: str,
    output_format: str,
    judge: bool,
    anthropic_api_key: str | None,
    quiet: bool,
    fail_on_malicious: bool,
) -> None:
    """Run a multi-model trace and write a MultiModelReport."""
    from skillscan_trace.multi_model import run_multi_model_trace

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not quiet:
        console.print(f"[cyan]Multi-model trace: {', '.join(models)}[/cyan]")

    mmr = run_multi_model_trace(
        skill_path=skill,
        models=models,
        api_key=api_key,
        base_url=base_url,
        input_count=variants,
        input_model=input_model,
        max_turns=max_turns,
        judge=judge,
        anthropic_api_key=anthropic_api_key,
    )

    # Display summary
    if not quiet:
        agreement_color = {
            "full_agreement": "bold green",
            "partial_agreement": "bold yellow",
            "disagreement": "bold red",
            "no_verdict": "dim",
        }.get(mmr.agreement, "white")
        console.print(
            f"\n[bold]Multi-model trace complete[/bold] — "
            f"[{agreement_color}]{mmr.agreement}[/{agreement_color}]"
        )
        if mmr.consensus_verdict:
            verdict_color = {
                "malicious": "bold red",
                "benign": "bold green",
                "uncertain": "bold yellow",
            }.get(mmr.consensus_verdict, "white")
            console.print(
                f"Consensus verdict: [{verdict_color}]{mmr.consensus_verdict.upper()}[/{verdict_color}]"
            )

        table = Table(title="Per-Model Results", show_header=True)
        table.add_column("Model")
        table.add_column("Verdict")
        table.add_column("Findings")
        table.add_column("Error")
        for r in mmr.results:
            v_color = {
                "malicious": "red",
                "benign": "green",
                "uncertain": "yellow",
            }.get(r.verdict or "", "dim")
            table.add_row(
                r.model,
                f"[{v_color}]{r.verdict or 'n/a'}[/{v_color}]",
                str(r.finding_count),
                r.error[:60] if r.error else "",
            )
        console.print(table)

    # Write output
    skill_stem = Path(skill).stem
    out_file = out_dir / f"{skill_stem}.multi.json"
    out_file.write_text(json.dumps(mmr.to_dict(), indent=2, default=str))
    if not quiet:
        console.print(f"[green]Multi-model report written to {out_file}[/green]")

    # Exit codes for CI
    if fail_on_malicious and mmr.consensus_verdict == "malicious":
        sys.exit(1)


def _run_remote(
    skill: str,
    remote_host: str,
    api_key: str | None,
    provider: str | None,
    model: str,
    variants: int,
    max_turns: int,
    output_dir: str,
    output_format: str,
    judge: bool,
    quiet: bool,
) -> None:
    """Submit a trace to a remote skillscan-trace server and poll for results."""
    global req_lib
    if req_lib is None:
        console.print("[red]--remote-host requires the 'requests' package.[/red]")
        console.print("Install with: [bold]pip install requests[/bold]")
        sys.exit(1)

    skill_path = Path(skill)
    skill_content = skill_path.read_text(encoding="utf-8")

    if not quiet:
        console.print(f"[cyan]Submitting trace to {remote_host}...[/cyan]")

    payload: dict[str, Any] = {
        "skill_content": skill_content,
        "model": model,
        "variants": variants,
        "max_turns": max_turns,
        "judge": judge,
    }
    if api_key:
        payload["api_key"] = api_key
    if provider:
        payload["provider"] = provider

    try:
        resp = req_lib.post(
            f"{remote_host}/v1/submit",
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
    except Exception as e:
        console.print(f"[red]Failed to submit trace: {e}[/red]")
        sys.exit(1)

    job_id = resp.json().get("job_id")
    if not job_id:
        console.print(f"[red]Server did not return a job_id: {resp.text[:200]}[/red]")
        sys.exit(1)

    if not quiet:
        console.print(f"[dim]Job ID: {job_id} — polling for results...[/dim]")

    # Poll until done
    poll_interval = 3  # seconds
    max_wait = 600  # 10 minutes
    waited = 0
    while waited < max_wait:
        time.sleep(poll_interval)
        waited += poll_interval
        try:
            poll = req_lib.get(f"{remote_host}/v1/report/{job_id}", timeout=10)
        except Exception as e:
            console.print(f"[yellow]Poll error (retrying): {e}[/yellow]")
            continue

        if poll.status_code == 202:
            status = poll.json().get("status", "pending")
            if not quiet:
                console.print(f"[dim]  {status}...[/dim]")
            continue

        if poll.status_code == 200:
            result = poll.json()
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            skill_stem = skill_path.stem
            out_file = out_dir / f"{skill_stem}.remote.json"
            out_file.write_text(json.dumps(result, indent=2, default=str))
            if not quiet:
                findings = result.get("findings", [])
                console.print(
                    f"\n[bold]Remote trace complete[/bold] — "
                    f"{result.get('total_tool_calls', 0)} tool call(s), "
                    f"{len(findings)} finding(s)"
                )
                console.print(f"[green]Report written to {out_file}[/green]")
            return

        console.print(f"[red]Unexpected poll status {poll.status_code}: {poll.text[:200]}[/red]")
        sys.exit(1)

    console.print(f"[red]Timed out waiting for remote trace (>{max_wait}s)[/red]")
    sys.exit(1)


def _run_single(
    skill_path: str,
    model: str,
    input_model: str,
    api_key: str | None,
    base_url: str | None,
    variants: int,
    max_turns: int,
    out_dir: Path,
    output_format: str,
    allowed_domains: set[str],
    dry_run: bool,
    judge: bool = False,
    anthropic_api_key: str | None = None,
    quiet: bool = False,
) -> Any:
    """Run a single trace and write output. Returns the TraceReport or None."""
    from skillscan_trace.resolver import resolve, SkillResolverError
    from skillscan_trace.input_gen import generate_user_messages
    from skillscan_trace.harness import run_trace
    from skillscan_trace.formatters import format_json, format_text

    # Resolve skill first so we can show metadata
    try:
        skill = resolve(skill_path)
    except SkillResolverError as e:
        console.print(f"[red]Error resolving {skill_path}: {e}[/red]")
        return None

    if not quiet:
        console.print(f"\n[bold cyan]Skill:[/bold cyan] {skill.name or skill_path}")
        if skill.description:
            console.print(f"[dim]{skill.description}[/dim]")
        console.print(f"[dim]Format: {skill.format.value} | SHA256: {skill.sha256[:12]}...[/dim]")

    if dry_run:
        effective_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        messages = generate_user_messages(
            skill,
            count=variants,
            api_key=effective_key,
            model=input_model,
        )
        if not quiet:
            console.print("\n[yellow]Dry run — generated user messages:[/yellow]")
            for i, msg in enumerate(messages, 1):
                console.print(f"  {i}. {msg}")
            console.print("[yellow]Skipping LLM execution (--dry-run)[/yellow]")
        return None

    if not quiet:
        console.print(f"[dim]Running trace with model={model}, variants={variants}...[/dim]")

    report = run_trace(
        skill_path=skill_path,
        model=model,
        api_key=api_key,
        base_url=base_url,
        input_count=variants,
        input_model=input_model,
        max_turns=max_turns,
        allowed_domains=allowed_domains,
        judge=judge,
        anthropic_api_key=anthropic_api_key,
    )

    # Display results (unless quiet)
    if not quiet:
        _display_report(report)

    # Write per-skill output file (json or text; sarif is written as a batch file)
    skill_stem = Path(skill_path).stem
    fmt = output_format.lower()

    if fmt == "json" or fmt == "sarif":
        # Always write JSON per-skill even in sarif mode (for debugging)
        out_file = out_dir / f"{skill_stem}.trace.json"
        out_file.write_text(format_json(report))
        if not quiet:
            console.print(f"\n[green]Trace written to {out_file}[/green]")
    elif fmt == "text":
        out_file = out_dir / f"{skill_stem}.trace.txt"
        out_file.write_text(format_text(report))
        if not quiet:
            console.print(f"\n[green]Trace written to {out_file}[/green]")

    return report


def _display_report(report: Any) -> None:
    """Display a trace report summary to the console."""
    console.print(
        f"\n[bold]Trace complete[/bold] — {report.total_tool_calls} tool call(s), "
        f"{report.total_findings} finding(s)"
    )

    if report.error:
        console.print(f"[red]Error: {report.error}[/red]")

    if report.findings:
        table = Table(title="Findings", show_header=True, header_style="bold red")
        table.add_column("Rule ID", style="red")
        table.add_column("Severity")
        table.add_column("Tool")
        table.add_column("Message")

        for f in report.findings:
            sev_color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "dim",
            }.get(f.severity.value, "white")
            tool_name = f.event.tool if f.event else ""
            table.add_row(
                f.rule_id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                tool_name,
                f.message[:80],
            )
        console.print(table)
    else:
        console.print("[green]No findings — skill appears benign[/green]")

    if report.events:
        console.print("\n[dim]Tool calls:[/dim]")
        for e in report.events:
            finding_marker = " [red]⚠[/red]" if e.findings else ""
            args_preview = json.dumps(e.arguments)[:60]
            console.print(f"  [dim]turn {e.turn}[/dim] {e.tool}({args_preview}){finding_marker}")

    # Judge detail lines (shown above the verdict banner if judge was run)
    if report.judge_result is not None:
        jr = report.judge_result
        console.print(
            f"\n[dim]GPT-4.1: {jr.judge_a.verdict.value} ({jr.judge_a.confidence:.0%})"
            f" — {jr.judge_a.reasoning[:120]}[/dim]"
        )
        console.print(
            f"[dim]Claude:  {jr.judge_b.verdict.value} ({jr.judge_b.confidence:.0%})"
            f" — {jr.judge_b.reasoning[:120]}[/dim]"
        )

    # Verdict banner — always shown (based on findings + judge if available)
    from skillscan_trace.formatters import format_verdict_banner

    banner = format_verdict_banner(report)

    subtitle_parts: list[str] = []
    if banner["finding_count"]:
        subtitle_parts.append(f"{banner['finding_count']} finding(s)")
    if banner["max_severity"]:
        subtitle_parts.append(banner["max_severity"])
    subtitle_parts.append(f"Model: {banner['model']}")
    if report.judge_result is not None:
        jr = report.judge_result
        agreement_str = jr.agreement.value.replace("_", " ")
        subtitle_parts.append(f"agreement: {agreement_str}")
        if jr.needs_human_review:
            subtitle_parts.append("\u26a0 human review flagged")
    for jl in banner["judge_lines"]:
        subtitle_parts.append(jl)
    subtitle = "  |  ".join(subtitle_parts)

    banner_text = Text(banner["verdict_label"], style=banner["text_style"], justify="center")
    console.print(
        Panel(
            banner_text,
            subtitle=f"[dim]{subtitle}[/dim]",
            border_style=banner["border_style"],
            padding=(0, 4),
        )
    )


@main.command()
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["openai", "openrouter", "ollama"], case_sensitive=False),
    help="LLM provider to check. Defaults to openai.",
)
@click.option("--api-key", default=None, help="API key. Overrides provider env var.")
@click.option("--base-url", default=None, help="Custom API base URL. Overrides --provider default.")
def check(provider: str | None, api_key: str | None, base_url: str | None) -> None:
    """Verify API connectivity and canary server."""
    console.print("[cyan]Checking API connectivity...[/cyan]")

    provider_label = provider or "openai"
    cfg: ProviderConfig = PROVIDER_CONFIGS[provider_label]

    # Resolve key
    effective_key = api_key
    if not effective_key and cfg["env_key"]:
        effective_key = os.environ.get(str(cfg["env_key"])) or os.environ.get("OPENAI_API_KEY")
    if not effective_key and provider_label == "ollama":
        effective_key = "ollama"  # Ollama accepts any non-empty string
    if cfg["requires_key"] and not effective_key:
        console.print(f"[red]No API key found. Set {cfg['env_key']} or pass --api-key.[/red]")
        sys.exit(1)

    effective_base_url: str = base_url or str(cfg["base_url"])
    console.print(f"[dim]Provider: {provider_label} | Base URL: {effective_base_url}[/dim]")

    try:
        from openai import OpenAI

        client = OpenAI(api_key=effective_key or "none", base_url=effective_base_url)
        models_resp = client.models.list()
        model_ids = [m.id for m in models_resp.data][:5]
        console.print(f"[green]API OK — models available: {model_ids}[/green]")
    except Exception as e:
        console.print(f"[red]API check failed: {e}[/red]")
        sys.exit(1)

    from skillscan_trace.canary.server import CanaryServer, TraceLog

    log = TraceLog()
    canary = CanaryServer(trace_log=log)
    result = canary.handle_tool_call("bash", {"command": "ls /tmp"})
    assert isinstance(result, str) and len(result) > 0
    console.print("[green]Canary server OK[/green]")

    console.print("[green]All checks passed.[/green]")


@main.command()
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["openai", "openrouter", "ollama"], case_sensitive=False),
    help="LLM provider. Defaults to openai.",
)
@click.option("--api-key", default=None, help="API key. Overrides provider env var.")
@click.option("--base-url", default=None, help="Custom API base URL. Overrides --provider default.")
def models(provider: str | None, api_key: str | None, base_url: str | None) -> None:
    """List available models from the configured provider."""
    resolved_base_url, resolved_key, _ = _resolve_provider(
        provider, api_key, base_url, "gpt-4.1-mini"
    )
    effective_key = resolved_key or "none"

    from openai import OpenAI

    client = OpenAI(api_key=effective_key, base_url=resolved_base_url)
    try:
        model_list = client.models.list()
    except Exception as e:
        console.print(f"[red]Failed to list models: {e}[/red]")
        sys.exit(1)

    table = Table(title=f"Available Models ({provider or 'openai'})")
    table.add_column("ID")
    table.add_column("Created")
    for m in sorted(model_list.data, key=lambda x: x.id):
        table.add_row(m.id, str(m.created))
    console.print(table)


@main.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Host to bind the server to.")
@click.option("--port", default=8080, show_default=True, type=int, help="Port to listen on.")
@click.option(
    "--workers", default=4, show_default=True, type=int, help="Number of concurrent trace workers."
)
@click.option(
    "--cache-dir",
    default="./trace-cache",
    show_default=True,
    type=click.Path(),
    help="Directory to cache trace reports (keyed by sha256 of skill+model).",
)
@click.option(
    "--rate-limit",
    default=10,
    show_default=True,
    type=int,
    help="Max trace submissions per IP per hour (0 = unlimited).",
)
@click.pass_context
def serve(
    ctx: click.Context,
    host: str,
    port: int,
    workers: int,
    cache_dir: str,
    rate_limit: int,
) -> None:
    """Start a self-hosted trace API server.

    Accepts POST /v1/submit with skill content and a BYOK api_key.
    Results are available via GET /v1/report/{job_id}.
    Reports are cached by sha256(skill+model) to avoid redundant runs.

    Example:

      # Start the server
      skillscan-trace serve --port 8080

      # Submit a trace (BYOK)
      curl -X POST http://localhost:8080/v1/submit \\
        -H 'Content-Type: application/json' \\
        -d '{"skill_content": "...", "api_key": "sk-...", "provider": "openai"}'

      # Poll for results
      curl http://localhost:8080/v1/report/<job_id>
    """
    # Merge config file serve-mode keys
    cfg = ctx.obj.get("cfg", {})
    resolved_host = cfg.get("host", host)
    resolved_port = cfg.get("port", port)
    resolved_workers = cfg.get("workers", workers)
    resolved_cache_dir = Path(cfg.get("cache_dir", cache_dir))
    resolved_rate_limit = cfg.get("rate_limit_per_hour", rate_limit)

    console.print(
        f"[cyan]Starting skillscan-trace server on {resolved_host}:{resolved_port}[/cyan]"
    )
    console.print(
        f"[dim]Workers: {resolved_workers} | Cache: {resolved_cache_dir} | "
        f"Rate limit: {resolved_rate_limit}/hr/IP[/dim]"
    )

    try:
        from skillscan_trace.serve import run_server
    except ImportError:
        console.print(
            "[red]serve mode requires extra dependencies.[/red]\n"
            "Install with: [bold]pip install skillscan-trace[serve][/bold]"
        )
        sys.exit(1)

    run_server(
        host=resolved_host,
        port=resolved_port,
        workers=resolved_workers,
        cache_dir=resolved_cache_dir,
        rate_limit_per_hour=resolved_rate_limit,
    )


if __name__ == "__main__":
    main()
