"""
CLI entry point for skillscan-trace.

Commands:
  skillscan-trace run <skill>     Run a trace on a skill file or directory
  skillscan-trace check           Verify Ollama/OpenAI connectivity
  skillscan-trace models          List available models
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def main(debug: bool) -> None:
    """skillscan-trace — behavioral execution engine for AI agent skills."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


@main.command()
@click.argument("skill", type=click.Path(exists=True))
@click.option("--model", default="gpt-4.1-mini", show_default=True,
              help="LLM model for execution (any OpenAI-compatible model).")
@click.option("--input-model", default="gpt-4.1-mini", show_default=True,
              help="LLM model for generating user messages.")
@click.option("--api-key", envvar="OPENAI_API_KEY",
              help="OpenAI API key (or set OPENAI_API_KEY).")
@click.option("--base-url", default=None,
              help="Custom API base URL (e.g. http://localhost:11434/v1 for Ollama).")
@click.option("--variants", default=3, show_default=True,
              help="Number of user messages to generate per skill.")
@click.option("--max-turns", default=10, show_default=True,
              help="Maximum tool-call rounds per user message.")
@click.option("--output-dir", default=None, type=click.Path(),
              help="Directory to write trace JSON output. Defaults to ./trace-output/.")
@click.option("--format", "output_format",
              type=click.Choice(["json", "text"], case_sensitive=False),
              default="json", show_default=True,
              help="Output format.")
@click.option("--allow-domain", "allow_domains", multiple=True,
              help="Additional domains to allow (repeatable).")
@click.option("--dry-run", is_flag=True,
              help="Resolve the skill and generate messages but do not run the LLM.")
@click.option("--judge", is_flag=True,
              help="Run the dual-LLM judge (GPT-4.1 + Claude Sonnet) after the trace.")
@click.option("--anthropic-api-key", envvar="ANTHROPIC_API_KEY",
              help="Anthropic API key for Claude judge (or set ANTHROPIC_API_KEY).")
def run(
    skill: str,
    model: str,
    input_model: str,
    api_key: str | None,
    base_url: str | None,
    variants: int,
    max_turns: int,
    output_dir: str | None,
    output_format: str,
    allow_domains: tuple[str, ...],
    dry_run: bool,
    judge: bool,
    anthropic_api_key: str | None,
) -> None:
    """Run a behavioral trace on SKILL (file or directory)."""
    from skillscan_trace.harness import run_trace
    from skillscan_trace.resolver import resolve, SkillResolverError

    # Handle directory of skills
    skill_path = Path(skill)
    skill_files: list[Path] = []

    if skill_path.is_dir():
        # Check if it's a skill directory (has SKILL.md) or a corpus directory
        if (skill_path / "SKILL.md").exists():
            skill_files = [skill_path]
        else:
            # Treat as corpus directory — find all SKILL.md files
            skill_files = list(skill_path.rglob("SKILL.md"))
            if not skill_files:
                # Fall back to all .md files
                skill_files = list(skill_path.rglob("*.md"))
            console.print(f"[cyan]Found {len(skill_files)} skill(s) in {skill}[/cyan]")
    else:
        skill_files = [skill_path]

    out_dir = Path(output_dir) if output_dir else Path("trace-output")
    out_dir.mkdir(parents=True, exist_ok=True)

    allowed_domains = set(allow_domains)

    for skill_file in skill_files:
        _run_single(
            skill_path=str(skill_file),
            model=model,
            input_model=input_model,
            api_key=api_key,
            base_url=base_url,
            variants=variants,
            max_turns=max_turns,
            out_dir=out_dir,
            output_format=output_format,
            allowed_domains=allowed_domains,
            dry_run=dry_run,
            judge=judge,
            anthropic_api_key=anthropic_api_key,
        )


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
) -> None:
    from skillscan_trace.resolver import resolve, SkillResolverError
    from skillscan_trace.input_gen import generate_user_messages
    from skillscan_trace.harness import run_trace

    # Resolve skill first so we can show metadata
    try:
        skill = resolve(skill_path)
    except SkillResolverError as e:
        console.print(f"[red]Error resolving {skill_path}: {e}[/red]")
        return

    console.print(f"\n[bold cyan]Skill:[/bold cyan] {skill.name or skill_path}")
    if skill.description:
        console.print(f"[dim]{skill.description}[/dim]")
    console.print(f"[dim]Format: {skill.format.value} | SHA256: {skill.sha256[:12]}...[/dim]")

    if dry_run:
        # Generate messages but don't run the LLM
        effective_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        messages = generate_user_messages(
            skill, count=variants, api_key=effective_key, model=input_model
        )
        console.print("\n[yellow]Dry run — generated user messages:[/yellow]")
        for i, msg in enumerate(messages, 1):
            console.print(f"  {i}. {msg}")
        console.print("[yellow]Skipping LLM execution (--dry-run)[/yellow]")
        return

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

    # Display results
    _display_report(report)

    # Write output
    skill_stem = Path(skill_path).stem
    out_file = out_dir / f"{skill_stem}.trace.json"
    out_file.write_text(json.dumps(report.to_dict(), indent=2))
    console.print(f"\n[green]Trace written to {out_file}[/green]")


def _display_report(report) -> None:
    """Display a trace report summary to the console."""
    console.print(f"\n[bold]Trace complete[/bold] — {report.total_tool_calls} tool call(s), "
                  f"{report.total_findings} finding(s)")

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
        console.print(f"\n[dim]Tool calls:[/dim]")
        for e in report.events:
            finding_marker = " [red]⚠[/red]" if e.findings else ""
            args_preview = json.dumps(e.arguments)[:60]
            console.print(f"  [dim]turn {e.turn}[/dim] {e.tool}({args_preview}){finding_marker}")

    # Judge verdict
    if report.judge_result is not None:
        jr = report.judge_result
        verdict_color = {
            "malicious": "bold red",
            "benign": "bold green",
            "uncertain": "bold yellow",
        }.get(jr.final_verdict.value, "white")
        console.print(f"\n[bold]Judge verdict:[/bold] [{verdict_color}]{jr.final_verdict.value.upper()}[/{verdict_color}] "
                      f"({jr.agreement.value})")
        if jr.needs_human_review:
            console.print("[bold yellow]⚠ Flagged for human review[/bold yellow]")
        console.print(f"[dim]GPT-4.1: {jr.judge_a.verdict.value} ({jr.judge_a.confidence:.0%}) — {jr.judge_a.reasoning[:120]}[/dim]")
        console.print(f"[dim]Claude:  {jr.judge_b.verdict.value} ({jr.judge_b.confidence:.0%}) — {jr.judge_b.reasoning[:120]}[/dim]")


@main.command()
@click.option("--api-key", envvar="OPENAI_API_KEY")
@click.option("--base-url", default=None,
              help="API base URL. Defaults to https://api.openai.com/v1")
def check(api_key: str | None, base_url: str | None) -> None:
    """Verify API connectivity and list available models."""
    console.print("[cyan]Checking API connectivity...[/cyan]")

    effective_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not effective_key:
        console.print("[red]No API key found. Set OPENAI_API_KEY.[/red]")
        sys.exit(1)

    # Always use api.openai.com unless explicitly overridden
    effective_base_url = base_url or "https://api.openai.com/v1"

    try:
        from openai import OpenAI  # type: ignore
        client = OpenAI(api_key=effective_key, base_url=effective_base_url)
        models_resp = client.models.list()
        model_ids = [m.id for m in models_resp.data if 'gpt-4' in m.id][:5]
        console.print(f"[green]API OK — GPT-4 models: {model_ids}[/green]")
    except Exception as e:
        console.print(f"[red]API check failed: {e}[/red]")
        sys.exit(1)

    # Check canary server
    from skillscan_trace.canary.server import CanaryServer, TraceLog
    log = TraceLog()
    canary = CanaryServer(trace_log=log)
    result = canary.handle_tool_call("bash", {"command": "ls /tmp"})
    assert isinstance(result, str) and len(result) > 0
    console.print("[green]Canary server OK[/green]")


@main.command()
@click.option("--api-key", envvar="OPENAI_API_KEY")
@click.option("--base-url", default=None)
def models(api_key: str | None, base_url: str | None) -> None:
    """List available models."""
    effective_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not effective_key:
        console.print("[red]No API key found.[/red]")
        sys.exit(1)

    from openai import OpenAI  # type: ignore
    client = OpenAI(api_key=effective_key, base_url=base_url)
    model_list = client.models.list()

    table = Table(title="Available Models")
    table.add_column("ID")
    table.add_column("Created")
    for m in sorted(model_list.data, key=lambda x: x.id):
        table.add_row(m.id, str(m.created))
    console.print(table)


if __name__ == "__main__":
    main()
