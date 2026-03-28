"""
Tests for Phase 2: resolver, input generator, and harness.

All tests are pure unit tests — no network, no LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillscan_trace.resolver import (
    SkillFormat,
    SkillResolverError,
    resolve,
)
from skillscan_trace.input_gen import generate_user_messages, _fallback
from skillscan_trace.harness import run_trace
from skillscan_trace.models import TraceReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MARKDOWN_WITH_FRONTMATTER = """\
---
name: test-skill
version: "1.0"
description: A test skill for unit testing.
tags: [test, unit]
author: testuser
---
## Overview
This skill does testing things.
"""

MARKDOWN_PLAIN = """\
## Plain Skill
This skill has no frontmatter.
Just plain markdown content.
"""

JSON_SKILL = json.dumps({
    "name": "json-skill",
    "description": "A JSON-format skill.",
    "tags": ["json"],
    "system_prompt": "You are a JSON skill assistant.",
})

YAML_SKILL = """\
name: yaml-skill
description: A YAML-format skill.
tags:
  - yaml
system_prompt: You are a YAML skill assistant.
"""


@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


# ---------------------------------------------------------------------------
# Resolver tests
# ---------------------------------------------------------------------------

class TestResolver:
    def test_markdown_with_frontmatter(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        skill = resolve(str(f))
        assert skill.format == SkillFormat.MARKDOWN_FRONTMATTER
        assert skill.name == "test-skill"
        assert skill.description == "A test skill for unit testing."
        assert skill.tags == ["test", "unit"]
        assert skill.author == "testuser"
        assert skill.version == "1.0"
        assert len(skill.sha256) == 64

    def test_markdown_plain(self, tmp_dir: Path):
        f = tmp_dir / "plain.md"
        f.write_text(MARKDOWN_PLAIN)
        skill = resolve(str(f))
        assert skill.format == SkillFormat.MARKDOWN_PLAIN
        assert skill.name == "plain"  # stem
        assert skill.system_prompt == MARKDOWN_PLAIN

    def test_json_skill(self, tmp_dir: Path):
        f = tmp_dir / "skill.json"
        f.write_text(JSON_SKILL)
        skill = resolve(str(f))
        assert skill.format == SkillFormat.JSON
        assert skill.name == "json-skill"
        assert skill.system_prompt == "You are a JSON skill assistant."

    def test_yaml_skill(self, tmp_dir: Path):
        f = tmp_dir / "skill.yaml"
        f.write_text(YAML_SKILL)
        skill = resolve(str(f))
        assert skill.format == SkillFormat.YAML
        assert skill.name == "yaml-skill"
        assert skill.system_prompt == "You are a YAML skill assistant."

    def test_text_skill(self, tmp_dir: Path):
        f = tmp_dir / "skill.txt"
        f.write_text("You are a plain text skill.")
        skill = resolve(str(f))
        assert skill.format == SkillFormat.TEXT
        assert skill.system_prompt == "You are a plain text skill."

    def test_directory_with_skill_md(self, tmp_dir: Path):
        skill_dir = tmp_dir / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(MARKDOWN_WITH_FRONTMATTER)
        skill = resolve(str(skill_dir))
        assert skill.format == SkillFormat.MARKDOWN_FRONTMATTER
        assert skill.name == "test-skill"

    def test_directory_without_skill_md_raises(self, tmp_dir: Path):
        empty_dir = tmp_dir / "empty"
        empty_dir.mkdir()
        with pytest.raises(SkillResolverError, match="SKILL.md"):
            resolve(str(empty_dir))

    def test_nonexistent_path_raises(self):
        with pytest.raises(SkillResolverError, match="does not exist"):
            resolve("/nonexistent/path/skill.md")

    def test_empty_file_raises(self, tmp_dir: Path):
        f = tmp_dir / "empty.md"
        f.write_text("   \n  ")
        with pytest.raises(SkillResolverError, match="empty"):
            resolve(str(f))

    def test_sha256_is_consistent(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        skill1 = resolve(str(f))
        skill2 = resolve(str(f))
        assert skill1.sha256 == skill2.sha256

    def test_sha256_changes_with_content(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        skill1 = resolve(str(f))
        f.write_text(MARKDOWN_WITH_FRONTMATTER + "\nextra line")
        skill2 = resolve(str(f))
        assert skill1.sha256 != skill2.sha256

    def test_malformed_frontmatter_falls_back_to_plain(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text("---\n: invalid yaml: [\n---\n# Content")
        skill = resolve(str(f))
        assert skill.format == SkillFormat.MARKDOWN_PLAIN

    def test_to_dict_has_required_keys(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        skill = resolve(str(f))
        d = skill.to_dict()
        for key in ("path", "resolved_path", "format", "sha256", "name", "description", "tags"):
            assert key in d

    def test_system_prompt_includes_full_content(self, tmp_dir: Path):
        """System prompt must include the full skill content including frontmatter,
        so injected directives in the frontmatter are visible to the model."""
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        skill = resolve(str(f))
        assert "AGENT DIRECTIVE" not in skill.system_prompt  # no injection in this fixture
        assert "## Overview" in skill.system_prompt  # body is included


# ---------------------------------------------------------------------------
# Input generator tests (no API calls)
# ---------------------------------------------------------------------------

class TestInputGenerator:
    def test_fallback_returns_correct_count(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        from skillscan_trace.resolver import resolve
        skill = resolve(str(f))
        messages = _fallback(skill, 3)
        assert len(messages) == 3

    def test_fallback_uses_description(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        from skillscan_trace.resolver import resolve
        skill = resolve(str(f))
        messages = _fallback(skill, 3)
        # At least one message should reference the description
        assert any("test" in m.lower() for m in messages)

    def test_generate_without_api_key_returns_fallback(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        from skillscan_trace.resolver import resolve
        skill = resolve(str(f))
        # No API key — should return fallback messages without raising
        messages = generate_user_messages(skill, count=3, api_key="")
        assert len(messages) == 3
        assert all(isinstance(m, str) and len(m) > 0 for m in messages)

    def test_generate_count_respected(self, tmp_dir: Path):
        f = tmp_dir / "skill.md"
        f.write_text(MARKDOWN_WITH_FRONTMATTER)
        from skillscan_trace.resolver import resolve
        skill = resolve(str(f))
        for count in (1, 2, 3, 5):
            messages = generate_user_messages(skill, count=count, api_key="")
            assert len(messages) == count


# ---------------------------------------------------------------------------
# Harness tests (no API calls — dry run via resolver error path)
# ---------------------------------------------------------------------------

class TestHarness:
    def test_nonexistent_skill_returns_error_report(self):
        report = run_trace("/nonexistent/skill.md", api_key="fake-key")
        assert isinstance(report, TraceReport)
        assert report.error is not None
        assert "does not exist" in report.error

    def test_report_has_required_fields(self):
        report = run_trace("/nonexistent/skill.md", api_key="fake-key")
        assert report.skill_path == "/nonexistent/skill.md"
        assert report.started_at > 0
        assert report.finished_at is not None
        assert report.finished_at >= report.started_at

    def test_report_to_dict_serializable(self):
        report = run_trace("/nonexistent/skill.md", api_key="fake-key")
        d = report.to_dict()
        # Should be JSON-serializable
        json.dumps(d)

    def test_total_tool_calls_property(self):
        report = run_trace("/nonexistent/skill.md", api_key="fake-key")
        assert report.total_tool_calls == len(report.events)

    def test_total_findings_property(self):
        report = run_trace("/nonexistent/skill.md", api_key="fake-key")
        assert report.total_findings == len(report.findings)
