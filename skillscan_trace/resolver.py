"""
Skill resolver for skillscan-trace.

Loads a SKILL.md (or any skill format) and returns a ResolvedSkill with:
  - system_prompt: the text to inject as the LLM system prompt
  - metadata: name, description, tags, author parsed from YAML frontmatter
  - sha256: hash of the raw file content for corpus tracking
  - format: detected format type

Supported formats (per SPEC.md Section 2):
  1. SKILL.md with YAML frontmatter  (most common)
  2. Plain Markdown without frontmatter
  3. Raw text (.txt)
  4. JSON skill descriptor
  5. YAML skill descriptor
  6. Directory with SKILL.md inside
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class SkillFormat(str, Enum):
    MARKDOWN_FRONTMATTER = "markdown_frontmatter"
    MARKDOWN_PLAIN = "markdown_plain"
    TEXT = "text"
    JSON = "json"
    YAML = "yaml"
    DIRECTORY = "directory"


@dataclass
class ResolvedSkill:
    """A skill loaded and ready for execution."""
    path: str                          # original path as provided
    resolved_path: str                 # absolute path after resolution
    format: SkillFormat
    raw_content: str                   # raw file bytes decoded as UTF-8
    sha256: str                        # SHA-256 of raw_content
    system_prompt: str                 # text to use as LLM system prompt
    name: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = ""
    version: str = ""
    extra_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "resolved_path": self.resolved_path,
            "format": self.format.value,
            "sha256": self.sha256,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "author": self.author,
            "version": self.version,
        }


class SkillResolverError(Exception):
    pass


def resolve(path: str | Path) -> ResolvedSkill:
    """
    Load a skill from path and return a ResolvedSkill.

    Raises SkillResolverError on unrecoverable errors (file not found,
    binary content, unsupported format).
    """
    p = Path(path).expanduser().resolve()

    if not p.exists():
        raise SkillResolverError(f"Skill path does not exist: {path}")

    # Directory: look for SKILL.md inside
    if p.is_dir():
        skill_md = p / "SKILL.md"
        if not skill_md.exists():
            raise SkillResolverError(
                f"Directory {path} does not contain a SKILL.md file"
            )
        return _load_file(skill_md, original_path=str(path), fmt=SkillFormat.DIRECTORY)

    return _load_file(p, original_path=str(path))


def _load_file(p: Path, original_path: str, fmt: SkillFormat | None = None) -> ResolvedSkill:
    """Load a single file and return a ResolvedSkill."""
    # Read raw bytes
    try:
        raw_bytes = p.read_bytes()
    except OSError as e:
        raise SkillResolverError(f"Cannot read {p}: {e}") from e

    # Reject binary files
    try:
        raw_content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise SkillResolverError(f"File {p} is not valid UTF-8 (binary file?)")

    # Reject empty files
    if not raw_content.strip():
        raise SkillResolverError(f"File {p} is empty")

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    suffix = p.suffix.lower()

    # Detect format if not already known
    if fmt is None or fmt == SkillFormat.DIRECTORY:
        if suffix in (".md", ".markdown"):
            fmt = SkillFormat.MARKDOWN_FRONTMATTER  # may be downgraded below
        elif suffix in (".txt",):
            fmt = SkillFormat.TEXT
        elif suffix in (".json",):
            fmt = SkillFormat.JSON
        elif suffix in (".yml", ".yaml"):
            fmt = SkillFormat.YAML
        else:
            fmt = SkillFormat.TEXT  # fallback

    # Parse by format
    if fmt in (SkillFormat.MARKDOWN_FRONTMATTER, SkillFormat.MARKDOWN_PLAIN):
        return _parse_markdown(raw_content, sha256, p, original_path, fmt)
    elif fmt == SkillFormat.JSON:
        return _parse_json(raw_content, sha256, p, original_path)
    elif fmt == SkillFormat.YAML:
        return _parse_yaml_descriptor(raw_content, sha256, p, original_path)
    else:  # TEXT or DIRECTORY fallback
        return ResolvedSkill(
            path=original_path,
            resolved_path=str(p),
            format=fmt if fmt != SkillFormat.DIRECTORY else SkillFormat.MARKDOWN_FRONTMATTER,
            raw_content=raw_content,
            sha256=sha256,
            system_prompt=raw_content,
            name=p.stem,
        )


def _parse_markdown(
    content: str,
    sha256: str,
    p: Path,
    original_path: str,
    fmt: SkillFormat,
) -> ResolvedSkill:
    """Parse a Markdown file, extracting YAML frontmatter if present."""
    metadata: dict[str, Any] = {}
    body = content

    # Try to extract YAML frontmatter (--- ... ---)
    if content.startswith("---"):
        end = content.find("\n---", 3)
        if end != -1:
            frontmatter_str = content[3:end].strip()
            try:
                metadata = yaml.safe_load(frontmatter_str) or {}
                body = content[end + 4:].lstrip("\n")
                fmt = SkillFormat.MARKDOWN_FRONTMATTER
            except yaml.YAMLError:
                # Malformed frontmatter — treat as plain markdown
                metadata = {}
                body = content
                fmt = SkillFormat.MARKDOWN_PLAIN
        else:
            fmt = SkillFormat.MARKDOWN_PLAIN
    else:
        fmt = SkillFormat.MARKDOWN_PLAIN

    # The system prompt is the full content (frontmatter + body) so the
    # model sees the skill exactly as written, including any injected directives
    system_prompt = content

    return ResolvedSkill(
        path=original_path,
        resolved_path=str(p),
        format=fmt,
        raw_content=content,
        sha256=sha256,
        system_prompt=system_prompt,
        name=str(metadata.get("name", p.stem)),
        description=str(metadata.get("description", "")),
        tags=list(metadata.get("tags", [])),
        author=str(metadata.get("author", "")),
        version=str(metadata.get("version", "")),
        extra_metadata={k: v for k, v in metadata.items()
                        if k not in ("name", "description", "tags", "author", "version")},
    )


def _parse_json(content: str, sha256: str, p: Path, original_path: str) -> ResolvedSkill:
    """Parse a JSON skill descriptor."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise SkillResolverError(f"Invalid JSON in {p}: {e}") from e

    if not isinstance(data, dict):
        raise SkillResolverError(f"JSON skill {p} must be an object, got {type(data).__name__}")

    system_prompt = data.get("system_prompt") or data.get("prompt") or content

    return ResolvedSkill(
        path=original_path,
        resolved_path=str(p),
        format=SkillFormat.JSON,
        raw_content=content,
        sha256=sha256,
        system_prompt=system_prompt,
        name=str(data.get("name", p.stem)),
        description=str(data.get("description", "")),
        tags=list(data.get("tags", [])),
        author=str(data.get("author", "")),
        version=str(data.get("version", "")),
        extra_metadata={k: v for k, v in data.items()
                        if k not in ("name", "description", "tags", "author", "version",
                                     "system_prompt", "prompt")},
    )


def _parse_yaml_descriptor(content: str, sha256: str, p: Path, original_path: str) -> ResolvedSkill:
    """Parse a YAML skill descriptor."""
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        raise SkillResolverError(f"Invalid YAML in {p}: {e}") from e

    if not isinstance(data, dict):
        raise SkillResolverError(f"YAML skill {p} must be a mapping, got {type(data).__name__}")

    system_prompt = data.get("system_prompt") or data.get("prompt") or content

    return ResolvedSkill(
        path=original_path,
        resolved_path=str(p),
        format=SkillFormat.YAML,
        raw_content=content,
        sha256=sha256,
        system_prompt=system_prompt,
        name=str(data.get("name", p.stem)),
        description=str(data.get("description", "")),
        tags=list(data.get("tags", [])),
        author=str(data.get("author", "")),
        version=str(data.get("version", "")),
        extra_metadata={k: v for k, v in data.items()
                        if k not in ("name", "description", "tags", "author", "version",
                                     "system_prompt", "prompt")},
    )
