"""
SkillManager
============
Loads Markdown skill packs and injects relevant ones into LLM prompts.

Skill sources (searched in order):
  1. Built-in packs shipped with XScan  (src/xscan/skills/packs/)
  2. User-installed packs               (~/.xscan/skills/)

A skill is a plain Markdown file. Its frontmatter declares:
  - tags: list of keywords that trigger this skill
  - category: xss | framework | analysis | misc

The manager selects skills by matching tags against the current
analysis context (technology stack, injection context, etc.).

Usage::

    manager = SkillManager()
    # Get skills relevant to React + script-block context
    context = manager.for_context(techs=["React","jQuery"], context="script-block")
    # Inject into LLM prompt
    skill_text = manager.render(context)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Built-in skill packs live next to this file
_BUILTIN_DIR = Path(__file__).parent / "packs"
_USER_DIR = Path.home() / ".xscan" / "skills"


@dataclass
class Skill:
    name: str
    path: Path
    tags: list[str] = field(default_factory=list)
    category: str = "misc"
    content: str = ""

    @property
    def display_name(self) -> str:
        return self.name.replace("-", " ").title()


class SkillManager:
    """Load, list, and select skills for LLM context injection."""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_all(self) -> None:
        """Load all skills from built-in and user directories."""
        self._skills.clear()
        for directory in [_BUILTIN_DIR, _USER_DIR]:
            if directory.exists():
                for md_file in sorted(directory.rglob("*.md")):
                    skill = self._parse(md_file)
                    self._skills[skill.name] = skill
        self._loaded = True

    def list(self) -> list[Skill]:
        """Return all available skills."""
        self._ensure_loaded()
        return sorted(self._skills.values(), key=lambda s: s.name)

    def get(self, name: str) -> Optional[Skill]:
        self._ensure_loaded()
        return self._skills.get(name)

    def for_context(
        self,
        techs: list[str] | None = None,
        context: str = "",
        category: str = "",
        xss_context: str = "",
    ) -> list[Skill]:
        """
        Select skills relevant to the current scan context.

        xss_context maps directly to skill tags:
          html_text                → reflected-html-context
          html_attribute           → reflected-attribute-encoded-angles, context-detection
          script_string_*          → reflected-javascript-string, javascript-context
          dom-xss                  → dom-xss-sources-sinks
          stored                   → stored-xss
          encoded / angle-brackets → reflected-attribute-encoded-angles

        Returns up to 4 most relevant skills.
        """
        self._ensure_loaded()
        techs_lower = {t.lower() for t in (techs or [])}
        context_lower = context.lower()

        # Direct xss_context → skill tag mapping
        _CONTEXT_SKILL_MAP: dict[str, list[str]] = {
            "html_text":              ["reflected-html-context", "context-detection"],
            "html_attribute":         ["reflected-attribute-encoded-angles", "context-detection"],
            "html_attribute_unquoted":["reflected-attribute-encoded-angles", "context-detection"],
            "script_string_double":   ["reflected-javascript-string", "javascript-context"],
            "script_string_single":   ["reflected-javascript-string", "javascript-context"],
            "script_string_template": ["reflected-javascript-string", "javascript-context"],
            "script_expression":      ["reflected-javascript-string", "javascript-context"],
            "dom-xss":                ["dom-xss-sources-sinks", "jquery"],
            "stored":                 ["stored-xss", "candidate-triage"],
            "url_param":              ["reflected-attribute-encoded-angles", "dom-xss-sources-sinks"],
        }

        # Build priority skill set from xss_context
        priority_names: list[str] = []
        if xss_context and xss_context in _CONTEXT_SKILL_MAP:
            priority_names = _CONTEXT_SKILL_MAP[xss_context]
        # Also check context string for context names
        for ctx_key, skill_names in _CONTEXT_SKILL_MAP.items():
            if ctx_key in context_lower:
                for sn in skill_names:
                    if sn not in priority_names:
                        priority_names.append(sn)

        # Collect priority skills first
        result: list[Skill] = []
        for name in priority_names:
            if name in self._skills:
                result.append(self._skills[name])

        # Score remaining skills by tag match
        scored: list[tuple[int, Skill]] = []
        already = {s.name for s in result}
        for skill in self._skills.values():
            if skill.name in already:
                continue
            score = 0
            for tag in skill.tags:
                tl = tag.lower()
                if tl in techs_lower:
                    score += 3
                if tl in context_lower:
                    score += 2
                if category and tl == category.lower():
                    score += 1
            if score > 0:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        result.extend(s for _, s in scored)

        # Always add context-detection and candidate-triage if space allows
        for always in ["context-detection", "candidate-triage"]:
            if always in self._skills and always not in {s.name for s in result}:
                result.append(self._skills[always])

        return result[:5]  # cap at 5 to keep prompt bounded

    def render(self, skills: list[Skill]) -> str:
        """Concatenate selected skill content for LLM injection."""
        if not skills:
            return ""
        parts = ["## XScan Skills\n"]
        for skill in skills:
            parts.append(f"### {skill.display_name}\n{skill.content}\n")
        return "\n".join(parts)

    def install(self, source_path: Path) -> Skill:
        """Copy a skill file into ~/.xscan/skills/ and register it."""
        _USER_DIR.mkdir(parents=True, exist_ok=True)
        dest = _USER_DIR / source_path.name
        dest.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")
        skill = self._parse(dest)
        self._skills[skill.name] = skill
        return skill

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_all()

    @staticmethod
    def _parse(path: Path) -> Skill:
        """Parse a Markdown file, extracting YAML-ish frontmatter if present."""
        text = path.read_text(encoding="utf-8")
        tags: list[str] = []
        category = "misc"
        content = text

        # Simple frontmatter: lines at top starting with "tags:" or "category:"
        if text.startswith("---"):
            end = text.find("---", 3)
            if end != -1:
                front = text[3:end]
                content = text[end + 3:].strip()
                for line in front.splitlines():
                    line = line.strip()
                    if line.startswith("tags:"):
                        raw = line[5:].strip().strip("[]")
                        tags = [t.strip().strip('"').strip("'") for t in raw.split(",") if t.strip()]
                    elif line.startswith("category:"):
                        category = line[9:].strip()

        # Fallback: infer tags from filename + parent dir
        if not tags:
            tags = [path.stem, path.parent.name]

        return Skill(
            name=path.stem,
            path=path,
            tags=tags,
            category=category,
            content=content,
        )


# Module-level singleton
skill_manager = SkillManager()
