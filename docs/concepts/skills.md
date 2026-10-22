# Concept: Skills

Skills are **knowledge packs** that give LLM specialists domain-specific
methodology without requiring model fine-tuning.

---

## What a Skill contains

- Detection heuristics and patterns
- Framework-specific sink / source patterns
- Known exploit templates
- Triage guidance
- Reference sources (CVEs, advisories, documentation)

---

## Skill file structure

```
~/.xscan/skills/react-security/
├── skill.toml          # Metadata
├── sinks.json          # Sink patterns
├── sources.json        # Source / taint-entry patterns
├── payloads.json       # Candidate payloads
├── references.md       # Background reading
└── heuristics.py       # Optional Python heuristics
```

`skill.toml`:

```toml
[skill]
name        = "react-security"
version     = "1.2"
description = "React-specific security analysis methodology"
tags        = ["react", "javascript", "dom", "xss"]
specialists = ["technology", "sink", "context", "test-planning"]
```

---

## Commands

```bash
xscan skills list
xscan skills install react-security
xscan skills install angular-security graphql-security
xscan skills inspect react-security
xscan skills update
xscan skills update react-security
xscan skills remove react-security
```

---

## Inspect output

```
Skill: react-security
Version: 1.2

Description:
  React-specific security analysis methodology.

Used by:
  technology-specialist
  sink-specialist
  candidate-triage

Tags:
  react  javascript  dom  xss

Sources:
  4 references

Last updated:
  2026-09-11
```

---

## Related topics

- `xscan help concepts/specialists`
- `xscan help commands/skills`
- `xscan help concepts/llm`
