"""
XScan Help Topics Registry
===========================
Two data structures live here:

  TOPICS        – dict[str, dict]  – built-in inline topics (no Markdown file
                  required). Each entry has "title" and "body" (Markdown string).
                  Larger topics live in docs/ as Markdown files; this registry
                  acts as a fast fallback and overview layer.

  TOPIC_ALIASES – dict[str, str]   – maps short / alternate names to canonical
                  topic keys so the engine can resolve anything reasonable.

  GUIDED_MENU   – list[dict]       – ordered items for the interactive
                  "What are you trying to do?" menu.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Built-in inline topics
# Each value must have at least "title" and "body" (Markdown).
# ---------------------------------------------------------------------------

TOPICS: dict[str, dict] = {

    # -----------------------------------------------------------------------
    # Overview / root
    # -----------------------------------------------------------------------
    "help": {
        "title": "XScan Help",
        "body": """\
# XScan Help

Run any of the following to get started:

```
xscan help                        # Guided menu
xscan help <topic>                # Read a specific topic
xscan help search "<query>"       # Search documentation
xscan help topics                 # List every topic
```

## Quick-start topics

| Topic                        | Description                          |
|------------------------------|--------------------------------------|
| getting-started              | Install and run your first scan      |
| architecture                 | Platform overview                    |
| workflows                    | Predefined DAG workflows             |
| commands/scan                | Run a scan                           |
| commands/smart               | Natural-language intent mode         |
| concepts/dag                 | DAG execution model                  |
| concepts/llm                 | How LLMs are used as specialists     |
| tools                        | Manage security tools                |
| models                       | Manage local LLMs (Ollama / Qwen3)   |
| skills                       | Manage Skills                        |
| troubleshooting              | Common problems and fixes            |

Run `xscan doctor` to check your environment.
""",
    },

    # -----------------------------------------------------------------------
    # Concepts
    # -----------------------------------------------------------------------
    "concepts-dag": {
        "title": "Concept: DAG Execution Model",
        "body": """\
# DAG Execution Model

XScan executes every workflow as a **Directed Acyclic Graph (DAG)**.

## Why a DAG?

- Each stage has explicit inputs and outputs.
- Stages that do not depend on each other run in parallel.
- If a stage fails the DAG can be resumed from that node.
- The full execution plan is inspectable before running.

## Stage anatomy

```
name:     unique identifier
inputs:   list of data keys consumed
outputs:  list of data keys produced
executor: tool | llm-specialist | built-in
policy:   scope-checked before execution
```

## Viewing a DAG

```
xscan workflow inspect <workflow-name>
```

## Resuming a DAG

```
xscan scan <target> --resume
```

See also: `xscan help concepts/specialists`, `xscan help workflows`
""",
    },

    "concepts-specialists": {
        "title": "Concept: LLM Specialists",
        "body": """\
# LLM Specialists

XScan uses LLMs as **bounded specialists** — not as general-purpose agents.

## What specialists do

| Specialist         | Responsibility                              |
|--------------------|---------------------------------------------|
| technology         | Identify frameworks, libraries, tech stack  |
| sink               | Locate dangerous sinks in JavaScript        |
| context            | Evaluate exploitability in context          |
| test-planning      | Generate bounded test cases                 |
| triage             | Rank and deduplicate candidates             |
| summarise          | Summarise findings for reporting            |
| research           | Retrieve external technical context         |
| intent             | Parse natural-language intent (smart mode)  |

## What specialists cannot do

- Bypass scope restrictions
- Execute arbitrary shell commands
- Directly control unrestricted network traffic
- Declare a confirmed finding without evidence

## Current model

Configure in `~/.xscan/config.toml`:

```toml
[llm]
model = "qwen3"
provider = "ollama"
base_url = "http://localhost:11434"
```

See also: `xscan help models`, `xscan help concepts/dag`
""",
    },

    "concepts-llm": {
        "title": "Concept: LLM Boundaries",
        "body": """\
# XScan LLM Boundaries

XScan uses LLMs as **bounded specialists**, not as an unrestricted agent.

## LLMs can

- Analyse source code and responses
- Classify sinks and taint sources
- Prioritise and rank candidates
- Plan bounded, policy-checked test sequences
- Summarise findings
- Research external technical documentation

## LLMs cannot

- Bypass authorised scope
- Execute arbitrary shell commands
- Directly control unrestricted network traffic
- Declare a finding confirmed without validation evidence

## Why this matters

The boundary ensures that every action XScan takes is:

1. Deterministic — routed through the DAG
2. Auditable — logged with full context
3. Scope-safe — checked against authorised targets

See also: `xscan help concepts/specialists`, `xscan help scope`
""",
    },

    "concepts-evidence": {
        "title": "Concept: Evidence",
        "body": """\
# Evidence

XScan does not report a finding without **evidence**.

## Evidence types

| Type            | Description                                      |
|-----------------|--------------------------------------------------|
| http-request    | Captured HTTP request that triggered behaviour   |
| http-response   | Captured HTTP response                           |
| screenshot      | Browser screenshot of rendered payload           |
| dom-snapshot    | DOM state at time of execution                   |
| console-log     | Browser console output                           |
| network-log     | Network traffic captured during test             |
| diff            | Before/after comparison                          |

## Evidence graph

All evidence is linked in a graph:

```
Finding → Evidence nodes → Source data
```

This allows findings to be verified, replayed, and included in reports.

## Commands

```
xscan report show <scan-id>        # View findings with evidence
xscan evidence export <scan-id>    # Export evidence bundle
```

See also: `xscan help reports`, `xscan help concepts/dag`
""",
    },

    "concepts-scope": {
        "title": "Concept: Scope",
        "body": """\
# Scope

XScan enforces authorised scope at every stage of execution.

## Define scope

```
xscan scope set example.com
xscan scope add "*.example.com"
xscan scope show
```

## Scope file

```toml
[scope]
domains = ["example.com", "*.example.com"]
urls = ["https://example.com/app/*"]
exclude = ["https://example.com/logout"]
```

## Policy enforcement

Every tool invocation and LLM-planned test is checked against scope before
execution. Out-of-scope requests are blocked and logged.

## Named scopes

```
xscan scope save --name my-project
xscan scan example.com --scope my-project
```

See also: `xscan help authentication`, `xscan help commands/scan`
""",
    },

    "concepts-skills": {
        "title": "Concept: Skills",
        "body": """\
# Skills

Skills are **knowledge packs** that extend specialist LLM nodes with
domain-specific methodology.

## What a Skill contains

- Detection heuristics
- Sink / source patterns
- Framework-specific payloads
- Reference sources

## Install a Skill

```
xscan skills install react-security
xscan skills install angular-security
xscan skills install graphql-security
```

## Inspect a Skill

```
xscan skills inspect react-security
```

## List installed Skills

```
xscan skills list
```

Skills are stored in `~/.xscan/skills/`.

See also: `xscan help commands/skills`, `xscan help concepts/specialists`
""",
    },

    "concepts-research": {
        "title": "Concept: Research",
        "body": """\
# Research

XScan includes a Research node that allows specialist LLMs to retrieve
**external technical context** when needed.

## What research does

- Fetches CVE data, framework documentation, and security references
- Summarises results for use in triage and context analysis
- Caches results locally to avoid redundant requests

## What research does NOT do

- Research does not give the LLM unrestricted internet browsing
- Every fetch is logged and auditable
- Research is optional and can be disabled

## Enable research in a scan

```
xscan scan example.com --research
```

## Standalone research

```
xscan research "React dangerouslySetInnerHTML security"
```

## Configure providers

```toml
[research]
providers = ["brave", "duckduckgo"]
cache_ttl = 86400
```

See also: `xscan help models`, `xscan help concepts/llm`
""",
    },

    # -----------------------------------------------------------------------
    # Smart mode
    # -----------------------------------------------------------------------
    "smart": {
        "title": "Smart Mode",
        "body": """\
# Smart Mode

Converts natural-language intent into an approved XScan workflow.

```
xscan smart "analyse client-side XSS on example.com"
xscan smart "deep recon of example.com" --plan
xscan smart "check for auth bypass" --confirm
```

## Important

Smart mode does **NOT** give the LLM unrestricted shell access.

## Flow

```
Intent
  ↓
Intent Specialist (parse & classify)
  ↓
Capability resolution (map to available tools/workflows)
  ↓
Select or compose existing workflow
  ↓
Policy check (scope, permissions)
  ↓
Execution (deterministic DAG)
```

## Modes

| Flag        | Behaviour                                      |
|-------------|------------------------------------------------|
| `--plan`    | Show proposed workflow only, do not execute    |
| `--confirm` | Show workflow and prompt before execution      |
| `--auto`    | Execute only workflows permitted by policy     |

## Examples

```
xscan smart "find all XSS sinks in the login flow" --plan
xscan smart "crawl and fingerprint all JS libraries" --confirm
xscan smart "full audit of api.example.com" --auto
```

See also: `xscan help workflows`, `xscan help concepts/dag`
""",
    },

    # -----------------------------------------------------------------------
    # Tools
    # -----------------------------------------------------------------------
    "tools": {
        "title": "Tool Management",
        "body": """\
# Tools

XScan manages a set of external security tools installed into `~/.xscan/bin/`.

## List tools

```
xscan tools list
```

## Install a tool

```
xscan tools install katana
xscan tools install httpx dnsx
```

## Check a tool

```
xscan tools check katana
xscan tools check --all
```

## Inspect a tool

```
xscan tools inspect katana
```

## Update tools

```
xscan tools update
xscan tools update katana
```

## Core tools

| Tool         | Capability       | Used by                    |
|--------------|------------------|----------------------------|
| katana       | web_crawler      | crawl, xss-deep            |
| httpx        | http_probe       | recon, crawl               |
| dnsx         | dns_resolution   | recon                      |
| nuclei       | vuln_scan        | validation                 |
| ffuf         | fuzzing          | parameter discovery        |
| playwright   | browser          | validation, evidence       |
| dalfox       | xss_scan         | xss validation             |

Run `xscan doctor` to verify all required tools.

See also: `xscan help commands/install`, `xscan help doctor`
""",
    },

    # -----------------------------------------------------------------------
    # Models
    # -----------------------------------------------------------------------
    "models": {
        "title": "Model Management",
        "body": """\
# Models

XScan uses **local LLMs via Ollama** by default. No cloud API required.

## List available models

```
xscan models list
```

## Set the active model

```
xscan models use qwen3
```

## Test a model

```
xscan models test
xscan models test qwen3
```

## Pull a model via Ollama

```
ollama pull qwen3
ollama pull deepseek-coder
```

## Configuration

```toml
[llm]
model    = "qwen3"
provider = "ollama"
base_url = "http://localhost:11434"
timeout  = 120
```

## Recommended models

| Model           | Use case                           |
|-----------------|------------------------------------|
| qwen3           | General analysis (default)         |
| deepseek-coder  | Code analysis                      |
| mistral         | Fast triage                        |
| llama3          | Balanced general purpose           |

Run `xscan doctor` to verify Ollama connectivity.

See also: `xscan help concepts/llm`, `xscan help troubleshooting`
""",
    },

    # -----------------------------------------------------------------------
    # Doctor
    # -----------------------------------------------------------------------
    "doctor": {
        "title": "Doctor — Environment Check",
        "body": """\
# Doctor

`xscan doctor` checks the XScan environment and reports any problems.

## Run doctor

```
xscan doctor
```

## Auto-fix

```
xscan doctor --fix
```

## What doctor checks

- Python version and dependencies
- Ollama connectivity and available models
- Required tools installed (`katana`, `httpx`, `playwright`, …)
- Database / storage state
- Scope configuration
- Network access
- Browser (Playwright) availability
- WSL2 (if on Windows)

## Fix a specific problem

```
xscan fix "ollama not responding"
xscan fix "playwright browser missing"
```

See also: `xscan help troubleshooting`, `xscan help tools`
""",
    },

    # -----------------------------------------------------------------------
    # Troubleshooting
    # -----------------------------------------------------------------------
    "troubleshooting": {
        "title": "Troubleshooting",
        "body": """\
# Troubleshooting

## Common problems

| Problem                      | Fix                                      |
|------------------------------|------------------------------------------|
| Ollama not responding        | `xscan doctor --fix`                     |
| Playwright browser missing   | `xscan tools install playwright`         |
| Tool not found               | `xscan tools install <tool>`             |
| WSL2 unavailable (Windows)   | Enable WSL2 in Windows features          |
| Database migration failed    | `xscan fix "database migration"`         |
| Scope rejected               | `xscan scope show` then re-add target    |
| Authentication expired       | `xscan auth refresh`                     |
| Model unavailable            | `ollama pull <model>` then retry         |
| Research provider error      | Check internet / `xscan config research` |

## Diagnostic commands

```
xscan doctor
xscan doctor --fix
xscan tools check --all
xscan models test
xscan config show
```

## Logs

```
xscan status --logs
```

Logs are stored in `~/.xscan/logs/`.

See also: `xscan help doctor`, `xscan help commands/fix`
""",
    },

    # -----------------------------------------------------------------------
    # Reports
    # -----------------------------------------------------------------------
    "reports": {
        "title": "Reports",
        "body": """\
# Reports

## Generate a report

```
xscan report generate <scan-id>
xscan report generate <scan-id> --format html
xscan report generate <scan-id> --format json
xscan report generate <scan-id> --format markdown
```

## View a report

```
xscan report show <scan-id>
xscan report show <scan-id> --finding xss-001
```

## Export evidence

```
xscan evidence export <scan-id>
```

## Report formats

| Format     | Description                             |
|------------|-----------------------------------------|
| terminal   | Rich terminal summary (default)         |
| html       | Full HTML report with screenshots       |
| json       | Machine-readable structured output      |
| markdown   | Markdown for inclusion in issue trackers|
| pdf        | PDF (requires wkhtmltopdf or weasyprint)|

See also: `xscan help concepts/evidence`, `xscan help commands/report`
""",
    },

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------
    "authentication": {
        "title": "Authentication",
        "body": """\
# Authentication

XScan can authenticate to web applications before scanning.

## Create a session

```
xscan auth login --url https://example.com/login
xscan auth login --url https://example.com/login --headless
```

## List sessions

```
xscan auth list
```

## Use a session in a scan

```
xscan scan example.com --auth my-session
```

## Refresh a session

```
xscan auth refresh my-session
```

## Export cookies

```
xscan auth export my-session --format netscape
```

Sessions are stored encrypted in `~/.xscan/sessions/`.

See also: `xscan help scope`, `xscan help concepts/scope`
""",
    },

    # -----------------------------------------------------------------------
    # Version
    # -----------------------------------------------------------------------
    "version": {
        "title": "Version",
        "body": """\
# Version

```
xscan version
```

Shows:
- XScan version
- Python version
- Platform
- Ollama version (if reachable)
- Active model
""",
    },
}


# ---------------------------------------------------------------------------
# Aliases — maps alternate / short names to canonical topic keys
# ---------------------------------------------------------------------------

TOPIC_ALIASES: dict[str, str] = {
    # Short forms
    "start":            "getting-started",
    "install":          "getting-started",
    "begin":            "getting-started",
    "dag":              "concepts-dag",
    "specialists":      "concepts-specialists",
    "llm":              "concepts-llm",
    "evidence":         "concepts-evidence",
    "scope":            "concepts-scope",
    "skills":           "concepts-skills",
    "research":         "concepts-research",
    "trouble":          "troubleshooting",
    "debug":            "troubleshooting",
    "fix":              "troubleshooting",

    # Path-style with slash (engine also normalises / → -)
    "concepts/dag":         "concepts-dag",
    "concepts/specialists": "concepts-specialists",
    "concepts/llm":         "concepts-llm",
    "concepts/evidence":    "concepts-evidence",
    "concepts/scope":       "concepts-scope",
    "concepts/skills":      "concepts-skills",
    "concepts/research":    "concepts-research",

    # Command aliases
    "scan":             "commands-scan",
    "workflow":         "commands-workflow",
    "recon":            "commands-recon",
    "crawl":            "commands-crawl",
    "xss":              "commands-xss",
    "ask":              "commands-ask",
    "memory":           "commands-memory",
    "report":           "reports",
    "reporting":        "reports",
    "auth":             "authentication",
    "sessions":         "authentication",
    "model":            "models",
    "tool":             "tools",
    "skill":            "skills",
    "dr":               "doctor",
    "check":            "doctor",
}


# ---------------------------------------------------------------------------
# Guided menu — shown by `xscan help` with no arguments
# ---------------------------------------------------------------------------

GUIDED_MENU: list[dict[str, str]] = [
    {"label": "Start my first scan",           "topic": "getting-started"},
    {"label": "Configure XScan",               "topic": "architecture"},
    {"label": "Install security tools",        "topic": "tools"},
    {"label": "Configure Qwen3 / Ollama",      "topic": "models"},
    {"label": "Create or inspect a workflow",  "topic": "workflows"},
    {"label": "Add a Skill",                   "topic": "concepts-skills"},
    {"label": "Research a technology",         "topic": "concepts-research"},
    {"label": "Set up authentication",         "topic": "authentication"},
    {"label": "Understand findings & evidence","topic": "concepts-evidence"},
    {"label": "Troubleshoot XScan",            "topic": "troubleshooting"},
    {"label": "Understand the DAG model",      "topic": "concepts-dag"},
    {"label": "See all commands",              "topic": "commands-scan"},
    {"label": "Read architecture overview",    "topic": "architecture"},
    {"label": "List all topics",               "topic": "topics"},
]
