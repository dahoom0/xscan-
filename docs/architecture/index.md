# XScan Architecture

XScan is a **deterministic, DAG-driven** security automation platform backed
by bounded LLM specialists.

---

## Platform overview

```
                         XSCAN
                           │
          ┌────────────────┼─────────────────┐
          ▼                ▼                 ▼
     Presentation       Commands          Help
     CLI/TUI/VSCode     Dispatcher         Engine
          │                │                 │
          └────────────────┼─────────────────┘
                           ▼
                  Deterministic DAG
                           │
       ┌───────────────────┼────────────────────┐
       ▼                   ▼                    ▼
     Tools              Analysis             Browser
       │                   │                    │
       └───────────────────┼────────────────────┘
                           ▼
                  LLM Specialists
                           │
                        Qwen3
                           │
                  structured decisions
                           │
                           ▼
                     Validation
                           │
                           ▼
                    Evidence Graph
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                   PoC          Reports

Platform Services
─────────────────────────────────────────────────
Scope / Policy       Config
Doctor / Self-Healing Tool Manager
Skill Manager        Memory
Research             Model Manager
Auth / Sessions      Audit / Telemetry
Plugin System
```

---

## Core principles

**1. Deterministic DAG execution**
Every workflow is a directed acyclic graph. Each stage has explicit inputs,
outputs, and a policy gate. Nothing executes outside the DAG.

**2. Bounded LLM specialists**
LLMs analyse, classify, and plan — they do not execute shell commands or
bypass scope. Every LLM decision feeds back into the deterministic DAG.

**3. Evidence-first findings**
No finding is reported without captured evidence (HTTP, DOM, screenshot).

**4. Scope enforcement**
Every tool invocation and LLM-planned request is checked against authorised
scope before execution.

**5. Local-first**
Everything runs on your machine. No cloud API required.

---

## Source layout

```
src/xscan/
├── help/           # Help & Documentation Engine
├── core/           # DAG engine, policy, config
├── cli/            # Typer CLI commands
├── tui/            # Rich/Textual interactive dashboard
├── daemon/         # Background scan daemon
├── doctor/         # Environment health checks
├── tools/          # Tool manager and adapters
├── workflows/      # Predefined DAG workflow definitions
├── llm/            # LLM client, specialist prompts
├── skills/         # Skill loader and registry
├── memory/         # Persistent memory and notes
├── research/       # External research node
├── recon/          # Reconnaissance stage
├── crawler/        # Web crawler stage
├── http/           # HTTP client and proxy
├── browser/        # Playwright browser controller
├── javascript/     # JS extraction and AST analysis
├── candidates/     # Taint tracking and candidate triage
├── validation/     # Active validation of candidates
├── evidence/       # Evidence capture and graph
├── poc/            # PoC generation
├── remediation/    # Remediation advice generation
├── reporting/      # Report generation
├── storage/        # Database layer (SQLite / DuckDB)
├── audit/          # Audit logging
├── telemetry/      # Optional telemetry
└── plugins/        # Plugin system
```

---

## Related topics

- `xscan help concepts/dag`
- `xscan help concepts/specialists`
- `xscan help workflows`
- `xscan help concepts/evidence`
