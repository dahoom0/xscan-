# XScan Architecture

Version: 0.2.0  
Status: In Progress — Platform Foundation Phase

---

## 1. Guiding Principles

| Principle | Meaning |
|-----------|---------|
| **Deterministic DAG** | Every workflow executes as a versioned, checkpointed directed acyclic graph. No stage directly orchestrates another. |
| **Scope-first** | Every network operation, browser action, and LLM-planned request passes through the Scope + Policy layer before execution. |
| **Bounded LLM** | LLMs are specialists. They analyse, classify, prioritise, and plan. They cannot execute shell commands, bypass scope, or confirm findings unilaterally. |
| **Evidence-first findings** | A finding is not confirmed until deterministic or browser evidence proves it. LLM reasoning alone is not proof. |
| **Platform not scanner** | The scanner is one workflow running on top of a platform. The platform exists independently. |
| **Local-first** | Everything runs on the user's machine. No cloud API required. |
| **WSL2 boundary** | Security tool execution lives inside WSL2. Windows/macOS is the control and presentation layer. |

---

## 2. Full Platform Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                     Presentation Layer                          │
│          CLI (Typer)  ·  TUI (Textual)  ·  VS Code             │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                    Command Dispatcher                           │
│        Maps CLI verbs → ApplicationService calls               │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                  Application Services                           │
│    ScanService · WorkflowService · DoctorService               │
│    ToolService · ModelService · EvidenceService                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│              Deterministic DAG Engine                           │
│   Graph · Scheduler · Checkpoint · Resume · NodeRunner         │
└───────────┬────────────────┬──────────────────┬────────────────┘
            │                │                  │
    ┌───────▼──────┐ ┌───────▼──────┐ ┌────────▼──────┐
    │ Scope Engine │ │Policy Engine │ │ Audit Logger  │
    └───────┬──────┘ └───────┬──────┘ └───────────────┘
            └────────┬───────┘
                     │ every operation checked here
┌────────────────────▼────────────────────────────────────────────┐
│                     Node Layer                                  │
│                                                                 │
│  Recon        Crawl        JS-Analysis    Candidate-Gen        │
│  Reflection   Taint-Graph  LLM-Triage     Validation          │
│  Evidence     PoC          Report                              │
└─────────────┬───────────────────────┬───────────────────────────┘
              │                       │
   ┌──────────▼──────────┐   ┌────────▼──────────────┐
   │   Tool Layer        │   │   LLM Gateway         │
   │                     │   │                       │
   │ ToolRegistry        │   │ LLMGateway            │
   │ CapabilityRegistry  │   │ OllamaProvider        │
   │ ToolAdapters        │   │ SpecialistFramework   │
   │ ToolInstallers      │   │ StructuredOutput      │
   └──────────┬──────────┘   └────────┬──────────────┘
              │                       │
   ┌──────────▼──────────────────────▼──────────────────────────┐
   │              Execution Runtime                             │
   │    LocalLinuxRuntime · WSLRuntime · FutureContainerRuntime │
   └─────────────────────────────────────────────────────────────┘

Platform Services (cross-cutting)
──────────────────────────────────────────────────────────────────
Config · Storage/SQLite · Migrations · EventBus
Doctor/RepairDAG · SkillManager · MemoryStore
ResearchCache · AuthSessions · Telemetry · PluginSystem
```

---

## 3. Package Layout

```
src/xscan/
│
├── __init__.py                  # version
│
├── config/                      # Configuration loading + validation
│   ├── __init__.py
│   ├── settings.py              # Pydantic Settings model
│   └── defaults.py
│
├── schemas/                     # Typed domain models (Pydantic)
│   ├── __init__.py
│   ├── scan.py                  # Scan, Target, ScanStatus
│   ├── workflow.py              # Workflow, WorkflowNode, NodeResult
│   ├── scope.py                 # Scope, ScopeRule
│   ├── finding.py               # Finding, Severity, FindingType
│   ├── evidence.py              # EvidenceNode, EvidenceEdge, Artifact
│   ├── tool.py                  # Tool, Capability, ToolHealth
│   ├── llm.py                   # LLMRequest, LLMResponse, SpecialistOutput
│   └── events.py                # DomainEvent, EventType
│
├── errors/                      # Exception hierarchy
│   └── __init__.py
│
├── events/                      # EventBus
│   └── __init__.py
│
├── storage/                     # Database abstraction
│   ├── __init__.py
│   ├── database.py              # Connection + session management
│   ├── migrations.py            # Schema migration runner
│   ├── repositories/
│   │   ├── scan.py
│   │   ├── workflow.py
│   │   ├── evidence.py
│   │   ├── finding.py
│   │   └── tool.py
│   └── models/                  # SQLite ORM models (not domain schemas)
│       └── __init__.py
│
├── core/
│   ├── dag/                     # DAG engine
│   │   ├── engine.py
│   │   ├── graph.py
│   │   ├── node.py
│   │   ├── scheduler.py
│   │   ├── state.py
│   │   ├── checkpoint.py
│   │   └── validators.py
│   ├── scope/                   # Scope + Policy
│   │   ├── engine.py
│   │   └── policy.py
│   └── dispatcher/              # Command → Service routing
│       └── __init__.py
│
├── services/                    # Application services
│   ├── scan.py
│   ├── workflow.py
│   ├── doctor.py
│   ├── tools.py
│   └── models.py
│
├── workflows/                   # YAML workflow definitions
│   ├── loader.py
│   ├── validator.py
│   └── definitions/
│       ├── recon-only.yaml
│       ├── xss-fast.yaml
│       ├── xss-balanced.yaml
│       └── xss-deep.yaml
│
├── nodes/                       # DAG node implementations
│   ├── base.py                  # NodeBase contract
│   ├── recon/
│   │   └── technology.py        # ← migrated from recon/fingerprint.py
│   ├── crawler/
│   │   └── discover.py          # ← migrated from crawler/spider.py
│   ├── analysis/
│   │   ├── reflection.py        # ← from candidates/xss_prober.py
│   │   └── candidate_gen.py
│   ├── llm/
│   │   └── triage.py            # ← from llm/analyst.py
│   ├── validation/
│   │   └── xss_candidate.py
│   └── reporting/
│       └── report.py            # ← from reporting/reporter.py
│
├── tools/                       # Tool management
│   ├── registry.py
│   ├── capabilities.py
│   ├── adapters/
│   ├── installers/
│   └── health.py
│
├── runtime/                     # Execution runtime abstraction
│   ├── __init__.py
│   ├── base.py
│   ├── local.py
│   └── wsl.py
│
├── llm/                         # LLM Gateway
│   ├── gateway.py
│   ├── providers/
│   │   └── ollama.py            # ← migrated from llm/ollama.py
│   └── specialists/
│       ├── base.py
│       ├── technology.py
│       ├── sink.py
│       ├── context.py
│       ├── triage.py            # ← from llm/analyst.py
│       ├── test_planning.py
│       ├── research.py
│       └── intent.py
│
├── evidence/                    # Evidence graph
│   ├── graph.py
│   ├── provenance.py
│   └── replay.py
│
├── doctor/                      # Environment health checks
│   ├── checks/
│   └── repairs/
│
├── skills/                      # Skill manager
├── memory/                      # Memory store
├── research/                    # Research cache
├── reporting/                   # Report generation
├── auth/                        # Auth sessions
├── audit/                       # Audit logging
├── telemetry/                   # Optional telemetry
├── plugins/                     # Plugin system
│
├── cli/                         # CLI presentation (Typer)
│   ├── main.py
│   └── cmd_help.py
│
├── help/                        # Help engine (complete)
│
└── _prototype/                  # Preserved prototype code (not imported)
    ├── core_engine.py           # ← core/engine.py
    ├── core_models.py           # ← core/models.py
    ├── http_client.py           # ← http/client.py
    ├── recon_fingerprint.py     # ← recon/fingerprint.py
    ├── crawler_spider.py        # ← crawler/spider.py
    ├── candidates_prober.py     # ← candidates/xss_prober.py
    ├── llm_analyst.py           # ← llm/analyst.py
    └── reporting_reporter.py    # ← reporting/reporter.py
```

---

## 4. XSS Workflow DAG (target state)

```
Scope Validation
      ↓
Recon / Technology Detection
      ↓
HTTP Probe
      ↓
Crawl (URL + Form Discovery)
      ↓
JavaScript Extraction
      ↓
AST Parsing
      ↓
Taint Graph Construction
      ↓
Reflection Analysis          ← deterministic
      ↓
Context Analysis             ← deterministic
      ↓
Candidate Ranking            ← deterministic
      ↓
Qwen3 Context Specialist     ← bounded LLM
      ↓
Qwen3 Test-Planning Spec.    ← bounded LLM
      ↓
Bounded Validation           ← deterministic + browser
      ↓
Evidence Graph               ← provenance captured
      ↓
Finding                      ← confirmed by evidence
      ↓
PoC Generation
      ↓
Report
```

---

## 5. LLM Boundary

LLMs **can**: analyse, classify, prioritise, plan bounded tests, summarise, research.  
LLMs **cannot**: execute shell commands, bypass scope, confirm findings without evidence,
issue unrestricted network requests, or generate repair recipes that execute without policy approval.

---

## 6. WSL2 Boundary

```
Windows / macOS
  CLI  ·  TUI  ·  VS Code
        ↓
  Command Dispatcher
        ↓
  WSLRuntime adapter
        ↓
  WSL2 Ubuntu
    Security tools (katana, nuclei, httpx-pd, dnsx, ...)
    Go binaries
    Playwright + Chromium
```

The Python platform code runs on Windows. Tool execution is proxied through WSLRuntime.

---

## 7. Scope + Policy Flow

```
Node requests: GET https://target.example.com/api/search?q=test
                    ↓
           ScopeEngine.check(url)
                    ↓
           PolicyEngine.evaluate(operation, context)
                    ↓
              Allowed?
          ┌──────┴──────┐
         yes             no
          │               │
      proceed          AuditLog + raise PolicyViolation
```

---

## 8. Implementation Phases

| Phase | Content | Status |
|-------|---------|--------|
| 0 | Audit + ARCHITECTURE.md + MIGRATION.md | Complete |
| 1 | Schemas · Config · Errors · Events · Storage | Complete |
| 2 | DAG Engine · Workflow Loader · Node Contract | Complete |
| 3 | Scope · Policy · Scope-aware HTTP adapter | Complete |
| 4 | Command Dispatcher · Application Services | Complete |
| 5 | Doctor · Repair DAG | Complete |
| 6 | Tool Registry · Capabilities · WSL2 Runtime | Complete |
| 7 | LLM Gateway · Ollama Provider · Specialists | Complete |
| 8 | Evidence Graph · Validation Contracts | Complete |
| 9 | Migrate prototype nodes into DAG | Complete |
| 10 | XSS pipeline (full DAG) | Complete |
| 1b | DOM-XSS diagnostics + registry integration | Complete |
| 11 | TUI / VS Code integration | Pending |
| 12 | Lab fixtures + end-to-end tests | Complete |
| 13 | Async I/O + Dedup + Tiered Escalation | Planned (see PHASE_13_ASYNC_DEDUP_TIERING.md) |

---

## 9. Evidence-Driven Payload Synthesis (v2.3)

XScan does not fire payloads from a dictionary. The payload for a finding is an
**output** of a reasoning chain over evidence gathered from the actual target:

```
Discovery (crawler, GET-form expansion)
  -> Reflection / source analysis (context, quote, enclosing construct)
  -> Encoding profile (raw / encoded / stripped chars, live-probed)
  -> Vulnerability model  (schemas/vuln_model.py)
       source -> flow -> sink -> execution context -> AttackConstraints
  -> Synthesis            (validation/payload_synthesis.py)
       construct closure + execution-context strategy + char feasibility
  -> Bounded execution    (IterativeValidator, IterationBudget)
  -> Observation          (HTTP reflection diff / browser dialogs + DOM state)
  -> Failure analysis     (refine_from_observations)
       learned constraints -> narrowed scenario -> next generation
  -> Confirmation         (browser execution only; sink-reach != finding)
  -> Explanation          (VulnerabilityModel.explain() -> finding["why"])
```

Key rules enforced in code:

* **Delivery class follows the observed execution context**, not a
  vulnerability-type label: the same sink synthesises markup in html_text but
  construct closure (`"-alert(1)};//`) inside a JSON literal that is eval'd.
* **Characters the server encodes or strips are never used**; refinement adds
  newly-observed bad characters to the constraint set and evicts them from the
  raw set.
* **A blocked scheme is learned**: after a stripped/normalized `javascript:`
  candidate the loop pivots to a different delivery family.
* **Static tables are fallbacks only** (dom_xss, taint, iterative legacy) —
  the synthesiser runs first everywhere; tables are regression fixtures.
* **Bounded iteration**: max_iterations / max_candidates / max_requests /
  max_runtime_s are enforced by IterationBudget; the LLM (when enabled)
  receives the structured model + observation history but can never override
  budgets or claim success — only browser/HTTP evidence confirms.
* **Findings explain themselves**: every confirmed candidate carries `why`
  lines generated from its own evidence (source, flow, sink, constraints).


---

## 10. Model-Driven Synthesis Initiative (P1-P4)

A structured initiative to replace generic family-based payload synthesis with evidence-driven,
model-informed synthesis that adapts payloads to the observed target's exact constraints.

### P1: Context Classification (✓ Complete)
- **Component**: `ExecutionContextType` enum (13 types)
- **Files**: `src/xscan/nodes/analysis/context_classification.py`
- **Purpose**: Structured classification of execution contexts (JS string, HTML attribute, JSON, etc.)
- **Output**: Typed `ContextClassification` model with confidence and strategy recommendations

### P2: Vulnerability Model Builder (✓ Complete)
- **Component**: `VulnerabilityModelBuilderNode`
- **Files**: 
  - `src/xscan/nodes/analysis/vulnerability_model_builder.py` (node implementation)
  - `src/xscan/schemas/vuln_model.py` (schema, already mature)
  - `tests/unit/nodes/test_vulnerability_model_builder.py` (comprehensive tests)
- **Purpose**: Transform evidence (reflection, encoding profile, context) into typed `VulnerabilityModel`
- **Contract**: 
  - Input: candidates dict with context_analysis, encoding_profile
  - Output: VulnerabilityModel instances with flow, constraints, and construction plans
  - Evidence: Each model linked to originating evidence nodes for provenance

### P3: Strategy Selector (✓ Complete)
- **Component**: `StrategySelectorNode`
- **Files**: 
  - `src/xscan/nodes/analysis/strategy_selector.py` (node implementation)
  - `src/xscan/schemas/synthesis_strategy.py` (schemas and strategy registry)
  - `tests/unit/nodes/test_strategy_selector.py` (comprehensive tests)
- **Purpose**: Map VulnerabilityModel to ranked synthesis strategies
- **Schemas**:
  - `SynthesisFamilyType` enum (14 payload families: tag_injection, attribute_breakout, script_string_breakout, json_object_breakout, event_handler, javascript_protocol, angular_csti, etc.)
  - `SynthesisTechnique` (specific payloads within families)
  - `SynthesisStrategy` (family + prioritized techniques)
  - `StrategyRanking` (ranked output for each model)
- **Algorithm**:
  - Input: VulnerabilityModel with execution context + constraints
  - Map context type → applicable strategy families
  - Score techniques by character availability
  - Rank by feasibility (0.0-1.0 confidence)
  - Output: Ranked StrategyRanking with top strategies first
- **Contract**:
  - Input: list[VulnerabilityModel] from P2
  - Output: list[StrategyRanking] with (strategy, confidence) tuples
  - Deterministic: Same model → same ranking every time

### P4: Constraint-Driven Synthesis (Planned)
- **Purpose**: Generate payloads using only available characters
- **Features**:
  - Respect raw/encoded/stripped character sets from encoding profile
  - Support iterative refinement on observed failures
  - Generate payloads specific to THIS target, not generic dictionary payloads

### Synthesis Pipeline Integration
```
Evidence (HTTP response, DOM snapshot, AST)
  ↓
Context Classification (P1)
  ↓
Vulnerability Model Builder (P2)
  ├─ Flow reconstruction
  ├─ Constraint extraction
  └─ Sink context analysis
  ↓
Strategy Selector (P3)
  ├─ Map model → applicable families
  └─ Prioritise based on likelihood
  ↓
Constraint-Driven Synthesis (P4)
  ├─ Character feasibility check
  ├─ Syntax balance analysis
  └─ Payload generation
  ↓
Validation (IterativeValidator, browser confirmation)
  ├─ Observation analysis
  ├─ Constraint refinement
  └─ Iterative retry if needed
  ↓
Finding (with evidence + construction plan explanation)
```

This design ensures:
- **Evidence-grounded**: Every payload is derived from THIS target's profile
- **Deterministic**: No randomness in synthesis; LLM used only for planning, not payload generation
- **Explainable**: Every payload carries construction plan showing why it works
- **Adaptive**: Failures refine constraints for next iteration
- **Testable**: Each component has typed inputs/outputs for unit and integration testing
