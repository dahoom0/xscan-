# XScan Migration Map

Maps every prototype module to its production location and migration status.

Legend: `[ ]` not started · `[~]` in progress · `[x]` complete

---

## Prototype → Production

| Prototype file | New location | New responsibility | Action | Status |
|---|---|---|---|---|
| `core/engine.py` | deleted | Monolithic orchestrator — replaced by DAG Engine + ScanService | REPLACE | `[ ]` |
| `core/models.py` | `schemas/*.py` | Dataclass models → Pydantic domain schemas | REFACTOR | `[ ]` |
| `http/client.py` | `nodes/base.py` (HTTP adapter) | Bare httpx → scope-aware HTTP adapter behind ScopeEngine | REFACTOR | `[ ]` |
| `recon/fingerprint.py` | `nodes/recon/technology.py` | Technology detection logic → `TechnologyNode` (DAG node) | MIGRATE | `[ ]` |
| `crawler/spider.py` | `nodes/crawler/discover.py` | BFS crawler → `CrawlerNode` (DAG node) | MIGRATE | `[ ]` |
| `candidates/xss_prober.py` | `nodes/analysis/reflection.py` + `nodes/validation/xss_candidate.py` | Probe-everything prober → deterministic ReflectionDetector + bounded ValidationNode | SPLIT | `[ ]` |
| `llm/ollama.py` | `llm/providers/ollama.py` | Direct Ollama client → OllamaProvider behind LLMGateway | MIGRATE | `[ ]` |
| `llm/analyst.py` | `llm/specialists/triage.py` | Monolithic analyst → CandidateTriageSpecialist in specialist framework | MIGRATE | `[ ]` |
| `reporting/reporter.py` | `nodes/reporting/report.py` | Direct reporter → `ReportNode` (DAG node) | MIGRATE | `[ ]` |

---

## Prototype preservation policy

All prototype files are copied to `src/xscan/_prototype/` before any production module is built.
Production modules must not import from `_prototype/`.
A prototype file is deleted from its original location only after:

1. Production equivalent exists in `nodes/` or correct package
2. Unit test covers production module
3. Migration row above is marked `[x]`

---

## New production modules (no prototype equivalent)

These are net-new and must be built from scratch:

| Module | Phase | Status |
|---|---|---|
| `config/settings.py` | 1 | `[ ]` |
| `errors/__init__.py` | 1 | `[ ]` |
| `events/__init__.py` | 1 | `[ ]` |
| `storage/database.py` + repositories | 1 | `[ ]` |
| `core/dag/` (engine, graph, node, scheduler, state, checkpoint, validators) | 2 | `[ ]` |
| `workflows/loader.py` + YAML definitions | 2 | `[ ]` |
| `core/scope/engine.py` | 3 | `[ ]` |
| `core/scope/policy.py` | 3 | `[ ]` |
| `core/dispatcher/` | 4 | `[ ]` |
| `services/scan.py` | 4 | `[ ]` |
| `services/workflow.py` | 4 | `[ ]` |
| `doctor/checks/` | 5 | `[ ]` |
| `doctor/repairs/` | 5 | `[ ]` |
| `tools/registry.py` | 6 | `[ ]` |
| `tools/capabilities.py` | 6 | `[ ]` |
| `runtime/wsl.py` | 6 | `[ ]` |
| `llm/gateway.py` | 7 | `[ ]` |
| `llm/specialists/base.py` | 7 | `[ ]` |
| `evidence/graph.py` | 8 | `[ ]` |
| `evidence/provenance.py` | 8 | `[ ]` |

---

## Dependency rules

```
schemas/     ← no internal imports (pure domain models)
errors/      ← imports schemas only
events/      ← imports schemas only
config/      ← imports schemas only
storage/     ← imports schemas, errors
core/dag/    ← imports schemas, errors, events, storage
core/scope/  ← imports schemas, errors
core/dispatcher/ ← imports services
services/    ← imports core/dag, core/scope, storage, schemas
nodes/       ← imports schemas, core/scope, llm/gateway, evidence
llm/gateway  ← imports schemas (NOT nodes, NOT services)
llm/providers ← imports llm/gateway
evidence/    ← imports schemas, storage
tools/       ← imports schemas, runtime
runtime/     ← imports schemas (no scanner imports)
cli/         ← imports services, help (NOT core/dag directly)
```

Violations of these dependency rules are a blocking issue.
