# ADR-001: Production Architecture — Platform-First Migration

Date: 2026-09-11  
Status: Accepted  
Deciders: Project owner

---

## Context

An initial prototype was built that implemented a monolithic scan pipeline:

```
cmd_scan()
  → ScanEngine.run()
    → http probe
    → BFS crawl
    → inject payloads into all parameters
    → LLM analysis
    → report
```

This prototype demonstrated the concept but created the following problems:

1. **No scope enforcement** — network requests were issued without any policy check
2. **No DAG** — stages were hardcoded procedure calls with no checkpointing or resume capability
3. **No tool abstraction** — httpx was called directly; Go tools were assumed on PATH
4. **Ambiguous tool identity** — `shutil.which("httpx")` could match the Python httpx CLI, not the ProjectDiscovery security tool
5. **LLM called directly from scanner** — `llm/analyst.py` held both prompt logic and HTTP calls to Ollama
6. **Windows-only** — paths like `C:\Users\...\bin` were hardcoded; WSL2 execution was not considered
7. **Findings without evidence** — LLM analysis output was treated as a finding directly
8. **No tests** — zero test coverage across the entire codebase
9. **Payload injection as primary strategy** — probing every parameter with XSS payloads is the last resort, not the first step

---

## Decision

Halt prototype extension. Implement the platform foundation in strict phases before reconnecting any scanner logic.

The phases are:

1. **Schemas · Config · Errors · Events · Storage**  
   Typed domain models (Pydantic), configuration management, exception hierarchy, event bus, SQLite abstraction with repository pattern.

2. **DAG Engine · Workflow Loader**  
   Deterministic DAG engine with checkpoint/resume. Versioned workflow YAML definitions. Node contract with typed input/output.

3. **Scope Engine · Policy Engine**  
   Every network operation validated before execution. Out-of-scope requests blocked and audited.

4. **Command Dispatcher · Application Services**  
   CLI commands route to ApplicationServices. Services orchestrate DAG. No business logic in CLI functions.

5. **Doctor · Repair DAG**  
   Independent health checks. Typed repair recipes. LLM may diagnose but not directly execute repairs.

6. **Tool Registry · Capabilities · WSL2 Runtime**  
   Tools resolved by capability. Execution proxied through WSLRuntime. No hardcoded paths.

7. **LLM Gateway · Ollama Provider · Specialist Framework**  
   LLMGateway abstracts all LLM calls. Specialists receive/return Pydantic models. Ollama is one provider.

8. **Evidence Graph · Validation Contracts**  
   All observations stored with provenance. Findings require evidence. LLM output is not evidence.

9. **Prototype node migration**  
   Existing `fingerprint.py`, `spider.py`, `xss_prober.py`, `analyst.py`, `reporter.py` become DAG nodes behind the new interfaces.

10. **XSS pipeline**  
    Full pipeline: AST → taint → reflection → candidate ranking → LLM context → bounded validation → evidence → finding.

---

## Consequences

### Positive

- Scope enforcement is structural, not optional
- DAG is checkpointable and resumable from any node
- LLM is bounded — cannot escalate beyond its specialist role
- Findings require deterministic evidence
- Tool resolution is unambiguous
- WSL2 execution is explicit, not implicit
- Platform can support future workflows beyond XSS without architectural changes

### Negative

- Significant up-front work before visible scanning results
- Prototype scan capability is temporarily removed from `cmd_scan`
- More files to maintain

### Mitigations

- Prototype code preserved in `src/xscan/_prototype/` — not lost
- `xscan models list` and the help system remain fully functional throughout
- Phases are independently testable and deliverable

---

## Alternatives considered

### A: Continue extending the prototype

Rejected. Would lock the payload-injection strategy as the architecture. Scope enforcement and evidence provenance would remain absent.

### B: Rewrite entirely, discard prototype

Rejected. `fingerprint.py`, `spider.py`, and `reporter.py` are useful and correct at the implementation level. Only the architecture above them is wrong.

### C: Platform-first migration (chosen)

Prototype code becomes nodes behind new interfaces. Platform is built first, scanner migrates into it.

---

## References

- `ARCHITECTURE.md` — full platform stack
- `AGENTS.md` — agent implementation rules
- `MIGRATION.md` — prototype → production mapping
