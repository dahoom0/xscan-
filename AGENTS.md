# XScan Agent Instructions

This file governs how AI coding agents must work on this repository.

---

## Mandatory rules

### 1. Phase discipline

Implement in the exact phase order defined in ARCHITECTURE.md.

**Do not** write Phase 6 (Tool Registry) before Phase 2 (DAG Engine) is tested.  
**Do not** write scanner logic (reflection probing, payload injection) until  
Phases 1–8 are complete and passing.

At the end of every phase:
1. Run `pytest` — fix all failures before continuing
2. Run `mypy src/xscan` — fix all type errors before continuing
3. Run `ruff check src/` — fix all lint errors before continuing
4. Update the phase status in ARCHITECTURE.md
5. List every changed file in the session notes

If any of the above fail, stop and report the failure. Do not proceed.

---

### 2. No monolithic functions

**Never** put workflow logic inside a CLI command function.

Bad:
```python
@app.command("scan")
def cmd_scan(target: str):
    resp = httpx.get(target)          # ← direct HTTP in CLI
    forms = extract_forms(resp)        # ← crawler logic in CLI
    for form in forms:                 # ← probing in CLI
        inject_payload(form)
```

Good:
```python
@app.command("scan")
def cmd_scan(target: str, profile: str = "balanced"):
    from xscan.services.scan import ScanService
    ScanService().start(target=target, profile=profile)
```

---

### 3. Scope before network

**Every** outbound HTTP request, DNS lookup, browser navigation, or tool
invocation must pass through `ScopeEngine` and `PolicyEngine` before execution.

Bad:
```python
resp = httpx.get(url)          # ← no scope check
```

Good:
```python
scope_engine.assert_allowed(url)
resp = http_adapter.get(url)   # ← scope-aware adapter
```

---

### 4. LLM boundaries

LLM specialists receive typed structured prompts and return typed structured output.

**Never** allow:
- LLM output to contain shell commands that are executed directly
- LLM output to declare a finding confirmed without deterministic evidence
- LLM to modify scope, policy, or tool configuration

Specialists return Pydantic models, not raw strings.

---

### 5. Evidence before findings

A `Finding` cannot be created without at least one `EvidenceNode` linked to it.

Bad:
```python
Finding(description="LLM says this is XSS", ...)
```

Good:
```python
evidence = EvidenceNode(type=EvidenceType.HTTP_RESPONSE, ...)
finding = Finding(evidence_ids=[evidence.id], ...)
```

---

### 6. No hardcoded paths or tool names

Bad:
```python
subprocess.run(["C:\\Users\\...\\bin\\katana", ...])
shutil.which("httpx")   # ← could match Python httpx CLI
```

Good:
```python
tool = tool_registry.resolve_capability(Capability.WEB_CRAWLER)
result = runtime.execute(tool, args)
```

---

### 7. No LLM-generated shell commands

Bad:
```python
cmd = llm.generate("write a shell command to install katana")
subprocess.run(cmd, shell=True)
```

Good:
```python
repair = repair_registry.get("install_katana")
repair.execute(runtime)   # ← typed, pre-approved recipe
```

---

### 8. Pydantic schemas everywhere

Do not pass raw `dict` objects between subsystems when a typed schema exists.

Bad:
```python
def analyse(data: dict) -> dict:
    ...
```

Good:
```python
def analyse(candidate: XssCandidate) -> TriageResult:
    ...
```

---

### 9. Prototype preservation

The `src/xscan/_prototype/` directory contains preserved prototype code.

**Do not import** from `_prototype/` in production modules.  
**Do not delete** files from `_prototype/` until the equivalent production  
module passes tests.

Migration is complete when:
- Production node exists in `src/xscan/nodes/`
- Unit test covers the production node
- MIGRATION.md entry is marked `migrated`

---

### 10. WSL2 awareness

Security tools run inside WSL2. The Python runtime on Windows communicates
with them through `WSLRuntime`.

**Never** hardcode `wsl` subprocess calls in scanner modules.  
Use `runtime.execute(...)` from `xscan.runtime`.

---

## Workflow for adding a new DAG node

1. Define input/output schemas in `xscan/schemas/`
2. Write the node class in `xscan/nodes/<category>/<name>.py` inheriting `NodeBase`
3. Register node type in `xscan/core/dag/registry.py`
4. Write unit test in `tests/unit/nodes/`
5. Add to at least one workflow YAML in `xscan/workflows/definitions/`
6. Validate workflow: `python -m xscan.workflows.validator <file>`
7. Run full test suite

---

## Commit discipline

- One commit per phase (minimum)
- Commit message format: `phase(N): <description>`
- Never commit with failing tests or type errors
