# Concept: DAG Execution Model

Every XScan workflow runs as a **Directed Acyclic Graph (DAG)**.

---

## Why a DAG?

- Stages have explicit, typed inputs and outputs — no hidden state
- Independent stages run in parallel automatically
- Failures are isolated to their node — the DAG can be resumed
- The execution plan is fully inspectable before running
- Policy is enforced at each edge, not just at entry

---

## Stage anatomy

```toml
[stage.crawl]
name     = "crawl"
executor = "tool:katana"
inputs   = ["target", "scope"]
outputs  = ["urls", "js_files", "forms"]
depends  = ["recon"]
policy   = "scope_check"
```

---

## Execution phases

```
1. Plan     — resolve DAG, check capabilities, policy pre-flight
2. Execute  — run nodes in dependency order (parallel where possible)
3. Collect  — gather outputs into evidence graph
4. Report   — summarise findings
```

---

## Resuming a DAG

Each stage records its completion state. On `--resume`:

1. XScan loads the saved DAG state
2. Completed stages are skipped
3. Failed or incomplete stages are re-run from their last checkpoint

```bash
xscan scan example.com --resume
```

---

## Viewing a DAG

```bash
xscan workflow inspect xss-deep
xscan workflow inspect xss-deep --format dot   # Graphviz DOT output
```

---

## Related topics

- `xscan help workflows`
- `xscan help concepts/specialists`
- `xscan help concepts/evidence`
