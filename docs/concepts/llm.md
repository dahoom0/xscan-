# Concept: LLM Boundaries

XScan uses LLMs as **bounded specialists**, not as unrestricted agents.

---

## LLMs can

- Analyse source code and HTTP responses
- Classify JavaScript sinks and taint sources
- Prioritise and rank candidates
- Plan bounded, policy-checked test sequences
- Summarise and explain findings
- Research external technical documentation

---

## LLMs cannot

- Bypass authorised scope
- Execute arbitrary shell commands
- Directly control unrestricted network traffic
- Declare a finding confirmed without validation evidence
- Access files outside the scan context

---

## Why this boundary matters

The boundary ensures every action XScan takes is:

| Property        | Mechanism                                        |
|-----------------|--------------------------------------------------|
| Deterministic   | All LLM outputs feed back into the DAG           |
| Auditable       | Every LLM call is logged with full prompt/response|
| Scope-safe      | Outputs are policy-checked before influencing runs|
| Reproducible    | Same inputs → same DAG path                      |

---

## Prompt architecture

```
System context (read-only)
  ↓
Structured task prompt
  ↓
LLM specialist
  ↓
Structured JSON response
  ↓
DAG policy gate
  ↓
Next stage
```

---

## Related topics

- `xscan help concepts/specialists`
- `xscan help models`
- `xscan help concepts/dag`
- `xscan help concepts/scope`
