# Concept: LLM Specialists

XScan uses LLMs as **bounded specialists** — each with a narrow, well-defined role
inside the DAG. They are not general-purpose agents.

---

## Specialist roster

| Specialist       | Stage               | Responsibility                               |
|------------------|---------------------|----------------------------------------------|
| `technology`     | recon               | Identify frameworks, libraries, tech stack   |
| `sink`           | js-analysis         | Locate dangerous sinks in JavaScript         |
| `context`        | candidate-triage    | Evaluate exploitability in context           |
| `test-planning`  | validation-planning | Generate bounded, policy-checked test cases  |
| `triage`         | candidate-triage    | Rank and deduplicate candidates              |
| `summarise`      | reporting           | Summarise findings for reports               |
| `research`       | context-enrichment  | Retrieve external technical context          |
| `intent`         | smart-mode          | Parse natural-language intent                |

---

## Specialist contract

Every specialist:

1. Receives a **typed, structured prompt** — not raw user input
2. Returns **structured JSON** — not free-form text actions
3. Cannot issue tool calls directly — decisions re-enter the DAG
4. Is scope-checked before its outputs influence execution

---

## What specialists cannot do

- Bypass authorised scope
- Execute arbitrary shell commands
- Directly control unrestricted network traffic
- Declare a confirmed finding without validation evidence

---

## Configuring specialists

```toml
[llm.specialists.sink]
model   = "qwen3"
timeout = 60

[llm.specialists.research]
model   = "deepseek-coder"
timeout = 120
```

---

## Related topics

- `xscan help concepts/llm`
- `xscan help concepts/dag`
- `xscan help models`
- `xscan help concepts/skills`
