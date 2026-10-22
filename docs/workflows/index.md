# Workflows

A workflow is a predefined **Directed Acyclic Graph (DAG)** that executes a
security analysis methodology end-to-end.

---

## List workflows

```bash
xscan workflow list
```

## Run a workflow

```bash
xscan workflow run xss-deep example.com
xscan scan example.com --workflow xss-deep
```

## Inspect a workflow

```bash
xscan workflow inspect xss-deep
```

Output:

```
Workflow: xss-deep
Version:  1.0

Purpose:
  Deep XSS analysis.

Stages:
   1. Scope validation
   2. Recon
   3. Crawl
   4. JavaScript extraction
   5. AST analysis
   6. Taint analysis
   7. Candidate triage
   8. LLM context analysis
   9. Validation
  10. Evidence generation
  11. Reporting

Required capabilities:
  web_crawler
  javascript_analysis
  browser
  xss_validation

LLM specialists:
  technology
  sink
  context
  test-planning

Output:
  findings
  evidence
  report
```

---

## Built-in workflows

| Workflow         | Description                                    |
|------------------|------------------------------------------------|
| xss-deep         | Full XSS analysis with taint tracking          |
| xss-fast         | Quick XSS scan for CI pipelines                |
| recon-full       | Comprehensive reconnaissance                   |
| crawl-deep       | Deep crawl and asset discovery                 |
| full-audit       | Complete security assessment                   |
| api-analysis     | REST/GraphQL API security analysis             |
| js-analysis      | Static JavaScript security analysis            |

---

## Workflow profiles

Profiles control resource usage and thoroughness:

| Profile    | Description                                   |
|------------|-----------------------------------------------|
| `fast`     | Quick checks, minimal LLM calls               |
| `balanced` | Default — thorough but time-bounded           |
| `deep`     | Maximum depth, all specialists enabled        |

```bash
xscan scan example.com --workflow xss-deep --profile deep
```

---

## Resume a workflow

```bash
xscan scan example.com --resume
xscan resume <scan-id>
```

---

## Related topics

- `xscan help concepts/dag`
- `xscan help concepts/specialists`
- `xscan help commands/scan`
