# xscan workflow

Run, list, and inspect predefined DAG workflows.

---

## Usage

```
xscan workflow COMMAND [OPTIONS]
```

---

## Sub-commands

| Sub-command                     | Description                             |
|---------------------------------|-----------------------------------------|
| `xscan workflow list`           | List all available workflows            |
| `xscan workflow run NAME TARGET`| Run a workflow against a target         |
| `xscan workflow inspect NAME`   | Show DAG stages and requirements        |

---

## workflow list

```bash
xscan workflow list
```

Output:

```
Available workflows:

  xss-deep         Deep XSS analysis with taint tracking
  xss-fast         Quick XSS scan
  recon-full       Comprehensive reconnaissance
  crawl-deep       Deep crawl and asset discovery
  full-audit       Complete security assessment
  api-analysis     REST/GraphQL API analysis
  js-analysis      Static JS security analysis
```

---

## workflow run

```bash
xscan workflow run xss-deep example.com
xscan workflow run xss-deep example.com --profile deep
xscan workflow run xss-deep example.com --auth my-session
```

---

## workflow inspect

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
  web_crawler  javascript_analysis  browser  xss_validation

LLM specialists:
  technology  sink  context  test-planning

Output:
  findings  evidence  report
```

---

## Related topics

- `xscan help workflows`
- `xscan help concepts/dag`
- `xscan help commands/scan`
