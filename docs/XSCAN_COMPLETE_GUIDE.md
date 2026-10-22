# XScan — Complete Technical Guide

Version 0.1.0 | Local AI-Powered XSS Security Scanner

---

## Table of Contents

1. [What XScan Is](#1-what-xscan-is)
2. [Design Philosophy](#2-design-philosophy)
3. [Architecture Overview](#3-architecture-overview)
4. [Installation and Setup](#4-installation-and-setup)
5. [Command Reference](#5-command-reference)
6. [Scan Profiles](#6-scan-profiles)
7. [How a Scan Works — Step by Step](#7-how-a-scan-works--step-by-step)
8. [The Detection Engines](#8-the-detection-engines)
9. [Context and Encoding Analysis](#9-context-and-encoding-analysis)
10. [The Iterative Validation Loop](#10-the-iterative-validation-loop)
11. [DOM XSS Detection](#11-dom-xss-detection)
12. [Stored XSS Detection](#12-stored-xss-detection)
13. [LLM Integration — Ollama](#13-llm-integration--ollama)
14. [Skills System](#14-skills-system)
15. [External Tools](#15-external-tools)
16. [Recon Pipeline](#16-recon-pipeline)
17. [Evidence System](#17-evidence-system)
18. [DAG Engine](#18-dag-engine)
19. [Scope and Policy](#19-scope-and-policy)
20. [Workflow Definitions](#20-workflow-definitions)
21. [Storage and Checkpointing](#21-storage-and-checkpointing)
22. [Output and Reports](#22-output-and-reports)
23. [Configuration Reference](#23-configuration-reference)
24. [Security Boundaries](#24-security-boundaries)
25. [Known Limitations and Roadmap](#25-known-limitations-and-roadmap)

---

## 1. What XScan Is

XScan is a **local, AI-powered XSS scanner** that runs entirely on your machine. It requires no cloud accounts, no API keys, and no external services beyond Ollama (which also runs locally).

XScan is designed to detect three classes of XSS vulnerabilities:

- **Reflected XSS** — input reflected immediately in the HTTP response
- **Stored XSS** — input stored and later rendered in another page
- **DOM-based XSS** — input flowing from a browser-controlled source through JavaScript to a dangerous sink

XScan combines deterministic static analysis, HTTP reflection testing, and local LLM reasoning (Qwen3, DeepSeek, Mistral, or any Ollama model) to analyse vulnerabilities in a way that minimises false positives and explains its reasoning.

### What XScan is NOT

- Not a general-purpose web application scanner
- Not a fuzzer that sprays thousands of payloads blindly
- Not an autonomous agent that makes unrestricted decisions
- Not a replacement for manual testing and expert review

---

## 2. Design Philosophy

XScan is built around five non-negotiable principles:

### 2.1 Deterministic analysis first

Every scan begins with deterministic code — reflection detection, context classification, encoding analysis, DOM source/sink detection. The LLM only receives structured evidence produced by this deterministic layer. It never controls the scanner directly.

### 2.2 Context before payloads

XScan does not maintain a list of payloads to try blindly. It first determines:
- Where exactly the input lands in the response (HTML text, attribute, script string, DOM sink)
- What characters the server encodes or strips
- What the injection context requires to break out

Only then does it generate payloads appropriate for that specific context. This is why XScan generates `" onmouseover="alert(1)` for an HTML attribute with encoded angle brackets — not `<script>alert(1)</script>`.

### 2.3 Evidence before findings

XScan does not declare a finding based on LLM opinion. A candidate becomes a validated finding only when deterministic evidence confirms it:
- HTTP reflection of an unencoded payload
- Browser event observation (Phase 10, in progress)

The LLM can say "this is likely vulnerable" but that is stored as analysis, not as a confirmed finding.

### 2.4 Scope enforcement at every step

Every network request, tool invocation, and browser action passes through `ScopeEngine` and `PolicyEngine`. The LLM cannot bypass scope. Out-of-scope URLs are blocked before execution, not filtered after.

### 2.5 Bounded LLM

The LLM is a specialist, not an agent. It:
- Analyses context
- Explains what evidence suggests
- Plans bounded test cases
- Reasons about previous failures

It cannot execute shell commands, issue HTTP requests directly, modify scope, or confirm findings without evidence.

---

## 3. Architecture Overview

```
User
 |
 v
CLI (xscan xss / xscan recon / xscan chat)
 |
 v
CommandDispatcher
 |
 v
ScanService
 |
 v
DAGEngine  <-- Workflow YAML defines which nodes run in what order
 |
 +-- ScopeEngine  (every operation checked here)
 +-- PolicyEngine (LLM boundaries enforced here)
 |
 v
Nodes (parallel waves where dependencies allow)
 |
 +-- scope-check         Validates target is in scope
 +-- technology-detect   HTTP fingerprinting
 +-- crawler             BFS web crawler
 +-- candidate-generator Canary -> context -> encoding analysis
 +-- dom-xss-detector    Static JS source/sink analysis
 +-- stored-xss-detector Canary submission + display-page check
 +-- evidence-fusion     Merges all candidates into one typed set
 +-- xss-validator       Iterative test planning + HTTP validation
 +-- tool-xss-scan       XSStrike / dalfox (if installed)
 +-- report              Terminal / JSON output
 |
 v
EvidenceGraph (SQLite-backed)
 |
 v
Findings (only with deterministic evidence)
```

### Package layout

```
src/xscan/
├── cli/            Typer CLI — thin command wrappers
├── config/         Pydantic settings, defaults
├── core/
│   ├── dag/        DAG engine, graph, node registry, checkpoint
│   ├── scope/      ScopeEngine, PolicyEngine
│   └── dispatcher/ CommandDispatcher
├── nodes/
│   ├── recon/      scope-check, technology-detect, subdomain-enum, http-probe
│   ├── crawler/    BFS web crawler
│   ├── analysis/   candidate-generator, dom-xss-detector, stored-xss-detector
│   │               js-extractor, ast-parser, reflection-detector
│   ├── dom/        dom-source-sink-event, taint-graph-builder
│   ├── llm/        llm-candidate-triage, llm-context-specialist
│   ├── validation/ xss-validator
│   ├── xss/        evidence-fusion, evidence-collector
│   └── reporting/  report
├── llm/
│   ├── gateway.py          LLMGateway (single entry point for all LLM calls)
│   ├── providers/ollama.py OllamaProvider
│   └── specialists/        SpecialistBase, test_planning, triage, iterative_planner
├── validation/
│   ├── http.py      HTTPValidator
│   ├── observation.py Observation model
│   └── iterative.py  IterativeValidator (the main validation loop)
├── evidence/        EvidenceGraph, taint graph, provenance
├── skills/          SkillManager, Markdown skill packs
├── schemas/         All Pydantic domain models
├── storage/         SQLite database, repositories, migrations
├── tools/           ToolRegistry, adapters, installers
├── runtime/         LocalRuntime, WSLRuntime, resolver
└── workflows/       WorkflowLoader, WorkflowValidator, YAML definitions
```

---

## 4. Installation and Setup

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Runtime |
| Ollama | 0.3+ | Local LLM |
| Any Ollama model | any | Analysis |

### Install XScan

```bash
pip install -e ".[dev]"
```

Or from a cloned repository:

```bash
git clone <repo>
cd xscan
pip install -e ".[dev]"
```

### Install Ollama and pull a model

```bash
# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows: download installer from https://ollama.com
# Then pull a model:
ollama pull qwen3:14b       # recommended — best analysis quality, 8.6 GB
ollama pull qwen2.5-coder:7b  # good for code analysis, faster, 4.4 GB
ollama pull mistral           # fast triage, 4.1 GB
```

### Check your environment

```bash
xscan --fix
```

This checks Python, Ollama, the database, configuration, and installed tools. It will attempt automatic repairs for known issues.

### Set the active model

```bash
xscan models list           # see what is pulled
xscan models use qwen3:14b  # set active model
```

---

## 5. Command Reference

### Primary commands

```bash
xscan xss <target>          # Run XSS scan
xscan chat [message]        # Chat with Ollama about your scan
xscan install <tool>        # Install security tools
xscan skills                # Manage skill packs
xscan --fix                 # Check + repair environment
xscan models list           # List Ollama models
xscan models use <model>    # Switch active model
```

### xscan xss

```bash
xscan xss https://target.com

Options:
  --profile / -p    fast | balanced | deep  (default: balanced)
  --verbose / -v    Show per-node details
  --debug           Show full internal state
  --quiet / -q      Summary line only
  --json            Machine-readable JSON output
  --no-llm          Disable Ollama — deterministic analysis only
  --output / -o     Save JSON report to file
```

Examples:
```bash
xscan xss https://target.com
xscan xss https://target.com --profile deep
xscan xss https://target.com --verbose
xscan xss https://target.com --no-llm --profile fast
xscan xss https://target.com --json --output report.json
xscan xss https://target.com --quiet
```

### xscan chat

```bash
xscan chat
xscan chat what did the last scan find
xscan chat why did the scanner find nothing
xscan chat --scan A1B2C3D4    # reference a specific scan
```

The chat command connects to Ollama with the most recent scan as context. It also loads relevant skill packs. No quotes needed for multi-word messages.

### xscan install

```bash
xscan install katana
xscan install katana httpx dalfox nuclei
xscan install https://github.com/s0md3v/XSStrike.git
xscan install --list       # show all available tools
```

Tools are installed to `~/.xscan/bin/`. On Windows, Go tools are installed via WSL2 and copied to the bin directory. Python tools like XSStrike are cloned and a launcher script is created.

### xscan skills

```bash
xscan skills list
xscan skills show jquery
xscan skills show xss-filter-bypass
xscan skills install ~/my-skill.md
xscan skills search --query dom
```

---

## 6. Scan Profiles

Profiles control depth, resource usage, and which nodes run. They do NOT change the methodology — every profile uses the same detection pipeline.

| Profile | Crawl | Candidates | Iterations | DOM | Stored | Use case |
|---------|-------|------------|------------|-----|--------|----------|
| `fast` | 20 pages, depth 2 | 20 max | 3 | Basic | No | CI pipelines, quick checks |
| `balanced` | 60 pages, depth 3 | 30 max | 5 | Full | Yes | Standard assessment |
| `deep` | 150 pages, depth 5 | 50 max | 5 | Full + AST | Yes | Thorough assessment |

```bash
xscan xss target.com --profile fast      # ~30s on simple targets
xscan xss target.com --profile balanced  # ~2-5 min typical
xscan xss target.com --profile deep      # ~10-20 min
```

The `deep` profile additionally runs the JS AST extractor, DOM source/sink/event analyser, and taint graph builder — nodes that are skipped in `fast` and `balanced` for performance.

---

## 7. How a Scan Works — Step by Step

When you run `xscan xss https://target.com --profile balanced`, this is what happens:

### Step 1: Scope validation (node: scope-check)

The target URL is parsed and a `Scope` object is created from the hostname. Every subsequent network operation will be checked against this scope before execution. Out-of-scope requests raise `PolicyViolation` and are blocked.

```
Scope: *.target.com, target.com
Allow: https://target.com/search
Allow: https://api.target.com/v1
Block: https://evil.com/steal
Block: https://target.com.attacker.test
```

### Step 2: Technology detection (node: technology-detect)

XScan makes one HTTP request to the target and fingerprints:
- Server software (Nginx, Apache, IIS, Caddy)
- Backend framework (PHP, ASP.NET, Express, Django, Laravel, Rails)
- Frontend framework (React, Angular, Vue, jQuery, Bootstrap)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie flags (HttpOnly, Secure, SameSite)

This information is used to select the right skill packs for LLM analysis.

### Step 3: Crawling (node: crawler)

A BFS web crawler discovers all URLs and HTML forms within scope:
- Follows `<a href>` links
- Discovers `<form>` elements with their inputs
- Stays within the target's origin (same scheme+host)
- Respects the `max_pages` and `max_depth` limits

Output: list of URLs, list of forms (with their input field names and types), URLs that contain query parameters.

### Step 4: Candidate generation (node: candidate-generator)

For each URL with parameters and each form input:

**Phase 1 — Canary injection:**
Injects a unique harmless marker (e.g., `xscCad95297d`) into each parameter and checks if it appears in the response.

**Phase 2 — Context classification:**
If the canary reflects, `ContextAnalyser` finds every position where it appears and classifies the injection context:
- `html_text` — inside a text node: `<h1>xscCad95297d</h1>`
- `html_attribute` — inside an attribute: `<input value="xscCad95297d">`
- `script_string_double` — inside a JS string: `var x = "xscCad95297d";`
- `script_expression` — bare JS expression: `return xscCad95297d;`
- `html_comment`, `url_param`, `json_string`, etc.

When multiple contexts are found (e.g., canary appears in both `<h1>` and `<input value="">`), the most exploitable context is selected: `html_attribute` > `script_string` > `html_text`.

**Phase 3 — Encoding analysis:**
For each special character (`<`, `>`, `"`, `'`, `&`, `;`, `(`, `)`, `` ` ``, `/`), a probe is injected to determine if the server encodes, strips, or passes it through raw.

This produces an `EncodingProfile` with three lists:
- `raw_chars` — characters NOT encoded (exploitable)
- `encoded_chars` — HTML entity encoded (must avoid these in payloads)
- `stripped_chars` — removed entirely (unusable)

The combination of context + encoding uniquely determines which payloads can work.

### Step 5: DOM analysis (nodes: dom-xss-detector, js-extractor, ast-parser, taint-graph-builder)

XScan extracts all JavaScript — both inline `<script>` blocks and external `.js` files — and analyses them for source→sink flows.

**Sources** (attacker-controlled data entering JS):
- `location.hash`, `location.search`, `location.href`
- `URLSearchParams.get()`
- `document.URL`, `document.referrer`
- `window.name`, `postMessage` data
- `localStorage`, `sessionStorage`

**Sinks** (where data causes execution):
- `innerHTML`, `outerHTML`, `document.write()`
- `eval()`, `new Function(string)` (NOT normal callbacks)
- `jQuery $()`, `jQuery .html()`, `.insertAdjacentHTML()`
- `element.href`, `element.src`, `location.assign()`

**Event detection:**
The engine specifically looks for event-driven flows:
```javascript
$(window).on('hashchange', function() {
    var post = $('section h2:contains(' +
        decodeURIComponent(window.location.hash.slice(1)) + ')');
});
```
This is detected as: `source=location.hash, event=hashchange, transform=decodeURIComponent+slice, sink=jQuery $()`

**Taint graph:**
For event-driven flows, XScan builds a 3-node taint path:
```
TaintNode(SOURCE, "location.hash")
  --[event-source]--> TaintNode(FUNCTION, "on:hashchange")
  --[event-sink]--> TaintNode(SINK, "jQuery $()")
```

### Step 6: Stored XSS detection (node: stored-xss-detector)

For forms that look like storage forms (comment boxes, feedback fields, profile fields), XScan:
1. Submits a unique canary to the form
2. Crawls pages that might display stored content (the homepage, post pages, profile pages, etc.)
3. If the canary appears in a response, classifies the injection context at that location

### Step 7: Evidence fusion (node: evidence-fusion)

All candidates from all engines are merged into one typed `XSSCandidate` set. Duplicates are deduplicated by (source, sink, file) or (url, parameter, context). Each DOM candidate is enriched with execution semantics:

```python
{
  "xss_type": "dom",
  "source_type": "hash",         # source delivers data via URL fragment
  "sink_capability": "selector", # jQuery $() interprets HTML
  "event_type": "hashchange",    # trigger: navigate + change hash
  "validation_mode": "event_triggered",
  "transformations": ["decodeURIComponent", "slice"]
}
```

### Step 8: Iterative validation (node: xss-validator)

For each candidate, XScan runs the iterative generate→test→learn→replan loop.

See Section 10 for full details.

### Step 9: External tools (node: tool-xss-scan)

If XSStrike and/or dalfox are installed, they are run against validated candidates. Results are normalised into `ToolObservation` objects with explicit status codes. `NO_PARAMETERS` and `TIMEOUT` are never interpreted as "no vulnerability found".

### Step 10: Report

A structured terminal report is printed (or JSON saved to file). See Section 22.

---

## 8. The Detection Engines

### Reflected XSS engine

**How it works:** Canary injection → HTTP response analysis → context classification → encoding probe → typed candidate.

**What it detects:** Any parameter or form input whose value appears unencoded in the server's HTML response.

**What it does NOT detect:** DOM-based flows where the server never reflects the value (the browser's JavaScript reads it client-side).

### DOM XSS engine

**How it works:** Static analysis of JavaScript source text. Regex-based source/sink/event detection with context windows. Taint graph construction.

**What it detects:**
- Direct source→sink flows in the same function
- Event-driven flows (hashchange, postMessage, popstate)
- jQuery selector injection patterns

**Known limitation:** Does not execute JavaScript. Cannot trace data flow through closures, async callbacks, or complex object property chains. Reports `analysis_incomplete` when budget is exceeded.

### Stored XSS engine

**How it works:** Canary submission to storage-like forms, followed by crawling of display pages.

**What it detects:** XSS that persists across requests — comments, reviews, profiles, messages.

**Important:** XScan only marks a result as stored XSS if the canary is found on a page other than the submission page. It does NOT assume a 200 OK response means the data was stored.

---

## 9. Context and Encoding Analysis

This is one of XScan's core capabilities — it determines exactly what you can inject before generating any payloads.

### Context taxonomy

| Context | Example | What it means |
|---------|---------|---------------|
| `html_text` | `<p>VALUE</p>` | Inside a text node |
| `html_attribute` | `<input value="VALUE">` | Inside a quoted attribute value |
| `html_attribute_unquoted` | `<input value=VALUE>` | Unquoted attribute |
| `script_string_double` | `var x = "VALUE";` | Inside a JS double-quoted string |
| `script_string_single` | `var x = 'VALUE';` | Inside a JS single-quoted string |
| `script_string_template` | `` var x = `VALUE`; `` | Inside a JS template literal |
| `script_expression` | `return VALUE;` | Bare JS expression |
| `html_comment` | `<!-- VALUE -->` | Inside HTML comment |
| `url_param` | `<a href="VALUE">` | Inside href/src/action attribute |
| `json_string` | `{"key":"VALUE"}` | Inside a JSON value |

### Multi-reflection ranking

When the same input appears in multiple places (very common — e.g., in the page title `<h1>` AND in a `<input value="">`), XScan picks the most exploitable context:

```
html_attribute (5) > script_string (4) > html_text (2) > html_comment (1) > unknown (0)
```

This is why `" onmouseover="alert(1)` is generated even when angle brackets are encoded — the attribute context is identified as the primary attack surface.

### Encoding analysis results

```
raw_chars:     ['"', "'", ' ', '=', '-']  # These pass through unencoded
encoded_chars: ['<', '>']                  # HTML entity encoded
stripped_chars: []                         # None removed

can_break_html_attribute: True   # " is raw → can break out of attribute
can_break_html_text:      False  # < is encoded → cannot inject tags
can_break_script_string:  True   # " is raw → can break JS string
```

---

## 10. The Iterative Validation Loop

XScan does not generate a payload list and fire them all blindly. It implements a bounded generate→test→learn→replan loop.

### How it works

```
IterationState (tracks all attempts and budget)
     |
     v
[while budget allows]
     |
     v
Plan candidates
  Iteration 1: skill-aware heuristic (deterministic, uses context+encoding)
  Iteration 2+: LLM replanner (uses observation history from previous attempts)
     |
     v
Deduplicate (fingerprint each candidate — never retest the same payload)
     |
     v
Policy gate (ScopeEngine + PolicyEngine must approve)
     |
     v
HTTPValidator executes the test
     |
     v
Observation captured:
  - reflected (unencoded) → VALIDATED → stop if stop_on_confirmation
  - encoded → record for replanning
  - stripped → record for replanning
  - not found → record for replanning
     |
     v
Build PreviousTestResult:
  "Candidate C003: payload='<img>' — stripped/removed by application"
     |
     v
If attempts remain → replan with observations
  LLM receives: context + encoding + all previous results + failed hypotheses
     |
     v
[repeat]
     |
     v
Terminal state: CONFIRMED | VALIDATED | INCONCLUSIVE | BUDGET_EXHAUSTED
```

### Budget limits (enforced by XScan, not LLM)

```yaml
max_iterations:               5    # How many replan cycles
max_candidates_per_iteration: 5    # Candidates per cycle
max_total_candidates:         20   # Hard cap on total tests
max_requests:                 40   # Maximum HTTP requests per candidate
max_runtime_s:                120  # Wall clock limit
stop_on_confirmation:         true # Stop immediately when validated
```

**BUDGET_EXHAUSTED is not the same as SAFE.** If the budget runs out without confirmation, the status is `INCONCLUSIVE`, not "no vulnerability".

### Candidate fingerprinting

Each candidate is identified by a SHA-256 fingerprint of `payload + url + parameter + context`. If the same payload has already been tested for this parameter+context, it is skipped — even across replan cycles.

### Replan prompt (what the LLM receives)

```
=== PREVIOUS TEST RESULTS ===
Candidate C001: payload='" onmouseover="alert(1)' — stripped/removed
Candidate C002: payload='<img src=x onerror=alert(1)>' — encoded as &lt;img&gt;
Candidate C003: payload='" onfocus="alert(1)"' — reflected UNENCODED

=== FAILED HYPOTHESES ===
angle bracket injection — < and > are HTML-encoded

=== REMAINING BUDGET ===
Max candidates this iteration: 5
Total tested so far: 3
```

---

## 11. DOM XSS Detection

### The execution semantics model

For DOM XSS, XScan tracks the full execution chain, not just source→sink:

```
Source:          location.hash
Transformation:  slice(1) → decodeURIComponent()
Event:           hashchange
Sink:            jQuery $()
Sink context:    selector construction
Validation mode: event_triggered
```

This information is stored in `execution_semantics` and passed to the validator. The validator then generates sink-specific payloads:

| Sink | Source (hash) | Generated payloads |
|------|--------------|-------------------|
| `jQuery $()` | `location.hash` | `#<img src=x onerror=alert(1)>`, `#<svg onload=alert(1)>` |
| `innerHTML` | `location.hash` | `#<img src=x onerror=alert(1)>`, `#<script>alert(1)</script>` |
| `eval()` | `location.hash` | `#alert(1)`, `#1;alert(1)//` |
| `Function()` | `location.hash` | `#alert(1)`, `#;alert(1)//` |
| `element.href` | `location.hash` | `#javascript:alert(1)` |

### The Function() false-positive fix

XScan specifically distinguishes:

```javascript
// SAFE — normal callback, NOT a sink
$(window).on('hashchange', function() { ... })

// DANGEROUS — dynamic code constructor, IS a sink
new Function(userControlledData)
Function("alert(1)")()
```

The sink patterns match `new Function(` and `Function(string_literal)` but not regular `function() {}` syntax.

### Event-driven validation

For `hashchange` and similar event-triggered flows, the test URL includes the payload in the fragment:
```
https://target.com/#<img src=x onerror=alert(1)>
```

HTTP validation can confirm text reflection. Browser validation (Phase 10) is required to confirm actual execution, because:
1. The page must load first to register the `hashchange` handler
2. Then the fragment must change to trigger the event
3. Then the JavaScript runs and the sink executes

Phase 10 will use Playwright to automate this sequence.

---

## 12. Stored XSS Detection

XScan identifies storage candidates by looking for form inputs with names that suggest storage:

```
comment, message, body, content, text, description
feedback, review, post, reply, note, name, username
title, subject, bio, about
```

For each storage form, it:
1. Submits a unique canary (e.g., `xscSTORED8a2f3b`)
2. Waits for the server to process it
3. Fetches the homepage, post pages, profile pages, and other likely display locations
4. If the canary is found on any of these pages, classifies the injection context

A stored XSS candidate is only created if the canary appears on a **different** page from where it was submitted.

---

## 13. LLM Integration — Ollama

### Architecture

```
Specialist (typed input/output)
     |
     v
LLMGateway (single entry point, logs all calls)
     |
     v
OllamaProvider (REST API wrapper)
     |
     v
Ollama (running locally at localhost:11434)
     |
     v
Model (qwen3:14b, deepseek-coder, mistral, etc.)
```

### Specialists

Each specialist receives structured Pydantic input and returns structured Pydantic output. The LLM never receives raw HTML or HTTP responses.

| Specialist | Input | Output | Used for |
|------------|-------|--------|---------|
| `CandidateTriageSpecialist` | Candidate + context + encoding + evidence | Severity, confidence, context analysis | Analysing a candidate's exploitability |
| `TestPlanningSpecialist` | Candidate + context + encoding + skills | List of test cases with rationale | Planning what to test |
| `IterativePlannerSpecialist` | All previous results + remaining budget + skills | Next candidates to try | Replanning after failures |
| `LLMContextSpecialist` | Fused candidate + taint path | Classification, explanation | Explaining what was found |
| `TechnologySpecialist` | HTTP evidence | Tech stack | Framework detection |
| `IntentSpecialist` | User's natural language intent | Workflow selection | `xscan smart` command |

### Model selection

```bash
xscan models list            # see available models
xscan models use qwen3:14b   # set active model
xscan models test qwen3:14b  # verify it responds
```

Recommended models by use case:
- **qwen3:14b** — best analysis quality, recommended for balanced/deep profiles
- **qwen2.5-coder:7b** — good for JavaScript/code analysis, faster
- **mistral** — fast triage, good for the `fast` profile
- **deepseek-r1:7b** — strong reasoning, good for complex candidates

### Running without LLM

```bash
xscan xss target.com --no-llm
```

In `--no-llm` mode, XScan uses only deterministic heuristics for test planning. It still detects reflected, DOM, and stored XSS — the LLM adds analysis depth and adaptive replanning, but the core detection works without it.

---

## 14. Skills System

Skills are Markdown knowledge files that give Ollama domain-specific XSS knowledge. They are injected into the LLM's context during analysis.

### How skills are selected

When a scan runs, the skill manager selects the most relevant skills based on:
- Detected technologies (`jQuery`, `React`, `Angular`, etc.)
- Injection context (`html_attribute`, `script_string`, `dom-xss`, etc.)
- Scan phase (triage, test planning, context analysis)

```python
# Example: attribute XSS with encoded angles → selects:
["reflected-attribute-encoded-angles", "context-detection", "xss-filter-bypass"]

# DOM XSS with jQuery → selects:
["dom-xss-sources-sinks", "jquery", "context-detection"]

# AngularJS detected → selects:
["xss-angularjs", "angularjs"]
```

### Built-in skills

**Core XSS skills:**
- `reflected-html-context` — HTML text injection, basic payloads
- `reflected-attribute-encoded-angles` — event handler injection when `<>` are encoded
- `reflected-javascript-string` — JS string breakout patterns
- `dom-xss-sources-sinks` — all DOM sources, sinks, and appropriate payloads
- `stored-xss` — storage form patterns, display-page detection
- `context-detection` — the decision matrix: which context needs which approach
- `javascript-context` — script string breakout techniques

**Framework skills:**
- `jquery` — `$()` selector injection, `location.hash` patterns, `.html()` sink
- `react` — `dangerouslySetInnerHTML`, unvalidated `href`
- `angularjs` — `{{expression}}` injection, sandbox escapes

**Advanced skills (from PayloadsAllTheThings):**
- `xss-filter-bypass` — case sensitivity, tag blacklist bypass, encoding bypass
- `xss-polyglot` — payloads that work across multiple contexts
- `xss-waf-bypass` — Cloudflare, Akamai, Incapsula bypass techniques
- `xss-csp-bypass` — JSONP, nonce, unsafe-inline bypass techniques
- `xss-angularjs` — full AngularJS template injection reference

### Adding custom skills

Create a Markdown file with frontmatter:

```markdown
---
tags: xss, my-framework, custom
category: framework
---

# My Framework XSS Patterns

## Dangerous sinks

...your knowledge here...
```

Install it:
```bash
xscan skills install ~/my-skill.md
```

### Importing from PayloadsAllTheThings

```bash
# Clone the repo
xscan install https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Import XSS files as skills
python scripts/import_payloads_skills.py
```

---

## 15. External Tools

XScan integrates with security tools through a typed adapter layer. Tools are never called directly from nodes — they go through `ToolRegistry → Runtime`.

### Installed tools

```bash
xscan --fix              # shows which tools are installed
xscan install --list     # shows all available tools
```

| Tool | Purpose | Install |
|------|---------|---------|
| `katana` | Web crawler | `xscan install katana` |
| `httpx` | HTTP probe | `xscan install httpx` |
| `dalfox` | XSS scanner | `xscan install dalfox` |
| `subfinder` | Subdomain enum | `xscan install subfinder` |
| `nuclei` | Vulnerability scan | `xscan install nuclei` |
| `ffuf` | Directory discovery | `xscan install ffuf` |
| `amass` | Subdomain enum | `xscan install amass` |
| `XSStrike` | XSS scanner (Python) | `xscan install https://github.com/s0md3v/XSStrike.git` |

### Tool failure semantics

XScan explicitly distinguishes these states — they are NEVER conflated:

| Status | Meaning |
|--------|---------|
| `completed_with_results` | Tool ran, found candidates |
| `completed_no_results` | Tool ran cleanly, found nothing |
| `no_parameters` | Tool found no parameters to test |
| `connection_failed` | Could not reach target |
| `execution_failed` | Tool process errored |
| `timeout` | Tool exceeded time limit |
| `tool_unavailable` | Binary not installed |

`timeout` and `no_parameters` are NOT "no vulnerability found". They mean XScan could not assess — not that the target is safe.

### WSL2 support

On Windows, Go-based security tools are installed inside WSL2 and their binaries are copied to `~/.xscan/bin/`. The `WSLRuntime` proxies execution through `wsl.exe`.

---

## 16. Recon Pipeline

The recon pipeline discovers the full attack surface before XSS analysis begins.

### Workflows

```bash
xscan recon target.com                    # balanced recon
xscan recon target.com --profile passive  # subdomain enum only, no active probing
xscan recon target.com --profile deep     # full recon with FFUF
```

### recon-only workflow (balanced)

```
scope-check
    |
    +-- technology-detect (HTTP fingerprinting)
    +-- subdomain-enum (Subfinder + Assetfinder)
         |
         v
    asset-fusion (deduplicate, scope-check each asset)
         |
         v
    http-probe (probe each in-scope asset)
         |
         v
    endpoint-inventory (merge crawler + probes)
         |
         v
    report
```

### recon-deep workflow

```
scope-check
    |
    +-- technology-detect
    +-- subdomain-enum (Subfinder + Assetfinder + Amass)
         |
         v
    asset-fusion
         |
         v
    http-probe
         |
         +-- tech-all (technology detect on all live assets)
         +-- directory-discovery (FFUF on each live asset)
              |
              v
    endpoint-inventory (crawler + FFUF + JS discovery merged)
         |
         v
    report
```

### Asset deduplication

The same hostname discovered by multiple tools → ONE `ReconAsset` with multiple sources:

```python
ReconAsset(
    hostname="api.target.com",
    sources=["subfinder", "assetfinder", "amass"],  # 3 tools, 1 asset
    in_scope=True,
    live=True,
    https_available=True,
    technologies=["Nginx", "Express.js"]
)
```

### Scope enforcement in recon

ScopeEngine is the authoritative scope check — not string matching. These are correctly handled:

```
target.com             → IN SCOPE
api.target.com         → IN SCOPE (subdomain)
dev.api.target.com     → IN SCOPE (deep subdomain)
target.com.evil.test   → BLOCKED (not a subdomain)
notarget.com           → BLOCKED (unrelated domain)
```

---

## 17. Evidence System

XScan captures structured evidence for every observation. Nothing is reported without evidence.

### Evidence types

| Type | Description |
|------|-------------|
| `http-request` | The exact HTTP request sent |
| `http-response` | The HTTP response received |
| `reflection` | Snippet showing where the payload appeared |
| `dom-snapshot` | DOM state at time of observation |
| `taint-path` | Source→event→sink path from JS analysis |
| `tool-output` | External tool observation |
| `llm-reasoning` | LLM analysis (explicitly marked as opinion, not proof) |

### Evidence graph

Evidence nodes are linked in a graph showing causality:

```
Finding
  └── XSSCandidate
        ├── HTTP Request (the probe)
        ├── HTTP Response (the reflection)
        ├── Reflection (snippet showing unencoded payload)
        └── LLM Reasoning (marked as analysis, not proof)
```

### Evidence invariant

A `Finding` cannot be created without at least one deterministic evidence node (HTTP_RESPONSE, REFLECTION, DOM_SNAPSHOT, etc.). The system raises `MissingEvidenceError` if this rule is violated. LLM reasoning alone is never sufficient for a finding.

---

## 18. DAG Engine

Every XScan workflow executes as a versioned, checkpointed Directed Acyclic Graph.

### How it works

1. **Plan**: Load workflow YAML, build `WorkflowGraph`, validate structure (no cycles, no unknown node types, no unknown dependencies)
2. **Compute waves**: Identify which nodes can run in parallel (nodes whose dependencies are all in earlier waves)
3. **Execute**: Run each wave. Within a wave, nodes execute sequentially (parallel support in roadmap)
4. **Checkpoint**: After each node completes or fails, save `NodeResult` to SQLite
5. **Thread outputs**: Each node's outputs are merged into shared state for downstream nodes

### Resume

```bash
xscan status          # list recent scans
xscan resume          # resume most recent interrupted scan
xscan resume A1B2C3   # resume a specific scan by ID
```

When resuming, the engine loads the previous `WorkflowRun` state, identifies completed nodes, and skips them. The scan continues from the first incomplete node.

### Node contract

Every DAG node:
- Receives an `ExecutionContext` (scope, policy, inputs, config, scan_id)
- Reads inputs via `ctx.get("key")`
- Writes outputs by returning a dict
- Uses `NodeEmitter` for structured event emission (no print statements)
- Calls `ctx.scope.assert_allowed()` before every network operation
- Never calls other nodes directly

---

## 19. Scope and Policy

### ScopeEngine

`ScopeEngine` is the authoritative gatekeeper. It is created from the target URL at scan start and is injected into every node via `ExecutionContext`.

```python
# Every network operation must pass this check
ctx.scope.assert_allowed("https://target.com/search", operation="http_request")
# Raises PolicyViolation if out of scope
```

Scope rules support:
- Exact domain: `target.com`
- Wildcard subdomain: `*.target.com`
- URL prefix: `https://target.com/app/*`
- CIDR range: `192.168.1.0/24`
- Regex: `target\.com/api/v\d+`
- Exclude: `https://target.com/logout` (blocks despite other allow rules)

### PolicyEngine

`PolicyEngine` applies operation-level rules on top of scope validation:

```
LLM specialist nodes CANNOT issue HTTP requests directly
Research fetches are restricted to an allowed-domain allowlist
```

The LLM cannot modify scope, increase request limits, or bypass policy checks. These are enforced structurally, not by prompting.

---

## 20. Workflow Definitions

Workflows are versioned YAML files that define the DAG.

### xss-fast

5 nodes. For CI pipelines and quick checks.
```
scope-check → recon → crawler → reflection-detect → report
```

### xss-balanced (default)

10 nodes. Standard assessment.
```
scope-check → recon → crawler
    ├── candidate-generator   (reflected XSS)
    ├── dom-xss-detector      (DOM source/sink)
    └── stored-xss-detector   (stored XSS)
         ↓
    evidence-fusion           (merge all candidates)
         ↓
    xss-validator             (iterative test planning)
         ↓
    tool-xss-scan             (XSStrike / dalfox)
         ↓
    report
```

### xss-deep

15 nodes. Thorough assessment.
```
scope-check → recon → crawler
    ├── candidate-generator
    ├── stored-xss-detector
    └── js-extractor
         ↓
    ast-parser
         ↓
    dom-source-sink-event
         ↓
    taint-graph-builder
         ↓
    tool-xss-scan
         ↓
    evidence-fusion
         ↓
    llm-context-specialist
         ↓
    xss-validator
         ↓
    evidence-collector        (creates Findings with evidence)
         ↓
    report
```

### recon-only

7 nodes. Discovery only, no XSS testing.

### recon-deep

9 nodes. Full discovery with FFUF directory scanning.

---

## 21. Storage and Checkpointing

XScan stores all data in SQLite at `~/.xscan/xscan.db`.

### What is stored

- `scans` — scan records (target, profile, status, timestamps)
- `workflow_runs` — DAG execution state per scan
- `node_results` — output + status per node per run
- `evidence_nodes` — all evidence observations
- `evidence_edges` — evidence graph relationships
- `artifacts` — binary/text artifacts (screenshots, HAR files, etc.)
- `findings` — confirmed findings with evidence links
- `audit_log` — all events with timestamps

### Schema migrations

The database uses versioned migrations. XScan automatically migrates on startup:
```bash
xscan --fix    # runs migrations if needed
```

### Configuration

```toml
# ~/.xscan/config.toml
[llm]
model    = "qwen3:14b"
provider = "ollama"
base_url = "http://localhost:11434"
timeout  = 120

[storage]
db_path = "/home/user/.xscan/xscan.db"
```

---

## 22. Output and Reports

### Terminal output (default)

```
XScan  Scan: A1B2C3D4
Target: https://target.com

  10:31:52  RUN   scope-validation
  10:31:52  DONE  scope-validation    target.com host  0.0s
  10:31:52  RUN   recon
  10:31:53  DONE  recon               jQuery  7 missing headers  0.9s
  10:31:53  RUN   crawl
  10:31:59  DONE  crawl               7 urls  5 forms  32 inputs  6.1s
  10:31:59  RUN   candidate-gen
  10:32:48  DONE  candidate-gen       37 inputs analyzed  2 candidates  31.3s
  ...

XScan Report  POTENTIAL CRITICAL XSS DETECTED

  URLs crawled:      7
  Inputs analyzed:   37
  Candidates found:  2
  Validated (HTTP):  2

Technologies:  jQuery

Validated XSS candidates (2):

  VALIDATED  search  https://target.com/...
     Context:   html_attribute
     Encoding:  raw: ['"']  encoded: ['<', '>']
     Strategy:  event handler injection (no < or > needed)
     Working payload: " onmouseover="alert(1)
     Test URL:
     https://target.com/?search=%22+onmouseover%3D%22alert%281%29

SCAN COMPLETE
  URLs crawled             7
  Reflections              2
  Validated (HTTP)         2
  Duration                 91.9s
  Scan ID                  A1B2C3D4
```

### Verbosity levels

```bash
xscan xss target.com              # normal — summaries and findings
xscan xss target.com --verbose    # per-node details and metrics
xscan xss target.com --debug      # full internal state
xscan xss target.com --quiet      # final summary line only
```

### JSON output

```bash
xscan xss target.com --json
xscan xss target.com --json --output report.json
```

```json
{
  "scan_id": "A1B2C3D4",
  "target_url": "https://target.com",
  "status": "completed",
  "duration_s": 91.9,
  "technologies": ["jQuery"],
  "validated_count": 2,
  "confirmed_findings": 0,
  "candidates": [...]
}
```

### Finding states

| State | Meaning |
|-------|---------|
| `VALIDATED` | Unencoded reflection confirmed via HTTP — payload reflects correctly |
| `CONFIRMED` | Browser evidence proves JavaScript execution (Phase 10) |
| `INCONCLUSIVE` | Budget exhausted without confirmation |
| `BUDGET_EXHAUSTED` | Hard limit hit — NOT the same as safe |

---

## 23. Configuration Reference

### Config file

Location: `~/.xscan/config.toml`

```toml
[llm]
model    = "qwen3:14b"      # Active Ollama model
provider = "ollama"         # LLM provider (only ollama currently)
base_url = "http://localhost:11434"
timeout  = 120              # LLM request timeout (seconds)
temperature = 0.1           # LLM temperature (lower = more deterministic)
max_tokens = 2048           # Maximum output tokens per LLM call

[scan]
default_profile = "balanced"
http_timeout    = 15        # HTTP request timeout (seconds)
verify_ssl      = false     # SSL certificate verification

[storage]
db_path = "~/.xscan/xscan.db"
log_dir = "~/.xscan/logs"

[runtime]
execution_env = null        # null = auto-detect, "wsl" = force WSL2, "local" = force local
wsl_distro    = "Ubuntu"
```

### Environment variables

All config values can be overridden via environment variables with the `XSCAN_` prefix:

```bash
XSCAN_LLM__MODEL=mistral xscan xss target.com
XSCAN_LLM__BASE_URL=http://localhost:11434 xscan xss target.com
XSCAN_SCAN__HTTP_TIMEOUT=30 xscan xss target.com
```

---

## 24. Security Boundaries

XScan is built with strict security boundaries that cannot be bypassed:

### The LLM cannot

- Execute shell commands
- Issue HTTP requests directly
- Navigate a browser directly
- Modify authorised scope
- Modify policy limits
- Confirm a finding without deterministic evidence
- Generate unlimited payloads
- Perform unrestricted fuzzing
- Select targets outside the configured scope

### All external tool execution passes through

```
ToolRegistry → CapabilityRegistry → ToolAdapter → Runtime → OS
```

Never from LLM output directly.

### Scope is enforced structurally

Every network operation calls `ctx.scope.assert_allowed()`. This raises `PolicyViolation` which is caught and logged. It is not possible to make a network request from a node without passing this check.

### Evidence requirement

```python
# This will raise MissingEvidenceError — LLM opinion alone is not sufficient
Finding(
    evidence_ids=[],  # empty → exception raised
    ...
)
```

---

## 25. Known Limitations and Roadmap

### Current limitations

**DOM XSS validation:**
HTTP validation cannot trigger `hashchange` or `postMessage` events. For event-driven DOM XSS, XScan correctly identifies the candidate and generates the right test URLs, but cannot confirm execution without browser automation. Status: `VALIDATED` (reflection confirmed) not `CONFIRMED` (execution proven).

**JavaScript analysis:**
The JS analysis uses regex-based heuristics, not a full AST parser with data-flow analysis. It does not trace data through closures, complex object property chains, or async callbacks. Results are conservative — it reports `analysis_incomplete` rather than guessing.

**Authentication:**
XScan cannot authenticate to applications that require login before testing. The `--auth` flag is planned but not yet implemented.

**Scope is set from target URL:**
Currently scope is derived automatically from the target URL. A dedicated `xscan scope` command is planned for complex multi-host assessments.

### Phase 10 — Browser validation (in progress)

The next major milestone is Playwright integration for browser-based validation:
- Trigger `hashchange`, `popstate`, `message` events
- Capture DOM snapshots, console output, network logs
- Take screenshots as evidence
- Confirm JavaScript execution (not just text reflection)

When Phase 10 is complete, DOM XSS candidates will move from `VALIDATED` to `CONFIRMED` with full browser evidence.

### Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Schemas, config, storage, events | Complete |
| 2 | DAG engine, workflow loader | Complete |
| 3 | Scope engine, policy engine | Complete |
| 4 | Command dispatcher, services | Complete |
| 5 | Doctor, repair DAG | Complete |
| 6 | Tool registry, WSL2 runtime | Complete |
| 7 | LLM gateway, specialists | Complete |
| 8 | Evidence graph | Complete |
| 9 | Node migration (reflected, DOM, stored, report) | Complete |
| 10 | Browser validation (Playwright) | In progress |
| 11 | TUI / VS Code integration | Planned |
| 12 | Lab fixtures, end-to-end tests | Planned |
| 13 | AngularJS template injection | Planned |
| 14 | JWT/Auth analysis | Planned |
| 15 | Prototype pollution detection | Planned |

---

## Quick Reference Card

```bash
# Run a balanced XSS scan
xscan xss https://target.com

# Deep scan with verbose output
xscan xss https://target.com --profile deep --verbose

# Fast scan, no LLM, save JSON
xscan xss https://target.com --profile fast --no-llm --json -o out.json

# Recon only
xscan recon target.com
xscan recon target.com --profile deep

# Check environment
xscan --fix

# Manage models
xscan models list
xscan models use qwen3:14b
xscan models test

# Install tools
xscan install katana dalfox
xscan install https://github.com/s0md3v/XSStrike.git
xscan install --list

# Skills
xscan skills list
xscan skills show xss-filter-bypass
xscan skills show jquery

# Chat about your scan
xscan chat what did the last scan find
xscan chat why did the scanner find nothing
xscan chat explain the DOM XSS that was found

# Switch model
xscan models use qwen2.5-coder:7b
```

---

*XScan is a controlled security assessment platform for authorised targets only. Always obtain written permission before scanning any system you do not own.*
