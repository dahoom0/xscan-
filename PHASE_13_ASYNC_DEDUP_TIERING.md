# Phase 13: Async I/O + Deduplication + Tiered Escalation

## Status
**Planned, not yet started.** This is a post-Phase-K refactoring initiative to improve speed and resource efficiency at scale (10k+ URLs).

## Rationale

Phases 1–12 delivered a working, end-to-end XScan with strong evidence-first semantics and comprehensive type safety. The current implementation uses:
- Synchronous `requests` + `ThreadPoolExecutor` (5 threads by default)
- Per-candidate HTTP validation without deduplication of similar endpoints
- Unbounded escalation to expensive Bounded Validation (headless browser) for all candidates

These choices work fine for 100–1000 URL targets but create three bottlenecks at scale:

1. **Thread-based sync I/O:** Threads carry OS-level overhead. 5 threads don't scale past a few hundred concurrent connections cleanly. TCP/TLS handshake overhead is paid per request, not per host. Modern async I/O (asyncio + httpx.AsyncClient) can sustain thousands of concurrent connections with connection pooling and keep-alive reused across all requests to the same host.

2. **No endpoint deduplication:** A real recon crawl often produces 200+ URLs that are structurally identical (`/product?id=1`, `/product?id=2`, `/product?id=3`, ...). Probing all of them wastes 80–90% of requests. Reflection behavior is almost always a property of the code path, not the specific value.

3. **Unbounded escalation to browser:** The Bounded Validation node (headless Chrome) is necessary and correct for confirming findings, but heavy and slow. Every candidate gets browser time, including low-confidence ones that would likely time out or trigger WAF blocks.

## Master Plan

### Phase 13A — Switch to async I/O

**Goal:** Replace thread-based sync I/O with `asyncio` + `httpx.AsyncClient`.

**Scope:**
- One `AsyncClient` per DAG run with connection pooling and keep-alive reused across all requests to the same host.
- Replace `--threads N` with `--concurrency N` controlling an `asyncio.Semaphore`, scoped **per-host** not global — so one slow host doesn't stall probing on fast ones, and you don't hammer a single target past its rate limit.
- Move this into a `ToolAdapter` (`side_effect="active_probe"`) so concurrency limits and rate limits are enforced by the **Policy Engine**, not just a CLI flag.
- Target throughput: thousands of param-probes per minute on a normal connection (vs. low hundreds with 5 threads).

**Files touched:**
- `src/xscan/tools/adapters/http_probe.py` (new or extended)
- `src/xscan/nodes/analysis/reflection.py` (if exists, adapt to async)
- `src/xscan/nodes/analysis/candidate_gen.py` (integrate async client)
- `src/xscan/validation/iterative.py` (async-aware validation loop)
- `tests/integration/` (add throughput benchmarks)

**Exit criteria:**
- All Phases 1–12 tests still pass
- Async client initialized and pooled correctly
- Concurrency semaphore per-host working
- Throughput benchmark shows 3–5x improvement over sync baseline

---

### Phase 13B — Deduplicate before you probe

**Goal:** Build a **URL template signature** system; probe **one representative per signature** first.

**Approach:**
1. Normalize URL path + sorted param names (ignore values). E.g., `/product?id=1&cat=shoes` → signature `product|cat|id`.
2. Group input URLs by signature.
3. Probe **one representative** from each group first. Record the reflection context and encoding profile.
4. Only expand to **sibling URLs** in the same group if the representative came back as a candidate — to confirm it's not route-specific (some backends validate `id` differently per endpoint).
5. If a sibling has different reflection behavior, promote it to a standalone candidate (rare).

**Files touched:**
- `src/xscan/nodes/analysis/reflection.py` (new or extended) — implement `URLTemplateSignature` and `URLDeduplicator`
- `src/xscan/nodes/analysis/candidate_gen.py` — integrate dedup before probing
- `src/xscan/schemas/xss.py` — add `Candidate.template_signature` field
- `tests/unit/analysis/test_dedup.py` (new) — test signature grouping and sibling expansion

**Exit criteria:**
- All Phases 1–12 tests still pass
- Dedup system groups structurally identical URLs
- Sibling expansion works for representative-as-candidate cases
- Integration test with 1k URLs shows 80–90% request reduction without FN on known sinks
- `test_dedup.py` covers edge cases (path with query params, sorted param names, resource IDs)

---

### Phase 13C — Tiered escalation: cheap first, expensive only on high confidence

**Goal:** Reserve the expensive Bounded Validation node for high-confidence candidates only.

**Tiers:**
```
Tier 1: HTTP reflection probe      [cheap, async, no browser]
        ↓ produces Context + Encoding Profile
        
Tier 2: Context classification    [free, deterministic from Tier 1 response]
        + Confidence scoring       [low|medium|high based on context]
        ↓ produces Confidence label
        
Tier 3: Browser-based Bounded     [expensive, Playwright/Chromium]
Validation                         ONLY if confidence == "high"
        
Logged for human review: medium/low candidates (not auto-escalated)
```

**Scope:**
- Add `confidence` field to `Candidate` (already exists, but not used for gating).
- Update `EvidenceFusionNode` to compute `confidence` deterministically (no LLM needed).
- Modify the DAG **execution engine** to conditionally skip `BoundedValidationNode` when `confidence < "high"`.
- Medium/low candidates logged with notes for triage (export in `candidates.json`, not filtered out).

**Files touched:**
- `src/xscan/schemas/xss.py` — ensure `Candidate.confidence` is used consistently
- `src/xscan/nodes/xss/fusion.py` — compute `confidence` deterministically
- `src/xscan/core/dag/execution.py` — conditional node execution based on `confidence`
- `src/xscan/validation/bounded_validation.py` (or equiv.) — gate on `confidence == "high"`
- `tests/unit/nodes/test_fusion.py` (extended) — test confidence scoring

**Exit criteria:**
- All Phases 1–12 tests still pass
- Confidence computed correctly for all contexts (no LLM calls needed)
- Bounded Validation node skipped for medium/low-confidence candidates
- Integration test shows 50–70% fewer browser sessions vs. baseline (most candidates are medium/low)
- Medium/low candidates still appear in output (not silently dropped)

---

### Phase 13D — Streaming + resumable output

**Goal:** Don't buffer everything in memory; write results incrementally; support resumption.

**Scope:**
- Write candidates as **JSON Lines** (`.jsonl`), one per line, flushed immediately — no buffering.
- Add a `--checkpoint` file tracking which URL signatures have been probed, so a re-run **resumes** instead of restarting.
- Integrate with the DAG engine's existing `checkpoint.py` / `resume` machinery — don't build a second checkpoint system.
- Final step converts `.jsonl` into the summary `candidates.json` your reporting node expects.

**Files touched:**
- `src/xscan/core/dag/checkpoint.py` (extended) — track probed URL signatures
- `src/xscan/nodes/analysis/candidate_gen.py` — output `.jsonl` instead of buffering
- `src/xscan/nodes/xss/fusion.py` (extended) — read `.jsonl`, merge, write summary JSON
- `tests/integration/test_resumption.py` (new) — verify checkpoint + resume works

**Exit criteria:**
- All Phases 1–12 tests still pass
- Candidates written to `.jsonl` incrementally (no memory buffering)
- `--checkpoint` file tracks probed signatures correctly
- Resume works: kill the scan halfway, re-run with `--resume`, picks up where it left off
- Integration test: probe 1k URLs, kill at 500, resume, confirm only 500 new requests

---

### Phase 13E — CLI clarity & verbosity

**Goal:** One binary, clear verbs, not a pile of flags.

**New commands:**
```bash
xscan probe --list alive.txt --scope scope.yaml --out candidates.jsonl
xscan probe --resume candidates.jsonl              # continues interrupted run
xscan probe --list alive.txt --dedupe-only-report  # shows what WOULD be probed, no requests
```

**Flags:**
- `--concurrency N` (default 100) — per-host connection limit
- `--timeout S` (default 10) — per-request timeout
- `--fail-on-confidence LEVEL` (default "high") — exit 1 if any candidate at or above this level; useful for CI gating
- `-q` — quiet (errors only)
- `-v` — verbose (per-param detail)
- Default — one line per URL

**Files touched:**
- `src/xscan/cli/commands/probe.py` (new or extended)
- `src/xscan/cli/main.py` (routing)
- `tests/integration/test_cli.py` (extended)

**Exit criteria:**
- All three commands work end-to-end
- `--dedupe-only-report` is cheap (< 1s for 10k URLs)
- Exit codes: 0 (complete), 1 (findings above `--fail-on-confidence`), 2 (run error)
- Help text is clear and concise

---

### Phase 13F — Integration back into DAG

**Goal:** Wire the standalone async tool back into the XScan DAG architecture.

**Scope:**
- Tier 1+2 logic → `nodes/analysis/reflection.py`, with dedup as explicit pre-filter node
- Async HTTP client → a `ToolAdapter` (`side_effect="active_probe"`) enforcing **Policy Engine** rate limits
- Tier 3 escalation → gate `BoundedValidationNode` invocation on `confidence == "high"`
- Update workflow YAML to include the new nodes

**Files touched:**
- `src/xscan/nodes/analysis/reflection.py` (new or extended)
- `src/xscan/tools/adapters/http_probe.py` (new or extended)
- `src/xscan/workflows/definitions/xss-async.yaml` (new)
- Integration tests

**Exit criteria:**
- All Phases 1–12 tests still pass
- Async reflection node works in DAG execution
- Policy engine rate limits are respected
- Bounded Validation gating works

---

### Phase 13G — Benchmark before shipping

**Goal:** Prove the efficiency gains are real.

**Benchmarks:**
1. **Throughput:** Sync baseline (5 threads) vs. async (concurrency 100) on a fixture app with 1k URLs.
   - Expected: 3–5x improvement.
2. **Dedup effectiveness:** URLs with/without dedup on 500 identical endpoints with varying IDs.
   - Expected: 80–90% request reduction.
3. **Tiering reduction:** All candidates vs. only high-confidence sent to Bounded Validation.
   - Expected: 50–70% fewer browser sessions.
4. **Memory footprint:** Long run (10k URLs) with streaming `.jsonl` vs. buffering everything.
   - Expected: constant memory, no growth over time.
5. **False negatives:** Dedup + tiering on known vulnerable paths.
   - Expected: 0 FN (no regressions in detection rate).

**Files touched:**
- `tests/integration/benchmarks/` (new directory)
- `tests/integration/benchmarks/fixture_app.py` — serves known-vulnerable and known-safe endpoints
- `tests/integration/benchmarks/benchmark_async_vs_sync.py`
- `tests/integration/benchmarks/benchmark_dedup.py`
- `tests/integration/benchmarks/benchmark_tiering.py`
- `tests/integration/benchmarks/benchmark_memory.py`
- Report: `PHASE_13_BENCHMARK_RESULTS.md`

**Exit criteria:**
- All benchmarks complete and documented
- Speed, memory, and accuracy targets met
- No regressions vs. Phases 1–12

---

## Work order (recommended)

1. **Phase 13A** (async I/O) — foundation; everything else depends on it
2. **Phase 13B** (dedup) — compounds with async; highest request reduction
3. **Phase 13C** (tiering) — reduces expensive validation burden
4. **Phase 13D** (streaming + resume) — robustness at scale
5. **Phase 13E** (CLI) — UX refinement
6. **Phase 13F** (DAG integration) — make it official
7. **Phase 13G** (benchmarks) — prove it works

## Estimated effort

- Phase 13A: 3–5 days (async patterns, concurrency semantics)
- Phase 13B: 2–3 days (URL signature logic, dedup grouping)
- Phase 13C: 1–2 days (confidence scoring, gating)
- Phase 13D: 2–3 days (checkpoint design, JSON Lines I/O)
- Phase 13E: 1–2 days (CLI wiring)
- Phase 13F: 2–3 days (DAG node integration)
- Phase 13G: 3–4 days (fixture app, benchmark scripts, analysis)

**Total: ~3–4 weeks of focused work** if executed sequentially. Can be parallelized (e.g., 13D–E while 13A is in test). Recommend starting Phase 13A after a 1-week user feedback cycle on Phases 1–12 to lock in API stability.

---

## Definition of done

All phases complete when:
- ✅ All Phases 1–12 tests still pass
- ✅ Phase 13 unit tests added for each new/modified module
- ✅ Phase 13G benchmarks show 3–5x throughput, 80–90% request reduction, 0 FN
- ✅ `ruff check`, `mypy src/xscan` clean
- ✅ `PHASE_13_BENCHMARK_RESULTS.md` documents results vs. targets
- ✅ One commit per sub-phase (13A, 13B, ..., 13G)
- ✅ ARCHITECTURE.md updated to mark Phase 13 complete and async-first

