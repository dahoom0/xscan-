# Concept: Research

The Research node allows LLM specialists to retrieve **external technical
context** during a scan when local knowledge is insufficient.

---

## What research does

- Fetches CVE data, framework documentation, and security advisories
- Summarises results and injects them into specialist context
- Caches all results locally (configurable TTL)
- Every fetch is logged and auditable

---

## What research does NOT do

- Give the LLM unrestricted internet browsing
- Fetch arbitrary user-supplied URLs
- Bypass scope policy (domain allow-list applies)
- Store any user data externally

---

## Enable research in a scan

```bash
xscan scan example.com --research
xscan scan example.com --workflow xss-deep --research
```

## Standalone research

```bash
xscan research "React dangerouslySetInnerHTML XSS"
xscan research "CVE-2024-12345"
xscan research "GraphQL batching attacks"
```

---

## Configuration

```toml
[research]
enabled   = true
providers = ["brave", "duckduckgo"]
cache_ttl = 86400        # seconds
max_depth = 2            # follow at most 2 links per query
```

---

## Cache

Research results are cached in `~/.xscan/research-cache/`.

```bash
xscan research cache list
xscan research cache clear
```

---

## Related topics

- `xscan help concepts/llm`
- `xscan help models`
- `xscan help commands/research`
