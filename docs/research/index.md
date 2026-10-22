# Research

The Research node lets XScan retrieve external technical context to enrich
LLM specialist analysis.

---

## Commands

```bash
xscan research "<query>"
xscan research "React dangerouslySetInnerHTML XSS"
xscan research "CVE-2024-12345"
xscan research cache list
xscan research cache clear
```

---

## Use in a scan

```bash
xscan scan example.com --research
xscan scan example.com --workflow xss-deep --research --profile deep
```

---

## Configuration

```toml
[research]
enabled   = true
providers = ["brave", "duckduckgo"]
cache_ttl = 86400
max_depth = 2
```

### Providers

| Provider      | Requires            |
|---------------|---------------------|
| `brave`       | BRAVE_API_KEY env   |
| `duckduckgo`  | No key (rate-limited)|
| `local`       | Local docs index    |

Set your API key:

```bash
export BRAVE_API_KEY=your-key-here
```

Or in `~/.xscan/config.toml`:

```toml
[research.providers.brave]
api_key = "your-key-here"
```

---

## Cache

Results are cached in `~/.xscan/research-cache/` with the configured TTL.

```bash
xscan research cache list          # Show cached queries
xscan research cache clear         # Wipe cache
xscan research cache clear --older-than 7d
```

---

## Related topics

- `xscan help concepts/research`
- `xscan help concepts/llm`
- `xscan help models`
