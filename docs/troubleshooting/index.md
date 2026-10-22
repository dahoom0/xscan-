# Troubleshooting

---

## Quick diagnostics

```bash
xscan doctor             # Full environment check
xscan doctor --fix       # Auto-repair common issues
xscan tools check --all  # Check all tools
xscan models test        # Test active LLM
xscan config show        # Show current config
```

---

## Common problems

### Ollama not responding

```
Error: LLM request failed — connection refused (localhost:11434)
```

**Fixes:**

```bash
ollama serve                   # Start Ollama
xscan doctor --fix             # XScan auto-fix
xscan models test              # Confirm after fixing
```

---

### Playwright browser missing

```
Error: Browser executable not found
```

**Fixes:**

```bash
playwright install chromium
xscan tools install playwright
xscan doctor --fix
```

---

### Tool not found

```
Error: katana not found in PATH or ~/.xscan/bin
```

**Fixes:**

```bash
xscan tools install katana
xscan tools check katana
```

---

### WSL2 unavailable (Windows)

Some tools require WSL2 on Windows.

**Fixes:**

1. Open PowerShell as Administrator
2. Run: `wsl --install`
3. Restart your machine
4. Re-run: `xscan doctor`

---

### Database migration failed

```
Error: database schema out of date
```

**Fixes:**

```bash
xscan fix "database migration"
```

If that fails:

```bash
# Backup first
cp ~/.xscan/xscan.db ~/.xscan/xscan.db.bak
xscan db migrate --force
```

---

### Scope rejected

```
Error: target not in authorised scope
```

**Fixes:**

```bash
xscan scope show
xscan scope add example.com
xscan scope add "*.example.com"
```

---

### Authentication expired

```
Error: session 'my-session' is expired or invalid
```

**Fixes:**

```bash
xscan auth refresh my-session
xscan auth login --url https://example.com/login --session my-session
```

---

### Model unavailable

```
Error: model 'qwen3' not found in Ollama
```

**Fixes:**

```bash
ollama pull qwen3
xscan models list
xscan models use qwen3
```

---

### Research provider unavailable

```
Error: research provider 'brave' returned 429
```

**Fixes:**

```bash
# Switch to duckduckgo (no key required)
xscan config set research.providers '["duckduckgo"]'

# Or check your API key
xscan config show research
```

---

## Log files

```bash
# View recent logs
xscan status --logs

# Log directory
ls ~/.xscan/logs/
```

---

## Related topics

- `xscan help doctor`
- `xscan help tools`
- `xscan help models`
- `xscan help authentication`
