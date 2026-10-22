# Models

XScan uses local LLMs via **Ollama** by default. No cloud API key required.

---

## Commands

```bash
xscan models list           # List available models
xscan models use qwen3      # Set active model
xscan models test           # Test the active model
xscan models test qwen3     # Test a specific model
xscan models info qwen3     # Show model details
```

---

## List output

```
Current model:
  qwen3  ✓

Available local models:
  qwen3            ✓  (active)
  deepseek-coder   ✓
  mistral          ✓
  llama3           ✗  (not pulled)
  phi3             ✗  (not pulled)
```

---

## Pull a model

```bash
ollama pull qwen3
ollama pull deepseek-coder
ollama pull mistral
```

---

## Recommended models

| Model             | Best for                               | Size  |
|-------------------|----------------------------------------|-------|
| `qwen3`           | General analysis (default)             | ~8 GB |
| `deepseek-coder`  | Code and JavaScript analysis           | ~7 GB |
| `mistral`         | Fast triage                            | ~4 GB |
| `llama3`          | Balanced general purpose               | ~8 GB |
| `phi3`            | Lightweight, fast responses            | ~2 GB |

---

## Configuration

`~/.xscan/config.toml`:

```toml
[llm]
model    = "qwen3"
provider = "ollama"
base_url = "http://localhost:11434"
timeout  = 120

[llm.specialists.sink]
model = "deepseek-coder"

[llm.specialists.research]
model = "qwen3"
```

Per-specialist model overrides are supported.

---

## Troubleshooting models

```bash
xscan doctor              # Checks Ollama connectivity
xscan models test         # Tests active model
ollama list               # Direct Ollama model list
ollama serve              # Start Ollama if not running
```

---

## Related topics

- `xscan help concepts/llm`
- `xscan help concepts/specialists`
- `xscan help troubleshooting`
