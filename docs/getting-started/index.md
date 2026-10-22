# Getting Started with XScan

XScan is a local AI-powered security automation platform. It runs entirely
on your machine — no cloud accounts required.

---

## Requirements

| Requirement  | Version  | Notes                                |
|--------------|----------|--------------------------------------|
| Python       | 3.11+    |                                      |
| Ollama       | 0.3+     | For local LLMs                       |
| Qwen3        | latest   | `ollama pull qwen3`                  |
| Playwright   | latest   | `pip install playwright && playwright install` |
| Go tools     | latest   | katana, httpx, dnsx (auto-installed) |

---

## Install XScan

```bash
pip install xscan
```

Or from source:

```bash
git clone https://github.com/xscan/xscan
cd xscan
pip install -e ".[dev]"
```

---

## Install Ollama and pull a model

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3

# Windows
# Download from https://ollama.com and run the installer, then:
ollama pull qwen3
```

---

## Check your environment

```bash
xscan doctor
```

Any problems are reported with suggested fixes. Run `xscan doctor --fix` to
attempt automatic repair.

---

## Your first scan

```bash
xscan scan target.example.com
```

Add `--profile deep` for thorough analysis:

```bash
xscan scan target.example.com --profile deep
```

Use natural language via smart mode:

```bash
xscan smart "analyse client-side XSS on target.example.com" --confirm
```

---

## Set authorised scope

**Always** configure scope before scanning:

```bash
xscan scope set target.example.com
xscan scope add "*.target.example.com"
```

XScan enforces scope at every stage — requests outside your authorised scope
are blocked and logged.

---

## Next steps

| Topic                          | Command                              |
|--------------------------------|--------------------------------------|
| Learn the platform             | `xscan help architecture`            |
| Configure a deep workflow      | `xscan help workflows`               |
| Add security tools             | `xscan tools install katana httpx`   |
| Set up authentication          | `xscan help authentication`          |
| Install a Skill                | `xscan skills install react-security`|
| Understand LLM specialists     | `xscan help concepts/specialists`    |
| Troubleshoot                   | `xscan help troubleshooting`         |
