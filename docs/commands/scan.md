# xscan scan

Run a deterministic XScan workflow against an authorised target.

---

## Usage

```
xscan scan TARGET [OPTIONS]
```

---

## Arguments

**TARGET**
Domain, URL, host, or named project target.

---

## Options

| Option            | Description                                              |
|-------------------|----------------------------------------------------------|
| `--workflow TEXT`  | Workflow to execute (default: auto-selected)            |
| `--profile TEXT`   | Execution profile: `fast`, `balanced`, `deep`           |
| `--scope TEXT`     | Scope definition or named scope profile                 |
| `--project TEXT`   | Project context name                                    |
| `--resume`         | Resume an interrupted scan                              |
| `--no-llm`         | Disable LLM specialist nodes                            |
| `--research`       | Allow research nodes when required                      |
| `--tui`            | Launch interactive TUI dashboard                        |
| `--auth TEXT`      | Named authentication session to use                     |
| `--output PATH`    | Write report to file                                    |
| `--format TEXT`    | Report format: `terminal`, `html`, `json`, `markdown`   |

---

## Examples

```bash
xscan scan example.com
xscan scan example.com --profile deep
xscan scan example.com --workflow xss-deep
xscan scan example.com --workflow xss-deep --profile deep --research
xscan scan example.com --auth my-session
xscan scan example.com --resume
xscan scan example.com --no-llm --profile fast
xscan scan example.com --tui
```

---

## Related commands

```bash
xscan workflow list
xscan workflow inspect xss-deep
xscan scope set example.com
xscan resume <scan-id>
xscan status
```

---

## Related topics

- `xscan help workflows`
- `xscan help concepts/dag`
- `xscan help scope`
- `xscan help authentication`
