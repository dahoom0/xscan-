# xscan smart

Convert natural-language intent into an approved XScan workflow.

---

## Usage

```
xscan smart INTENT [OPTIONS]
```

---

## Arguments

**INTENT**
A natural-language description of what you want to do.

---

## Options

| Option       | Description                                                |
|--------------|------------------------------------------------------------|
| `--plan`     | Show proposed workflow only — do not execute               |
| `--confirm`  | Show workflow and ask for confirmation before execution    |
| `--auto`     | Execute only workflows permitted by policy (default)       |
| `--scope TEXT`| Scope override                                            |
| `--auth TEXT` | Authentication session                                    |

---

## Important

Smart mode does **NOT** give the LLM unrestricted shell access.

```
Intent
  ↓
Intent Specialist (parse & classify)
  ↓
Capability resolution
  ↓
Select or compose existing workflow
  ↓
Policy check
  ↓
Deterministic DAG execution
```

---

## Examples

```bash
xscan smart "analyse client-side XSS on example.com"
xscan smart "deep recon of example.com" --plan
xscan smart "find all XSS sinks in the login flow" --confirm
xscan smart "crawl and fingerprint all JS libraries" --confirm
xscan smart "full audit of api.example.com" --auto
```

---

## Related topics

- `xscan help workflows`
- `xscan help concepts/dag`
- `xscan help concepts/specialists`
