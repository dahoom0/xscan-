# Concept: Scope

XScan enforces **authorised scope** at every stage of execution. Requests
and actions outside the defined scope are blocked and logged.

---

## Define scope

```bash
xscan scope set example.com
xscan scope add "*.example.com"
xscan scope add "https://example.com/app/*"
xscan scope show
xscan scope clear
```

---

## Scope configuration file

```toml
[scope]
domains = ["example.com", "*.example.com"]
urls    = ["https://example.com/app/*"]
exclude = [
  "https://example.com/logout",
  "https://example.com/admin/*",
]
```

Store named scope profiles:

```bash
xscan scope save --name my-project
xscan scan example.com --scope my-project
```

---

## Scope enforcement chain

```
Tool invocation requested
         ↓
Scope policy check
         ↓
Allowed? → proceed
         ↓
Denied?  → block + audit log
```

This check applies to:
- Web crawler requests
- Browser navigation
- LLM-planned test URLs
- DNS lookups
- Research fetches

---

## Wildcard syntax

| Pattern                        | Matches                                  |
|--------------------------------|------------------------------------------|
| `example.com`                  | Exact domain                             |
| `*.example.com`                | All subdomains                           |
| `https://example.com/app/*`    | All paths under /app/                    |
| `192.168.1.0/24`               | CIDR range                               |

---

## Related topics

- `xscan help authentication`
- `xscan help concepts/dag`
- `xscan help commands/scan`
