# Evidence

XScan captures structured evidence for every finding. Nothing is reported
without evidence that confirms the behaviour.

---

## Commands

```bash
xscan report show <scan-id>
xscan report show <scan-id> --finding <finding-id>
xscan evidence export <scan-id>
xscan evidence export <scan-id> --format zip
xscan evidence replay <scan-id> <finding-id>
```

---

## Evidence types

| Type            | Description                                        |
|-----------------|----------------------------------------------------|
| `http-request`  | Raw HTTP request that triggered the behaviour      |
| `http-response` | Raw HTTP response                                  |
| `screenshot`    | Browser screenshot of rendered payload             |
| `dom-snapshot`  | Full serialised DOM state                          |
| `console-log`   | Browser console output during execution            |
| `network-log`   | HAR-format network log                             |
| `diff`          | Before/after DOM or response comparison            |
| `ast-node`      | JavaScript AST node linked to a sink               |

---

## Evidence graph

Each finding links to a graph of evidence nodes:

```
Finding: XSS in search parameter
  ├── http-request   POST /search?q=<payload>
  ├── http-response  200 OK — body contains unescaped payload
  ├── screenshot     Rendered alert() in browser
  └── console-log    "XSS triggered" in browser console
```

---

## Export

```bash
# Export all evidence for a scan as a zip bundle
xscan evidence export <scan-id>

# Export only a specific finding
xscan evidence export <scan-id> --finding <finding-id>
```

The export includes:
- All evidence files
- Metadata JSON
- Replay instructions

---

## Replay

```bash
xscan evidence replay <scan-id> <finding-id>
```

Replays the validated request in a fresh browser session to confirm
reproducibility.

---

## Related topics

- `xscan help concepts/evidence`
- `xscan help reports`
- `xscan help concepts/dag`
