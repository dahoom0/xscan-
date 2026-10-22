# Concept: Evidence

XScan does not report a finding without **captured evidence**. The evidence
graph links every finding to the raw data that confirms it.

---

## Evidence types

| Type           | Description                                       |
|----------------|---------------------------------------------------|
| `http-request` | Captured HTTP request that triggered behaviour    |
| `http-response`| Captured HTTP response                            |
| `screenshot`   | Browser screenshot of rendered payload            |
| `dom-snapshot` | Full DOM state at time of execution               |
| `console-log`  | Browser console output during execution           |
| `network-log`  | Network traffic captured during test              |
| `diff`         | Before/after DOM or response comparison           |
| `ast-node`     | JavaScript AST node linked to sink                |

---

## Evidence graph

```
Finding
  └── Evidence node (type: screenshot)
        └── Source: browser session #4, timestamp, url
  └── Evidence node (type: http-request)
        └── Source: proxy capture, raw bytes
  └── Evidence node (type: console-log)
        └── Source: playwright, execution context
```

All nodes are stored in the evidence graph and linked to their scan.

---

## Evidence commands

```bash
# View findings with evidence links
xscan report show <scan-id>

# Inspect a specific finding's evidence
xscan report show <scan-id> --finding <id>

# Export full evidence bundle (zip)
xscan evidence export <scan-id>

# Replay a finding's execution
xscan evidence replay <scan-id> <finding-id>
```

---

## Related topics

- `xscan help reports`
- `xscan help concepts/dag`
- `xscan help concepts/scope`
