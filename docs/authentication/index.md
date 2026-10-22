# Authentication

XScan can authenticate to web applications before scanning so that
authenticated endpoints are included in analysis.

---

## Commands

```bash
xscan auth login --url https://example.com/login
xscan auth login --url https://example.com/login --headless
xscan auth login --url https://example.com/login --session my-session
xscan auth list
xscan auth show my-session
xscan auth refresh my-session
xscan auth export my-session --format netscape
xscan auth delete my-session
```

---

## Use a session in a scan

```bash
xscan scan example.com --auth my-session
xscan scan example.com --workflow xss-deep --auth my-session
```

---

## How login works

1. Playwright opens a browser at the login URL
2. In interactive mode: you log in manually in the browser
3. XScan captures the resulting session cookies and storage
4. The session is stored encrypted in `~/.xscan/sessions/`
5. Subsequent scan requests replay the session

In headless mode, provide credentials via environment variables:

```bash
XSCAN_AUTH_USER=user@example.com \
XSCAN_AUTH_PASS=password \
xscan auth login --url https://example.com/login --headless
```

---

## Session storage

Sessions are stored encrypted in `~/.xscan/sessions/`.

The encryption key is derived from your OS keychain where available, or
from a local key file at `~/.xscan/.session-key`.

---

## Export formats

| Format       | Use case                               |
|--------------|----------------------------------------|
| `netscape`   | Import into Burp Suite, curl, etc.     |
| `json`       | Machine-readable cookie dump           |
| `har`        | HTTP Archive with auth headers         |

---

## Troubleshooting

```bash
xscan auth refresh my-session      # Refresh expired session
xscan doctor                       # Check Playwright browser
```

---

## Related topics

- `xscan help scope`
- `xscan help concepts/scope`
- `xscan help commands/auth`
