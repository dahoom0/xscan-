---
tags: csp, content-security-policy, bypass, advanced, tier3
category: advanced
---

# Content Security Policy (CSP) Analysis and Bypass

## What CSP does

CSP blocks XSS execution by whitelisting allowed script sources.

```
Content-Security-Policy: script-src 'self'
```

This blocks:
- Inline `<script>alert(1)</script>` NO
- `onerror=alert(1)` event handlers NO
- `eval()` NO
- External scripts not on the whitelist NO

## CSP weakness patterns

### 1. Wildcard in allowed domain

```
script-src *.trusted.com
```

If attacker can upload to any trusted.com subdomain -> bypass.
Or if `cdn.trusted.com/user-uploads/` exists -> upload JS file.

### 2. Unsafe-inline allowed

```
script-src 'self' 'unsafe-inline'
```

Completely bypasses CSP -> standard XSS payloads work.

### 3. Unsafe-eval allowed

```
script-src 'self' 'unsafe-eval'
```

`eval()`, `setTimeout(string)`, `Function()` still work.

### 4. JSONP endpoint on whitelisted domain

```
script-src https://accounts.google.com
```

If `https://accounts.google.com/o/oauth2/revoke?token=alert(1)` is a JSONP endpoint:
```html
<script src="https://accounts.google.com/o/oauth2/revoke?token=alert(1)"></script>
```

### 5. Angular + whitelisted CDN

```
script-src cdn.jsdelivr.net
```

Load AngularJS from CDN -> use template injection to bypass.

### 6. Nonce misuse

```
Content-Security-Policy: script-src 'nonce-abc123'
```

If nonce is predictable or leaked in HTML -> can add nonce to injected script.

## Scanner checks for CSP

1. Read `Content-Security-Policy` response header
2. Parse directives: `script-src`, `default-src`, `object-src`
3. Check for `unsafe-inline`, `unsafe-eval`, wildcards
4. If strict CSP: check whitelisted domains for JSONP endpoints
5. Check if AngularJS loaded from CDN (template injection bypass)
6. Report CSP strength: strong / weak / bypassed

## Impact on XSS findings

| CSP State | XSS Exploitability |
|-----------|-------------------|
| No CSP | Full — all payloads work |
| `unsafe-inline` | Full — inline payloads work |
| `unsafe-eval` | Partial — eval/setTimeout payloads work |
| Strict with nonce | Low — requires nonce leak |
| Strict with JSONP bypass | Medium — domain-specific |
| Strict, no bypass found | Detected but not confirmed exploitable |

