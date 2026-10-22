---
tags: xss, dom, javascript, dom-xss, sink, source
category: xss
---

# XSS: DOM-Based Injection

## What DOM XSS is

The vulnerability is in client-side JavaScript, not the server response.
The server never reflects the input — the page's own JS reads it and
writes it to the DOM unsafely.

## Common sources (where attacker input enters)

- `location.href`, `location.search`, `location.hash`
- `document.URL`, `document.referrer`
- `window.name`, `postMessage` data
- `URLSearchParams.get()`
- Cookie values, localStorage, sessionStorage

## Dangerous sinks (where input causes execution)

| Sink | Risk |
|---|---|
| `innerHTML`, `outerHTML` | Critical — direct HTML injection |
| `document.write()`, `document.writeln()` | Critical |
| `eval()`, `Function()`, `setTimeout(str)` | Critical — JS execution |
| `element.src`, `element.href` with `javascript:` | High |
| `location.assign()`, `location.replace()` | Medium — open redirect -> XSS |
| `$.html()`, `$(str)` in jQuery | High — jQuery HTML injection |

## Detection signals

- `URLSearchParams.get()` result flows to `innerHTML` or similar
- No server-side reflection but JS reads from URL/hash
- `location.hash` used to set content without encoding

## jQuery-specific patterns

```javascript
// Dangerous
$(location.hash)          // jQuery parses as HTML if starts with <
$('#el').html(userInput)  // direct innerHTML
$.parseHTML(userInput)    // parsed as HTML
```

