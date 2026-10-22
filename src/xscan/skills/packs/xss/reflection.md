---
tags: xss, reflection, html-body, html-attribute
category: xss
---

# XSS: Reflected Injection Analysis

## What to look for

A reflected XSS exists when user-supplied input appears unencoded in the response
in a context where it is interpreted as HTML or JavaScript.

## Injection contexts and risk

| Context | Example | Exploitability |
|---|---|---|
| HTML body | `<p>Hello PAYLOAD</p>` | High — direct tag injection |
| HTML attribute | `<input value="PAYLOAD">` | High — break out with `"` |
| HTML attribute (unquoted) | `<input value=PAYLOAD>` | High — no escape needed |
| Script block | `var x = "PAYLOAD";` | High — break string with `'` or `"` |
| URL href/src | `<a href="PAYLOAD">` | Medium — `javascript:` scheme |
| HTML comment | `<!-- PAYLOAD -->` | Low — need `-->` to escape |

## Key signals

- Input appears in response without HTML entity encoding (`&lt;` `&gt;` `&quot;`)
- Response `Content-Type` is `text/html`
- No CSP header preventing inline script execution
- Input appears inside a JavaScript string or expression

## Candidate evaluation

When analysing a candidate, determine:
1. Is the reflection unencoded?
2. What is the exact injection context?
3. Is there a working breakout sequence?
4. Are there any filters or WAF patterns to consider?

