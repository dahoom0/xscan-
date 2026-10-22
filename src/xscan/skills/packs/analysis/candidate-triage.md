---
tags: triage, analysis, candidate, false-positive, context, encoding
category: analysis
---

# XSS Candidate Triage Guidelines

## The triage question

> Given the reflection context and encoding profile, is this parameter exploitable?

## Decision matrix

| Context | Raw chars needed | Exploitable? | Payload type |
|---------|-----------------|--------------|--------------|
| html_text | `<` | YES | Tag injection |
| html_text | `<` encoded | NO | Not exploitable via tags |
| html_attribute (double) | `"` | YES | Event handler `" onX="` |
| html_attribute (single) | `'` | YES | Event handler `' onX='` |
| html_attribute (unquoted) | ` ` or `>` | YES | Attribute injection |
| script_string_double | `"` | YES | String breakout `"-alert(1)-"` |
| script_string_single | `'` | YES | String breakout `'-alert(1)-'` |
| script_expression | none | YES | Direct injection |
| url_param (href/src) | any | YES | `javascript:alert(1)` |
| html_comment | `-->` | MAYBE | Comment escape |

## Multi-context candidates

When input reflects in MULTIPLE locations, rank by exploitability:

```
html_attribute > script_string > html_text > url_param > html_comment > unknown
```

**Always test the most exploitable context, not just the first.**

## False positive signals

- Input encoded as HTML entities in ALL special chars
- Response is `application/json` not `text/html`
- Input appears inside a `<noscript>` block
- Input inside `<textarea>` (requires `</textarea>` escape)
- All quotes AND angle brackets are encoded

## Confidence levels

| Signal | Confidence |
|--------|-----------|
| Unencoded payload reflects, browser fires event | Confirmed |
| `"` raw in attribute context | High |
| `<` raw in html_text context | High |
| `"` raw in script string | High |
| Canary reflects, `<` encoded | Medium (try attribute/script) |
| Canary reflects but all special chars encoded | Low |

## Key principle

**The LLM's job is to reason about whether exploitation is viable,
not to guess random payloads. Use the encoding profile as evidence.**

If `encoded_chars` contains the breakout character you need -> not viable.
If `raw_chars` contains the breakout character you need -> viable.

