---
tags: jquery, javascript, dom, xss, framework
category: framework
---

# Framework: jQuery XSS Patterns

## High-risk jQuery sinks

```javascript
$(userInput)              // HTML injection if input starts with <
$el.html(userInput)       // equivalent to innerHTML
$el.append(userInput)     // appends raw HTML
$.parseHTML(userInput)    // returns DOM nodes from HTML string
$el.after(userInput)      // inserts raw HTML
$el.before(userInput)     // inserts raw HTML
$(document).write(str)    // rare but exists
```

## URL-based DOM XSS pattern (very common in labs)

```javascript
// Source: URL parameter
var returnUrl = new URLSearchParams(window.location.search).get('returnPath');
// Sink: href attribute
document.querySelector('a.back').href = returnUrl;
```

This allows `javascript:alert(1)` as the payload since no HTML
encoding is needed — only the `javascript:` scheme prefix.

## Detection checklist

- Page uses jQuery (`$` global, `jquery` in scripts)
- URL parameters flow into `$()`, `.html()`, `.append()`, `.attr('href', ...)`
- Hash value `location.hash` used in jQuery selector
- `$.ajax` callback data written directly to DOM

## Common PortSwigger patterns

- `returnPath` / `returnUrl` parameter -> `href` sink
- Search parameter -> `$('.results').html(data)`
- `location.hash` -> `$(location.hash).show()`

