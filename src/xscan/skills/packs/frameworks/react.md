---
tags: react, javascript, dom, xss, framework
category: framework
---

# Framework: React XSS Patterns

## Safe by default — but these are dangerous

```jsx
// DANGEROUS — bypasses React's escaping
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// DANGEROUS — href with user input (javascript: scheme)
<a href={userInput}>click</a>

// DANGEROUS — dynamic component creation
React.createElement('div', { dangerouslySetInnerHTML: { __html: data } })
```

## Detection signals

- `dangerouslySetInnerHTML` present in source
- Unvalidated URL props passed to `href`, `src`, `action`
- Server-side rendered (SSR) data injected into React state without encoding

## Low risk patterns (React encodes these automatically)

```jsx
<div>{userInput}</div>           // safe — React encodes
<input value={userInput} />      // safe
```

## Key rule

React XSS almost always involves `dangerouslySetInnerHTML` or
unvalidated URLs. Pure content injection in JSX expressions is safe.

