# XScan DOM-XSS Detection: Root Cause Analysis & Fix Plan

## Executive Summary

The scan produced **zero DOM-XSS candidates** despite discovering 7 pages and 3 JavaScript files because:

1. **Static analysis is too restrictive**: Requires source AND sink on same line or within 8-line context
2. **No runtime observation**: Cannot see how JavaScript actually executes or modifies the DOM
3. **Framework filtering is overly aggressive**: May exclude legitimate application code
4. **Parameter names not resolved**: Crawler may not discover parameterized URLs, or URLSearchParams calls are not recognized
5. **No browser-based verification**: DOM mutations and actual execution are never observed

## Root Cause Breakdown

### Issue 1: Static Source-Sink Proximity Requirement
**File**: `src/xscan/nodes/analysis/dom_xss.py`, lines 706-730  
**Problem**: Source and sink must be within 8-line context window  
**Impact**: If JavaScript has `location.search` at line 10 and `innerHTML` at line 20, no candidate generated

### Issue 2: Limited Data-Flow Analysis  
**File**: `src/xscan/nodes/analysis/js_ast.py`  
**Problem**: Regex-based heuristic parsing, no real AST traversal or variable tracking  
**Impact**: Cannot follow assignments, function parameters, or object properties

### Issue 3: Vendor Code Overly Filtered
**File**: `src/xscan/nodes/analysis/dom_xss.py`, lines 129-133, 624-625  
**Problem**: Framework detection too broad (URL patterns, content markers)  
**Impact**: May exclude application-specific code that happens to use framework libraries

### Issue 4: Taint Graph Builder Not Invoked
**File**: `src/xscan/nodes/dom/taint_builder.py`  
**Problem**: Node exists but not in xss-balanced.yaml workflow  
**Impact**: No comprehensive source-to-sink data-flow tracking

### Issue 5: No Browser-Based Evidence Collection
**File**: No current implementation  
**Problem**: Scanner cannot observe runtime DOM mutations, browser execution  
**Impact**: Cannot verify actual behavior; static analysis gaps go undetected

## Implementation Plan

### Phase 1: Diagnostics & Logging (THIS PHASE)
- [ ] Add comprehensive logging to identify exact breakpoint
- [ ] Instrument candidate generation with detailed metrics
- [ ] Trace why zero candidates despite JS discovery
- [ ] Create diagnostic output showing what was analyzed and why discarded

### Phase 2: Improve Static Analysis
- [ ] Extend source definition registry (runtime sources, aliases, properties)
- [ ] Expand sink registry (library-specific methods, framework APIs)
- [ ] Increase data-flow proximity window or implement variable tracking
- [ ] Preserve uncertain flows instead of silently discarding

### Phase 3: Browser-Based Analysis
- [ ] Load target in Playwright with instrumentation
- [ ] Observe DOM mutations and JavaScript execution
- [ ] Correlate input markers with DOM changes
- [ ] Collect runtime evidence of source-to-sink flows

### Phase 4: Evidence-Driven Candidate Generation
- [ ] Generate candidates from observed runtime behavior
- [ ] Combine static + dynamic evidence
- [ ] Use browser observations to refine constraints
- [ ] Generate context-appropriate test payloads

### Phase 5: Integration & Testing
- [ ] Wire into existing candidate-gen pipeline
- [ ] Add regression tests for DOM-XSS patterns
- [ ] Test with PortSwigger Academy lab
- [ ] Verify no regression in reflected/stored XSS detection

## Starting Point

Begin with Phase 1: Add diagnostics to understand exactly where analysis breaks down on the test target.
