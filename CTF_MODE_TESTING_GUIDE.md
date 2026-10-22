# CTF Mode Testing Guide

## What Was Built

XScan now has **CTF-Mode**: a specialized validation pipeline that:
1. Detects if target is a CTF challenge
2. Generates custom XSS payloads tailored to that target's encoding profile
3. Tests payloads immediately
4. Confirms vulnerabilities automatically

## Testing Locally

### Test 1: Verify Components Load

```bash
# From workspace root
python -c "
from src.xscan.llm.specialists.ctf_payload_generator import CTFPayloadGeneratorSpecialist
from src.xscan.nodes.validation.ctf_validate import CtfValidateNode
from src.xscan.nodes.validation.xss_validate import XssValidatorNode

print('✓ All CTF components loaded')
print('  - CTFPayloadGeneratorSpecialist')
print('  - CtfValidateNode')
print('  - XssValidatorNode (with CTF detection)')
"
```

### Test 2: Run the Demo

```bash
# From workspace root
python test_ctf_demo.py
```

**Output shows:**
- CTF specialist configuration for shop.post.ch scenario
- Encoding profile analysis
- Comparison: generic vs CTF mode
- Expected payloads

### Test 3: Verify Integration

```bash
# Check xss-validate includes CTF detection
python -c "
import inspect
from src.xscan.nodes.validation.xss_validate import XssValidatorNode

source = inspect.getsource(XssValidatorNode.execute)
if 'detect_ctf_context' in source and 'CtfValidateNode' in source:
    print('✓ CTF detection integrated into xss-validate')
    print('  Automatically delegates to CTF mode when target is detected as CTF')
else:
    print('✗ Integration missing')
"
```

---

## Testing on Real Targets

### Option 1: Local CTF Lab (Recommended)

Set up a vulnerable target locally:

```bash
# Example: DVWA (Damn Vulnerable Web Application)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Then scan it
xscan scan http://localhost/DVWA/vulnerabilities/xss_r/?name=test --profile xss-balanced
```

XScan will:
1. Detect DVWA (known vulnerable app)
2. Activate CTF mode
3. Generate custom payloads for DVWA's specific filters
4. Test and confirm them

### Option 2: HackTheBox CTF

```bash
# Scan a HackTheBox machine (10.10.x.x range)
xscan scan http://10.10.11.xxx/vulnerable-endpoint --profile xss-balanced

# Scanner detects CTF IP range and activates CTF mode
```

### Option 3: Custom Vulnerable App

Create a test app with a specific XSS vulnerability:

```html
<!-- test-xss.html -->
<form method="GET">
    <input name="search" placeholder="Search...">
</form>
<script>
    const params = new URLSearchParams(location.search);
    const search = params.get('search');
    // Filtered but not perfectly
    const filtered = search
        .replace(/</g, '')
        .replace(/>/g, '')
        .replace(/"/g, '');
    eval('var result = "' + filtered + '";');
    document.write('Results for: ' + result);
</script>
```

**Filter Profile:**
- Blocks: `<`, `>`, `"`
- Allows: `;`, `(`, `)`, `/`, `=`, letters, numbers

**What XScan CTF Mode Will Do:**

1. Analyze filter: `< > "` blocked, `;` allowed
2. Generate: `;alert(1)//` (only uses allowed chars)
3. Test: Payload reflects unencoded
4. Confirm: XSS vulnerability found!

---

## Expected Behavior

### When CTF is Detected

```
[INFO] Target detected as CTF challenge
[INFO] Activating CTF-mode validation
[DEBUG] CTFPayloadGeneratorSpecialist generating custom payloads for encoding profile...
[DEBUG] Generated 3 candidates using only available characters
[INFO] Testing candidate 1/3: ;alert(1)//
[SUCCESS] Payload reflected unencoded!
[CONFIRMED] XSS vulnerability confirmed
```

### When CTF is NOT Detected

```
[INFO] Standard XSS validation mode
[DEBUG] Using family-based payload synthesis
[INFO] Testing reflected XSS candidates...
```

---

## Verification Checklist

After implementing CTF mode, verify:

- [ ] Import test passes (components load)
- [ ] Demo runs without errors
- [ ] Integration test passes (xss-validate includes CTF delegation)
- [ ] Can create CTFPayloadGeneratorInput
- [ ] Can create CtfValidateNode instance
- [ ] XssValidatorNode has CTF detection in execute()

---

## Comparison: Before vs After

### Before CTF Mode

**Problem:**
```
Scanner tries generic payloads:
  Try: ";alert(1)//   ← Quote is encoded, FAILS
  Try: '"/alert(1)    ← Angle brackets blocked, FAILS
  Try: \x22alert(1)   ← Complex escapes, FAILS
Result: No confirmation (budget exhausted)
```

**Why it fails:**
- Generic families don't know THIS target's filter
- Payloads use characters that don't survive

### After CTF Mode

**Solution:**
```
Scanner analyzes THIS target:
  Filter analysis: ; ( ) allowed, < > " blocked
  Context: JavaScript string
  Strategy: Statement chaining
  Generated: ;alert(1)//   ← ONLY uses allowed chars, SUCCEEDS!
Result: Vulnerability CONFIRMED
```

**Why it works:**
- Custom payloads use only available characters
- Techniques tailored to target's constraints
- Higher success rate

---

## Troubleshooting

### If CTF Mode Doesn't Activate

Check CTF detection:
```python
from xscan.validation.ctf_detection import detect_ctf_context

# Test detection
result = detect_ctf_context("http://10.10.11.100/", ["php", "apache"])
print(f"Is CTF: {result.is_ctf}")
print(f"Platform: {result.platform}")
print(f"Confidence: {result.confidence}")
```

### If Specialist Fails

Check LLM connection:
```python
from xscan.llm.specialists.ctf_payload_generator import CTFPayloadGeneratorSpecialist

specialist = CTFPayloadGeneratorSpecialist()
# This will attempt LLM connection; check error message
```

### If Payloads Don't Confirm

- Verify encoding profile is correct
- Check that raw_chars are actually unencoded
- Look at HTTP responses to see what characters survived
- Update strip_chars/encoded_chars and retry

---

## Next: Run a Full Scan

Once verified, run a full XSS scan with CTF mode active:

```bash
# Profile: balanced (recommended for testing)
xscan scan http://target.com --profile xss-balanced

# For aggressive CTF testing:
# Edit config to use xss-deep profile (more iterations)
xscan scan http://target.com --profile xss-deep
```

XScan will:
1. Detect if target is CTF
2. If yes → Use CTF mode (LLM-driven custom payloads)
3. If no → Use standard validation
4. Report findings with full evidence

---

## Success Criteria

CTF mode is working correctly when:

✅ Custom payloads are generated for the target's encoding profile
✅ Payloads use ONLY characters from raw_chars
✅ Payloads are tested immediately after generation
✅ Confirmation happens when payload reflects unencoded
✅ Reports show findings with target-specific evidence

---

## Need Help?

- Check `test_ctf_demo.py` for example usage
- Read `CTFPayloadGeneratorSpecialist` docstrings
- Review `CtfValidateNode` implementation
- Check test files in `tests/unit/llm/` and `tests/integration/`

---

## Summary

You now have a scanner that:
- Detects CTF targets automatically
- Generates custom payloads for each target's specific filter profile
- Tests payloads immediately
- Confirms vulnerabilities with high success rate
- Works seamlessly with existing workflow

No configuration needed. Just scan normally.
