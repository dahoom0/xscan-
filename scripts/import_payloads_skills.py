"""
Import PayloadsAllTheThings XSS files as XScan skill packs.
Adds frontmatter with tags so the SkillManager selects them correctly.
Run: python scripts/import_payloads_skills.py
"""
from pathlib import Path

SRC  = Path.home() / ".xscan" / "tools" / "PayloadsAllTheThings" / "XSS Injection"
DEST = Path(__file__).parent.parent / "src" / "xscan" / "skills" / "packs" / "payloadsallthethings"
DEST.mkdir(parents=True, exist_ok=True)

SKILLS = [
    {
        "src":  "README.md",
        "dest": "xss-overview.md",
        "frontmatter": """\
---
tags: xss, reflected, stored, dom, html-text, html-attribute, javascript, payloads, common, html5, tier1
category: xss
source: PayloadsAllTheThings
---
""",
    },
    {
        "src":  "1 - XSS Filter Bypass.md",
        "dest": "xss-filter-bypass.md",
        "frontmatter": """\
---
tags: xss, filter-bypass, bypass, encoding, obfuscation, waf, blacklist, case-sensitive, tier2
category: xss
source: PayloadsAllTheThings
---
""",
    },
    {
        "src":  "2 - XSS Polyglot.md",
        "dest": "xss-polyglot.md",
        "frontmatter": """\
---
tags: xss, polyglot, multi-context, universal, bypass, tier2
category: xss
source: PayloadsAllTheThings
---
""",
    },
    {
        "src":  "3 - XSS Common WAF Bypass.md",
        "dest": "xss-waf-bypass.md",
        "frontmatter": """\
---
tags: xss, waf, waf-bypass, cloudflare, akamai, bypass, obfuscation, tier3
category: advanced
source: PayloadsAllTheThings
---
""",
    },
    {
        "src":  "4 - CSP Bypass.md",
        "dest": "xss-csp-bypass.md",
        "frontmatter": """\
---
tags: xss, csp, csp-bypass, content-security-policy, jsonp, nonce, unsafe-inline, tier3
category: advanced
source: PayloadsAllTheThings
---
""",
    },
    {
        "src":  "5 - XSS in Angular.md",
        "dest": "xss-angularjs.md",
        "frontmatter": """\
---
tags: xss, angularjs, angular, template-injection, sandbox-bypass, ng-app, tier3
category: framework
source: PayloadsAllTheThings
---
""",
    },
]

imported = 0
for skill in SKILLS:
    src_path  = SRC  / skill["src"]
    dest_path = DEST / skill["dest"]

    if not src_path.exists():
        print(f"  SKIP (not found): {skill['src']}")
        continue

    content = src_path.read_text(encoding="utf-8", errors="replace")

    # Strip any existing frontmatter
    if content.startswith("---"):
        end = content.find("---", 3)
        if end != -1:
            content = content[end + 3:].lstrip()

    dest_path.write_text(
        skill["frontmatter"] + "\n" + content,
        encoding="utf-8",
    )
    print(f"  OK  {skill['dest']}  ({len(content):,} chars)")
    imported += 1

print(f"\nImported {imported}/{len(SKILLS)} skills to {DEST}")
