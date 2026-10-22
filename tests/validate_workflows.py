"""Quick workflow validation check."""
import xscan.nodes.registry  # noqa: F401
from xscan.workflows.loader import WorkflowLoader
from xscan.workflows.validator import WorkflowValidator

loader = WorkflowLoader()
validator = WorkflowValidator(check_registry=True)

for name in ["recon-only", "recon-deep", "xss-balanced", "xss-deep", "xss-fast"]:
    wf = loader.load(name)
    r  = validator.validate(wf)
    status = "OK" if r.valid else "FAIL"
    print(f"  {status}  {name:<16}  {len(wf.nodes)} nodes  {len(r.warnings)} warnings")
    for e in r.errors:
        print(f"    ERROR: {e}")
    for w in r.warnings:
        print(f"    WARN:  {w}")
