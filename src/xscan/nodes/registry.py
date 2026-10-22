"""
Node registration loader.
Import this module once at startup to register all built-in nodes.
Called by ScanService before executing any workflow.
"""

# Phase 1 nodes — recon, crawl, scope
from xscan.nodes.recon.scope_check          import ScopeCheckNode            # noqa: F401
from xscan.nodes.recon.technology           import TechnologyDetectNode       # noqa: F401
from xscan.nodes.recon.tool_health          import ToolHealthNode             # noqa: F401
from xscan.nodes.recon.subdomain_enum       import SubdomainEnumNode          # noqa: F401
from xscan.nodes.recon.asset_fusion         import AssetFusionNode            # noqa: F401
from xscan.nodes.recon.http_probe           import HttpProbeNode              # noqa: F401
from xscan.nodes.recon.directory_discovery  import DirectoryDiscoveryNode     # noqa: F401
from xscan.nodes.recon.endpoint_inventory   import EndpointInventoryNode      # noqa: F401
from xscan.nodes.recon.screenshot_capture   import ScreenshotCaptureNode      # noqa: F401
from xscan.nodes.recon.nuclei_vuln          import NucleiVulnNode             # noqa: F401
from xscan.nodes.crawler.discover           import CrawlerNode                # noqa: F401

# Phase 2 nodes — JS extraction + AST (xss-deep)
from xscan.nodes.analysis.js_extract import JsExtractorNode         # noqa: F401
from xscan.nodes.analysis.js_ast     import AstParserNode           # noqa: F401

# Phase 3 nodes — DOM analysis + taint graph (xss-deep)
from xscan.nodes.dom.dom_analysis  import DomSourceSinkEventNode    # noqa: F401
from xscan.nodes.dom.taint_builder import TaintGraphBuilderNode     # noqa: F401

# Phase 4 nodes — candidate generation (xss-balanced)
from xscan.nodes.analysis.candidate_gen  import CandidateGeneratorNode   # noqa: F401
from xscan.nodes.analysis.dom_xss        import DomXssDetectorNode        # noqa: F401
from xscan.nodes.analysis.dompurify_scan import DomPurifyScanNode         # noqa: F401
from xscan.nodes.analysis.stored_xss     import StoredXssDetectorNode     # noqa: F401
from xscan.nodes.analysis.tool_scan      import ToolXssScanNode           # noqa: F401

# Phase 5 nodes — evidence fusion + LLM context + test planning
from xscan.nodes.xss.fusion              import EvidenceFusionNode         # noqa: F401
from xscan.nodes.llm.context_specialist  import LLMContextSpecialistNode   # noqa: F401
from xscan.nodes.llm.triage              import LLMCandidateTriageNode      # noqa: F401

# Phase 6 nodes — validation + evidence collection
from xscan.nodes.validation.dom_confirm     import DomConfirmNode           # noqa: F401
from xscan.nodes.validation.xss_validate    import XssValidatorNode        # noqa: F401
from xscan.nodes.xss.evidence_collector     import EvidenceCollectorNode   # noqa: F401

# Legacy alias — kept for xss-fast workflow
from xscan.nodes.analysis.reflection import ReflectionDetectorNode   # noqa: F401

# Report
from xscan.nodes.reporting.report import ReportNode                  # noqa: F401

__all__ = [
    "ScopeCheckNode", "TechnologyDetectNode", "ToolHealthNode", "CrawlerNode",
    "JsExtractorNode", "AstParserNode",
    "DomSourceSinkEventNode", "TaintGraphBuilderNode",
    "CandidateGeneratorNode", "DomXssDetectorNode",
    "StoredXssDetectorNode", "ToolXssScanNode", "DomPurifyScanNode",
    "EvidenceFusionNode", "LLMContextSpecialistNode", "LLMCandidateTriageNode",
    "XssValidatorNode", "DomConfirmNode", "EvidenceCollectorNode",
    "ReflectionDetectorNode", "ReportNode", "ScreenshotCaptureNode", "NucleiVulnNode",
]
