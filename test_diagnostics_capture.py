#!/usr/bin/env python3
"""Test script to capture DOM-XSS diagnostics with extended proximity window."""
from xscan.nodes.analysis.dom_xss import DomXssDetectorNode
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.nodes.base import ExecutionContext
from xscan.schemas.scope import Scope, ScopeRule, ScopeRuleType
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s: %(message)s')

def test_extended_proximity():
    """Test that extended proximity window catches distant source-sink pairs."""
    
    scope = Scope(
        scan_id='test-1',
        rules=[ScopeRule(type=ScopeRuleType.REGEX, value=r".*")]
    )
    scope_engine = ScopeEngine(scope)
    policy = PolicyEngine()

    test_js = '''var x = 1;
var y = 2;
var z = 3;
var a = 4;
var b = 5;
var c = 6;
var d = 7;
var e = 8;
var f = 9;
var source = location.search;
var g = 10;
var h = 11;
var i = 12;
var j = 13;
var k = 14;
var l = 15;
var m = 16;
var n = 17;
var o = 18;
var p = 19;
var q = 20;
var r = 21;
var s = 22;
var t = 23;
var u = 24;
document.body.innerHTML = source;
'''

    ctx = ExecutionContext(
        scan_id='test-extended-proximity',
        node_id='dom-xss-detector',
        run_id='run-1',
        inputs={
            'target_url': 'http://example.com/',
            'urls': [],
            'urls_with_params': ['http://example.com/?search=test'],
            'js_files': [{
                'page': 'http://example.com/',
                'url': 'inline:http://example.com/:0',
                'content': test_js
            }]
        },
        scope=scope_engine,
        policy=policy,
        config={}
    )

    node = DomXssDetectorNode()
    result = node.execute(ctx)

    print("\n" + "="*70)
    print("DOM-XSS DIAGNOSTICS CAPTURE TEST")
    print("="*70)
    
    if '_diagnostics' in result:
        diag = result['_diagnostics']
        print("\nDiagnostics Summary:")
        summary = {
            'pages_crawled': diag.get('pages_crawled'),
            'js_files_extracted': diag.get('js_files_extracted'),
            'js_files_analysed': diag.get('js_files_analysed'),
            'total_lines_analysed': diag.get('total_lines_analysed'),
            'dom_sources_detected': diag.get('dom_sources_detected'),
            'dom_sinks_detected': diag.get('dom_sinks_detected'),
            'candidates_generated': diag.get('candidates_generated'),
            'discard_reasons': diag.get('discard_reasons'),
        }
        print(json.dumps(summary, indent=2))
        
        print("\nFile Metrics:")
        for file_metric in diag.get('file_metrics', []):
            print(f"\n  File: {file_metric['file_url']}")
            print(f"    Sources: {file_metric['sources_count']}, Sinks: {file_metric['sinks_count']}")
            print(f"    Result: {file_metric['analysis_result']}")

    print(f"\n✓ DOM Candidates Found: {result['dom_candidate_count']}")
    if result['dom_candidates']:
        for i, cand in enumerate(result['dom_candidates'][:5]):
            print(f"\n  Candidate {i+1}:")
            print(f"    Source: {cand.get('source')}")
            print(f"    Sink: {cand.get('sink')} (line {cand.get('line')})")
            print(f"    Confidence: {cand.get('confidence')}")
    print("\n" + "="*70)
    return result

if __name__ == '__main__':
    test_extended_proximity()
