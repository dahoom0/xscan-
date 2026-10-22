"""
report node — produces the terminal / JSON scan report.

Counts:
  candidates           = reflections detected (canary phase)
  llm_likely           = Ollama judged likely-vulnerable
  confirmed_findings   = HTTP-confirmed + browser-confirmed candidates from the
                         validation stage (xss-validate, dom-confirm)

Inputs:  target_url, technologies, fused_candidates/xss_candidates,
         validated_candidates, dom_candidates,
         crawl_count, http_status, missing_security_headers, inputs_analyzed
         degraded (bool), degradation_reason (str)
Outputs: report_path (str), finding_count (int), llm_likely_count (int)
"""
from __future__ import annotations
import sys
from typing import Any
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.core.dag.node_registry import registry


def _profile_label(profile_name: str) -> str:
    """Return a descriptive label for a scan profile."""
    labels = {
        "fast": "fast (crawl + reflect only, no LLM or DOM analysis)",
        "balanced": "balanced (reflect + DOM + stored + LLM triage)",
        "deep": "deep (full taint analysis, comprehensive)",
        "recon-only": "recon-only (discovery only, no vulnerability testing)",
        "recon-deep": "recon-deep (deep reconnaissance)",
    }
    return labels.get(profile_name, f"{profile_name} (custom)")


class _EncodingSafeStream:
    """
    Wrap a text stream so glyphs it cannot encode degrade instead of raising.

    Legacy Windows code pages (cp1252) cannot encode the arrows and boxes this
    report uses; ``stream.write('\u25b6')`` raises UnicodeEncodeError, which
    would fail the whole report node — and with it the scan — over a cosmetic
    character (seen when stdout is piped or redirected).
    """

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        encoding = getattr(self._stream, "encoding", None) or "utf-8"
        try:
            text.encode(encoding)
        except (UnicodeEncodeError, LookupError):
            text = text.encode(encoding, "replace").decode(encoding, "replace")
        return int(self._stream.write(text))

    def __getattr__(self, name: str) -> Any:
        # Everything else (isatty, flush, encoding, ...) belongs to the stream.
        return getattr(self.__dict__["_stream"], name)


def _console() -> Any:
    """Report console that survives non-UTF8 terminals and piped output."""
    from rich.console import Console

    stream: Any = _EncodingSafeStream(sys.stdout)
    return Console(highlight=False, file=stream)


@registry.register("report")
class ReportNode(NodeBase):
    node_type = "report"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        fmt: str    = ctx.config.get("format", "terminal")
        output: str = ctx.config.get("output", "")
        con = _console()

        target_url:      str        = ctx.get("target_url", "?")
        techs:           list[str]  = ctx.get("technologies", [])
        crawl_count:     int        = ctx.get("crawl_count", 0)
        http_status:     int        = ctx.get("http_status", 0)
        missing_hdrs:    list[str]  = ctx.get("missing_security_headers", [])
        inputs_analyzed: int        = ctx.get("inputs_analyzed", 0)

        # Recon data (from recon pipeline nodes)
        tool_status:     dict[str, dict] = ctx.get("tool_status", {})
        available_tools: list[str]  = ctx.get("available_tools", [])
        missing_tools:   list[str]  = ctx.get("missing_tools", [])
        assets_total:    int        = ctx.get("assets_total", 0)
        assets_in_scope: int        = ctx.get("assets_in_scope", 0)
        assets_out_of_scope: int    = ctx.get("assets_out_of_scope", 0)
        live_count:      int        = ctx.get("live_count", 0)
        endpoint_count:  int        = ctx.get("endpoint_count", 0)
        screenshot_count: int       = ctx.get("screenshot_count", 0)

        # New pipeline uses validated_candidates; old pipeline uses triaged_candidates
        validated:    list[dict] = ctx.get("validated_candidates", [])
        # Accept fused_candidates (new) OR xss_candidates (legacy) for the candidate store
        candidates:   list[dict] = (
            ctx.get("fused_candidates") or
            ctx.get("xss_candidates") or
            ctx.get("triaged_candidates") or
            ctx.get("candidates") or
            []
        )

        dom_candidates:   list[dict] = ctx.get("dom_candidates", [])
        stored_candidates:list[dict] = ctx.get("stored_candidates", [])
        tool_findings:    list[dict] = ctx.get("tool_findings", [])
        tools_used:       list[str]  = ctx.get("tools_used", [])

        # Total candidate count: fused (which includes DOM) + raw DOM if not fused
        # Avoid double-counting: if evidence-fusion ran, fused_candidates already includes DOM
        fused_ran = bool(ctx.get("fused_candidates") or ctx.get("fused_count"))
        dom_cands_for_count = [] if fused_ran else dom_candidates
        total_candidates = len(candidates) or len(validated) or len(dom_cands_for_count)

        # Counts
        validated_count  = ctx.get("validated_count",  len([v for v in validated if v.get("validated")]))
        confirmed_count  = ctx.get("confirmed_count", 0)

        # For old pipeline compat
        llm_likely   = [c for c in candidates if c.get("llm_likely_vulnerable") is True]
        llm_unlikely = [c for c in candidates if c.get("llm_likely_vulnerable") is False]
        unanalysed   = [c for c in candidates
                        if c.get("llm_likely_vulnerable") is None and not c.get("llm_skip")]
        confirmed    = confirmed_count

        # New pipeline: validated candidates take precedence for severity label
        severity_source = (
            [v for v in validated if v.get("validated")]
            or llm_likely
        )

        # ── Header ──────────────────────────────────────────────────────
        con.print()
        severity_label = ""
        if severity_source:
            top_sev = _top_severity_validated(severity_source) if validated else _top_severity(llm_likely)
            col = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}.get(top_sev, "white")
            severity_label = f"  [{col}]POTENTIAL {top_sev.upper()} XSS DETECTED[/{col}]"

        con.print(Panel(
            f"[bold cyan]XScan Report[/bold cyan]{severity_label}\n\n"
            f"Target       {target_url}\n"
            f"Scan ID      {ctx.scan_id}\n"
            f"Profile      {_profile_label(ctx.inputs.get('profile', '?'))}\n"
            f"HTTP status  {http_status}"
            + (f"\n[yellow][!] DEGRADED MODE[/yellow]: {ctx.inputs.get('degradation_reason', 'Unknown')}"
               if ctx.inputs.get("degraded") else ""),
            expand=False,
        ))

        # ── Tool Health Status (recon pipeline) ───────────────────────────
        if tool_status:
            con.print("[bold]Tool Health Status:[/bold]")
            for tool_name in sorted(tool_status.keys()):
                info = tool_status[tool_name]
                status = info.get("status", "unknown")
                version = info.get("version", "")
                if status == "installed":
                    con.print(f"  [green]✓[/green] {tool_name:<15} {version or 'available'}")
                else:
                    con.print(f"  [red]✗[/red] {tool_name:<15} {status}")
            con.print()

        # ── Stats ────────────────────────────────────────────────────────
        rejected_count   = ctx.get("rejected_count",   0)
        actionable_count = ctx.get("actionable_count", total_candidates)

        con.print(
            f"  URLs crawled:      [cyan]{crawl_count}[/cyan]\n"
            f"  Inputs analyzed:   [cyan]{inputs_analyzed}[/cyan]\n"
            f"  Candidates found:  [cyan]{total_candidates}[/cyan]"
            + (f"  [dim]({rejected_count} invalid endpoints rejected)[/dim]"
               if rejected_count else "")
            + "\n"
            f"  Validated (HTTP):  [{'red' if validated_count else 'green'}]{validated_count}[/]"
            + (f"  [dim]({confirmed_count} browser-confirmed)[/dim]" if confirmed_count else "")
            + "\n"
        )

        # ── Recon Summary (if applicable) ────────────────────────────────
        # Get recon data before conditionals for use in save prompts
        raw_assets: list[dict] = ctx.get("assets", [])
        live_urls: list[str] = ctx.get("live_urls", [])
        probes: list[dict] = ctx.get("probes", [])
        discovered_paths: list[dict] = ctx.get("discovered_paths", [])
        path_count: int = ctx.get("path_count", 0)
        
        if assets_total > 0:
            con.print("[bold]Recon Summary:[/bold]")
            con.print(
                f"  Subdomains:     [cyan]{assets_total}[/cyan] discovered  "
                f"([green]{assets_in_scope}[/green] in-scope, [dim]{assets_out_of_scope}[/dim] out-of-scope)"
            )
            con.print(
                f"  Live hosts:     [cyan]{live_count}[/cyan]"
                + (f"  (via HTTP/HTTPS probe)" if live_count > 0 else "")
            )
            if endpoint_count > 0:
                con.print(f"  Endpoints:      [cyan]{endpoint_count}[/cyan]")
            if screenshot_count > 0:
                con.print(f"  Screenshots:    [cyan]{screenshot_count}[/cyan]")
            con.print()

            # ── Directory Discovery Results (if applicable) ─────────────────
            if path_count > 0:
                con.print("[bold]Directory Discovery Results:[/bold]")
                con.print(f"  Paths discovered: [cyan]{path_count}[/cyan]\n")
                
                # Group paths by status code
                paths_by_status: dict[int, list[dict]] = {}
                for p in discovered_paths[:100]:  # limit to 100 rows
                    status = p.get("status_code", 0)
                    if status not in paths_by_status:
                        paths_by_status[status] = []
                    paths_by_status[status].append(p)
                
                # Display paths grouped by status
                for status in sorted(paths_by_status.keys(), reverse=True):
                    paths = paths_by_status[status]
                    status_color = "green" if 200 <= status < 300 else "yellow" if 300 <= status < 400 else "red"
                    con.print(f"  [{status_color}]{status}[/{status_color}]  ({len(paths)} paths)")
                    
                    for p in paths[:5]:  # show first 5 per status
                        url = p.get("url", "?")
                        size = p.get("size", 0)
                        lines = p.get("lines", 0)
                        con.print(f"    {url[:80]}")
                    
                    if len(paths) > 5:
                        con.print(f"    ... and {len(paths) - 5} more")
                
                con.print()

            # ── Discovered Assets Table ──────────────────────────────────

            if raw_assets:
                con.print("[bold]Discovered Assets:[/bold]\n")
                table = Table(
                    box=box.SIMPLE_HEAD,
                    header_style="bold blue",
                    padding=(0, 1),
                    show_lines=False
                )
                table.add_column("Hostname",           style="cyan",  min_width=24)
                table.add_column("Status",             style="green", min_width=12)
                table.add_column("Technology",         min_width=28)
                table.add_column("Scope",              min_width=16)

                # Build lookup: url -> probe result
                probe_map: dict[str, dict] = {}
                for p in probes:
                    url = p.get("url", "")
                    if url:
                        probe_map[url] = p

                # Group assets by status
                for asset in raw_assets[:50]:  # limit to 50 rows
                    hostname = asset.get("hostname", "?")
                    in_scope = asset.get("in_scope", False)
                    sources = asset.get("sources", [])
                    urls = asset.get("urls", [])

                    # Determine status: LIVE or DEAD
                    if urls:
                        live_url = urls[0]
                        probe_result = probe_map.get(live_url, {})
                        http_code = probe_result.get("http_status_code", "?")
                        status = f"[green]LIVE[/green] [{http_code}]"
                        title = probe_result.get("title", "")[:26]
                    else:
                        status = "[dim]DEAD[/dim]"
                        title = ""

                    # Scope classification
                    scope_reason = asset.get("scope_reason", "")
                    if in_scope:
                        scope_label = "[green]in-scope[/green]"
                    else:
                        scope_label = "[dim]out-of-scope[/dim]"
                        if "boundary_violation" in scope_reason:
                            scope_label = "[yellow]!boundary[/yellow]"

                    table.add_row(
                        hostname,
                        status,
                        title or "[dim]—[/dim]",
                        scope_label
                    )

                con.print(table)
                con.print()

            # ── Live Hosts with Technology Stack ─────────────────────────
            if live_count > 0:
                con.print("[bold]Live Hosts Technology Stack:[/bold]\n")
                tech_map: dict[str, dict] = {}
                for probe in probes:
                    if probe.get("live"):
                        url = probe.get("url", "")
                        hostname = probe.get("hostname", "")
                        if hostname not in tech_map:
                            tech_map[hostname] = {
                                "urls": [],
                                "servers": set(),
                                "content_types": set(),
                            }
                        if url:
                            tech_map[hostname]["urls"].append(url)
                        server = probe.get("server", "")
                        if server:
                            tech_map[hostname]["servers"].add(server)
                        ct = probe.get("content_type", "")
                        if ct:
                            tech_map[hostname]["content_types"].add(ct.split(";")[0])

                for hostname in sorted(tech_map.keys())[:20]:
                    info = tech_map[hostname]
                    urls = info["urls"]
                    servers = ", ".join(sorted(info["servers"]))[:40] or "unknown"
                    content_types = ", ".join(sorted(info["content_types"]))[:40]
                    
                    url_str = urls[0] if urls else "?"
                    con.print(f"  [cyan]{hostname}[/cyan]")
                    con.print(f"    URL:    {url_str}")
                    con.print(f"    Server: [yellow]{servers}[/yellow]")
                    if content_types:
                        con.print(f"    Type:   {content_types}")

                    # Add technologies detected at target level
                    if techs and hostname == target_url.split("://")[-1].split("/")[0]:
                        con.print(f"    Stack:  {', '.join(f'[yellow]{t}[/yellow]' for t in techs[:4])}")
                    con.print()

        # ── Negative result explanation ───────────────────────────────────
        # Only show when we have candidates but none validated — explain why
        if total_candidates > 0 and validated_count == 0 and not validated:
            # Collect unique rejection reasons
            unique_reasons: dict[str, int] = {}
            for c in candidates:
                reason = (c.get("rejection_reason") or
                          c.get("endpoint_status", ""))
                if reason and reason != "valid":
                    unique_reasons[reason] = unique_reasons.get(reason, 0) + 1
            if unique_reasons:
                con.print("[bold]Candidate assessment:[/bold]")
                for reason, count in unique_reasons.items():
                    con.print(f"  [dim]{count}× {reason}[/dim]")
                con.print()

        # ── Technologies ─────────────────────────────────────────────────
        if techs:
            con.print(
                "[bold]Technologies:[/bold]  " +
                "  ".join(f"[yellow]{t}[/yellow]" for t in techs) + "\n"
            )

        # ── Missing headers ──────────────────────────────────────────────
        if missing_hdrs:
            con.print("[bold]Missing security headers:[/bold]")
            for h in missing_hdrs:
                con.print(f"  [dim]{h}[/dim]")
            con.print()

        # ── Nuclei Vulnerability Findings ────────────────────────────────
        vulnerabilities: list[dict] = ctx.get("vulnerabilities", [])
        vuln_count: int = ctx.get("vuln_count", 0)
        severity_breakdown: dict[str, int] = ctx.get("severity_breakdown", {})
        
        if vuln_count > 0:
            con.print("[bold red]🔴 VULNERABILITIES FOUND[/bold red]\n")
            con.print(f"[bold]Total vulnerabilities: {vuln_count}[/bold]")
            
            # Show severity breakdown
            if severity_breakdown:
                con.print("\n[bold]Severity Breakdown:[/bold]")
                severity_colors = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "blue",
                }
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = severity_breakdown.get(sev, 0)
                    if count > 0:
                        color = severity_colors.get(sev, "white")
                        con.print(f"  [{color}]{sev.upper()}[/{color}]: {count}")
            
            con.print("\n[bold]Vulnerability Details:[/bold]\n")
            
            # Group vulnerabilities by severity
            vulns_by_sev: dict[str, list[dict]] = {}
            for vuln in vulnerabilities:
                sev = vuln.get("severity", "info")
                if sev not in vulns_by_sev:
                    vulns_by_sev[sev] = []
                vulns_by_sev[sev].append(vuln)
            
            # Display by severity (highest first)
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev not in vulns_by_sev:
                    continue
                
                vulns = vulns_by_sev[sev]
                color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "blue"}.get(sev, "white")
                
                for i, vuln in enumerate(vulns[:10], 1):  # Show first 10 per severity
                    template = vuln.get("template", "unknown")
                    host = vuln.get("host", "?")
                    matched_at = vuln.get("matched-at", "?")
                    tags = vuln.get("tags", [])
                    
                    con.print(f"  [{color}]{i}. {template}[/{color}]")
                    con.print(f"     Host:       {host}")
                    con.print(f"     URL:        {matched_at[:80]}")
                    if tags:
                        con.print(f"     Tags:       {', '.join(tags[:5])}")
                    con.print()
                
                if len(vulns) > 10:
                    con.print(f"  ... and {len(vulns) - 10} more {sev} vulnerabilities\n")
            
            con.print()

        # ── Candidates table ─────────────────────────────────────────────
        # ── New pipeline: validated candidates ──────────────────────────
        if validated:
            v_found    = [v for v in validated if v.get("validated")]
            v_tried    = [v for v in validated if v.get("observations")]
            v_not_tried= [v for v in validated if not v.get("observations") and not v.get("validated")]

            if not v_found and v_tried:
                con.print(
                    f"[yellow]Candidates analysed ({len(v_tried)}) — "
                    f"no unencoded reflection confirmed.[/yellow]\n"
                )
            elif not v_found:
                con.print("[green]No unencoded XSS reflections confirmed.[/green]\n")

            # Show every candidate — validated or not
            for v in validated:
                ctx_info    = v.get("context_analysis") or {}
                enc_info    = v.get("encoding_profile") or {}
                param       = v.get("parameter", "?")
                url         = v.get("url", "?")
                ctx_name    = ctx_info.get("context", "?")
                enc_sum     = enc_info.get("summary", "")
                plan        = v.get("test_plan", {})
                obs_list    = v.get("observations", [])
                replans     = v.get("replan_count", 0)
                best_pay    = v.get("best_payload", "")
                best_url    = v.get("best_test_url", "")
                is_validated= v.get("validated", False)

                # Header
                sev_col = "red" if is_validated else "yellow"
                status_tag = "[red]VALIDATED[/red]" if is_validated else "[yellow]ANALYSED[/yellow]"
                con.print(f"  {status_tag}  [cyan]{param}[/cyan]  [dim]{url[:65]}[/dim]")

                # Context + encoding
                con.print(f"     Context:   [cyan]{ctx_name}[/cyan]")
                if ctx_info.get("tag"):
                    con.print(f"     Tag/Attr:  {ctx_info['tag']}  {ctx_info.get('attribute','')}  quote={ctx_info.get('quote_type','')}")
                con.print(f"     Encoding:  {enc_sum or 'not tested'}")
                if enc_info.get("raw_chars"):
                    con.print(f"     Raw chars: [red]{enc_info['raw_chars']}[/red]  ← these are NOT encoded")
                if enc_info.get("encoded_chars"):
                    con.print(f"     Blocked:   [dim]{enc_info['encoded_chars']}[/dim]  ← HTML entity encoded by server")
                if enc_info.get("stripped_chars"):
                    con.print(f"     Stripped:  [dim]{enc_info['stripped_chars']}[/dim]  ← removed by server")

                # Canary evidence
                if v.get("canary_evidence"):
                    con.print(f"     Evidence:  [dim]{v['canary_evidence'][:140]}[/dim]")

                # WHY this payload works — generated from the candidate's own
                # evidence by the vulnerability model.
                why_lines = v.get("why") or []
                if best_pay and why_lines:
                    con.print(f"     Why:       [dim]{why_lines[0]}[/dim]")
                    for wl in why_lines[1:4]:
                        con.print(f"                [dim]{wl}[/dim]")

                # Browser confirmation evidence (dom-confirm)
                browser = v.get("browser_evidence") or {}
                if browser.get("dialog_fired"):
                    fired = ", ".join(
                        f"{d.get('type', 'dialog')}({(d.get('args') or [''])[0][:40]})"
                        for d in (browser.get("dialogs") or [])[:2]
                    )
                    trigger_note = ""
                    if browser.get("triggered"):
                        trigger_note = f" via click on {browser['triggered'][0]}"
                    con.print(f"     Browser:   [red]CONFIRMED[/red] {fired}{trigger_note}")
                elif browser.get("dom_state"):
                    hit = (browser.get("dom_state") or [{}])[0]
                    con.print(
                        f"     Browser:   [yellow]payload reached "
                        f"<{hit.get('tag', '?')} {hit.get('attribute', '?')}>[/yellow]"
                        " but never executed — not a finding"
                    )
                elif browser.get("note"):
                    con.print(f"     Browser:   [dim]{browser['note'][:120]}[/dim]")

                # Test plan reasoning
                if plan.get("context_interpretation"):
                    con.print(f"     Analysis:  {plan['context_interpretation'][:160]}")
                if plan.get("breakout_strategy"):
                    con.print(f"     Strategy:  {plan['breakout_strategy'][:120]}")
                if not plan.get("viable") and plan.get("reasoning"):
                    con.print(f"     [dim]Not viable: {plan['reasoning'][:160]}[/dim]")

                # Observations (what was actually tried)
                if obs_list:
                    con.print(f"\n     Attempts ({len(obs_list)}"
                              + (f", {replans} re-plan(s)" if replans else "") + "):")
                    for o in obs_list:
                        if o.get("payload_reflected") and not o.get("payload_encoded"):
                            status_sym = "[red]REFLECTED (unencoded)[/red]"
                        elif o.get("payload_encoded"):
                            status_sym = "[dim]encoded[/dim]"
                        elif o.get("payload_stripped"):
                            status_sym = "[dim]stripped[/dim]"
                        else:
                            status_sym = "[dim]not found[/dim]"
                        con.print(f"       #{o.get('attempt',0)}  {o.get('payload','')[:60]:<62}  {status_sym}")
                        if o.get("reflection_context"):
                            con.print(f"              ctx={o['reflection_context']}  {o.get('reflection_snippet','')[:80]}")

                # Working payload — only "working" when validation confirmed it.
                if best_pay:
                    label = "Working payload:" if is_validated else "Payload tried (unconfirmed):"
                    con.print(f"\n     [bold]{label}[/bold]  [red]{best_pay}[/red]")
                if best_url:
                    con.print(f"     [bold]Test URL:[/bold]")
                    con.print(f"     [cyan]{best_url}[/cyan]")

                # Why it may not be exploitable
                if not is_validated and obs_list:
                    encoded = enc_info.get("encoded_chars", [])
                    stripped = enc_info.get("stripped_chars", [])
                    if "<" in encoded or ">" in encoded:
                        con.print(
                            f"\n     [dim]Note: < and > are HTML-encoded — "
                            "reflected XSS blocked. May be exploitable via attribute/script context.[/dim]"
                        )
                    elif "<" in stripped or ">" in stripped:
                        con.print(f"\n     [dim]Note: < and > are stripped — input sanitised server-side.[/dim]")

                con.print()

        # ── Old pipeline: LLM-triaged candidates (legacy) ───────────────
        elif candidates:
            con.print(f"[bold]Candidates ({len(candidates)}):[/bold]\n")
            table = Table(box=box.SIMPLE_HEAD, header_style="bold blue", padding=(0, 1))
            table.add_column("Param",  style="cyan", min_width=14)
            table.add_column("URL",    min_width=42)
            table.add_column("Context", min_width=16)
            table.add_column("Verdict", min_width=14)
            for c in sorted(candidates, key=_sort_key, reverse=True):
                vuln = c.get("llm_likely_vulnerable")
                if vuln is True:
                    verdict = "[red]likely XSS[/red]"
                elif vuln is False:
                    verdict = "[green]false positive[/green]"
                else:
                    verdict = "[dim]unanalysed[/dim]"
                url_s = c.get("url", "?")
                if len(url_s) > 52:
                    url_s = url_s[:49] + "..."
                table.add_row(
                    c.get("parameter", "?"), url_s,
                    c.get("context", "?"), verdict,
                )
            con.print(table)
            con.print()

            # Detailed LLM analysis for likely candidates
            if llm_likely:
                con.print("[bold]Ollama deep analysis:[/bold]\n")
                for c in llm_likely:
                    param = c.get("parameter", "?")
                    url   = c.get("url", "?")
                    sev   = c.get("llm_severity", "?")
                    col   = {"critical":"red","high":"red","medium":"yellow","low":"cyan"}.get(sev, "white")
                    con.print(f"  [{col}]▶  {param}[/{col}]  [dim]{url[:70]}[/dim]")
                    if c.get("llm_context"):
                        con.print(f"     [dim]Context:[/dim]    {c['llm_context']}")
                    if c.get("llm_encoding_analysis"):
                        con.print(f"     [dim]Encoding:[/dim]   {c['llm_encoding_analysis']}")
                    working = c.get("working_payloads", [])
                    unencoded = [p for p in working if not p.get("encoded")]
                    if unencoded:
                        con.print(f"     [bold]Working payloads:[/bold]")
                        for p in unencoded[:3]:
                            con.print(f"       [red]{p['payload']}[/red]")
                    best = c.get("llm_best_payload", "")
                    if best:
                        con.print(f"     [bold]Suggested payload:[/bold]  [yellow]{best}[/yellow]")
                    if c.get("llm_reasoning"):
                        con.print(f"     [dim]Reasoning:[/dim]  {c['llm_reasoning'][:160]}")
                    best_url = (unencoded[0].get("url","") if unencoded else "") or c.get("request_url","")
                    if best_url:
                        con.print(f"\n     [bold]Test URL:[/bold]")
                        con.print(f"     [cyan]{best_url}[/cyan]")
                    con.print()
        else:
            con.print("[green]No reflected XSS candidates found.[/green]\n")

        # ── DOM XSS candidates ───────────────────────────────────────────
        if dom_candidates:
            con.print(f"[bold]DOM XSS candidates ({len(dom_candidates)}):[/bold]\n")
            for d in dom_candidates:
                sev = d.get("severity", "high")
                col = {"critical":"red","high":"red","medium":"yellow","low":"cyan"}.get(sev,"white")
                con.print(
                    f"  [{col}]▶  {d.get('source','?')}  →  {d.get('sink','?')}[/{col}]"
                    f"  [{col}]{sev}[/{col}]"
                    f"  [dim]{('inline' if d.get('file_url')=='inline' else d.get('file_url','?')[-35:])}[/dim]"
                )
                if d.get("snippet"):
                    con.print(f"     [dim]{d['snippet'][:140]}[/dim]")

                # Payloads
                payloads = d.get("payloads", [])
                test_urls = d.get("test_urls", [])
                if payloads:
                    con.print(f"\n     [bold]Payloads to test:[/bold]")
                    for j, payload in enumerate(payloads[:4]):
                        con.print(f"       [red]{payload}[/red]")

                # Best ready-to-use test URL
                best_url = d.get("best_test_url", "")
                if best_url:
                    con.print(f"\n     [bold]Test URL:[/bold]")
                    con.print(f"     [cyan]{best_url}[/cyan]")

                # All test URLs
                if len(test_urls) > 1:
                    con.print(f"\n     [dim]All test URLs:[/dim]")
                    for turl in test_urls[:4]:
                        con.print(f"     [dim]{turl}[/dim]")

                con.print()

        # ── Stored XSS candidates ────────────────────────────────────────
        if stored_candidates:
            con.print(f"[bold red]Stored XSS candidates ({len(stored_candidates)}):[/bold red]\n")
            for s in stored_candidates:
                con.print(
                    f"  [red]STORED XSS[/red]  param=[cyan]{s.get('parameter','?')}[/cyan]  "
                    f"submitted to [dim]{s.get('form_action','?')[:50]}[/dim]"
                )
                con.print(f"  Found at: [cyan]{s.get('found_at','?')}[/cyan]")
                con.print(f"  Context:  {s.get('context','?')}  Evidence: {s.get('snippet','')[:100]}")
            con.print()

        # ── Tool findings ────────────────────────────────────────────────
        if tool_findings:
            con.print(f"[bold]Tool findings ({len(tool_findings)}):[/bold]  "
                      f"[dim]tools: {', '.join(tools_used)}[/dim]\n")
            for f_item in tool_findings:
                tool = f_item.get("tool","?")
                payload = f_item.get("payload","") or f_item.get("raw","")[:80]
                con.print(f"  [{tool}]  [red]{payload[:100]}[/red]")
                con.print(f"           {f_item.get('url','')[:80]}")
            con.print()
        elif tools_used:
            con.print(f"[dim]Tools ran ({', '.join(tools_used)}) — no additional findings.[/dim]\n")

        # ── JSON output ──────────────────────────────────────────────────
        if fmt == "json" or (output and output.endswith(".json")):
            import json
            from pathlib import Path
            report_data = {
                "scan_id":       ctx.scan_id,
                "target_url":    target_url,
                "profile":       ctx.inputs.get("profile", "?"),
                "http_status":   http_status,
                "technologies":  techs,
                "crawl_count":   crawl_count,
                "inputs_analyzed": inputs_analyzed,
                "candidates_count": len(candidates),
                "llm_likely_count": len(llm_likely),
                "confirmed_findings": confirmed,
                "candidates": [
                    {k: v for k, v in c.items() if k != "form"}
                    for c in candidates
                ],
            }
            out_str = json.dumps(report_data, indent=2)
            if output:
                Path(output).write_text(out_str, encoding="utf-8")
                con.print(f"[dim]JSON report saved: {output}[/dim]\n")
            else:
                con.print(out_str)

        # ── Interactive save prompts for discovered data ──────────────────
        from xscan.nodes.reporting.export import (
            prompt_save_location, export_subdomains, export_endpoints, export_paths
        )
        
        con.print()
        con.print("[bold]Save Discovery Results:[/bold]")
        
        # Prompt for subdomains if any discovered
        if assets_total > 0 and raw_assets:
            filepath = prompt_save_location(
                "subdomains",
                default_name=f"xscan_subdomains_{ctx.scan_id}",
                formats=["json", "csv"]
            )
            if filepath:
                export_subdomains(raw_assets, filepath)
        
        # Prompt for endpoints if any discovered
        if endpoint_count > 0:
            endpoints = ctx.get("endpoints", [])
            if endpoints:
                filepath = prompt_save_location(
                    "endpoints",
                    default_name=f"xscan_endpoints_{ctx.scan_id}",
                    formats=["json", "csv"]
                )
                if filepath:
                    export_endpoints(endpoints, filepath)
        
        # Prompt for discovered paths (from ffuf) if any found
        if path_count > 0 and discovered_paths:
            filepath = prompt_save_location(
                "discovered paths",
                default_name=f"xscan_paths_{ctx.scan_id}",
                formats=["json", "csv"]
            )
            if filepath:
                export_paths(discovered_paths, filepath)

        return {
            "report_path":       output or "",
            "finding_count":     confirmed,
            "llm_likely_count":  len(llm_likely),
            "validated_count":   validated_count,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def _sort_key(c: dict) -> int:
    if not c.get("llm_likely_vulnerable"):
        return 0
    return _SEV_ORDER.get(c.get("llm_severity", ""), 0)

def _top_severity(candidates: list[dict]) -> str:
    best = 0
    label = "high"
    for c in candidates:
        sev = c.get("llm_severity", "")
        score = _SEV_ORDER.get(sev, 0)
        if score > best:
            best = score
            label = sev
    return label

def _top_severity_validated(validated: list[dict]) -> str:
    """Get severity from context analysis for validated candidates."""
    # Validated candidates don't have llm_severity yet — use context heuristic
    ctx_sev = {
        "html_text": "high",
        "html_attribute": "high",
        "script_string_double": "high",
        "script_string_single": "high",
        "script_expression": "critical",
        "html_attribute_unquoted": "high",
    }
    best = 0
    label = "high"
    for v in validated:
        ctx = (v.get("context_analysis") or {}).get("context", "")
        sev = ctx_sev.get(ctx, "high")
        score = _SEV_ORDER.get(sev, 0)
        if score > best:
            best = score
            label = sev
    return label
