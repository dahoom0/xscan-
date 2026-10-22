"""
XScan CLI
=========
Five focused commands:

  xscan xss <target>       # XSS scanner
  xscan chat               # Ollama assistant with scan context
  xscan install <tool>     # Install security tools
  xscan skills             # Manage skill packs
  xscan --fix              # Health check + auto-repair

Everything else (model management, workflow inspection, status, etc.)
is available as sub-commands but the primary surface stays small.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from xscan.cli.cmd_help import app as help_app

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="xscan",
    help=(
        "[bold cyan]XScan[/bold cyan] — Local AI-powered XSS scanner\n\n"
        "[bold]Scanning:[/bold]\n"
        "  [cyan]xscan xss <target>[/cyan]                        Balanced scan (default)\n"
        "  [cyan]xscan xss <target> --profile fast[/cyan]         Fast scan, no LLM\n"
        "  [cyan]xscan xss <target> --profile deep[/cyan]         Deep scan with JS taint analysis\n"
        "  [cyan]xscan xss <target> --no-llm[/cyan]               Skip Ollama, deterministic only\n"
        "  [cyan]xscan xss <target> --spa[/cyan]                   Force SPA mode (Angular/React/Vue)\n"
        "  [cyan]xscan xss <target> --output report.json[/cyan]    Save results to file\n"
        "  [cyan]xscan xss --urls targets.txt[/cyan]              Scan every URL in a file, sequentially\n"
        "  [cyan]cat targets.txt | xscan xss --stdin[/cyan]       Scan URLs piped from stdin\n\n"
        "[bold]Recon only:[/bold]\n"
        "  [cyan]xscan recon <target>[/cyan]                       Passive recon (no XSS probing)\n"
        "  [cyan]xscan recon <target> --deep[/cyan]                Deep recon with FFUF + amass\n\n"
        "[bold]Output flags (on xss / recon):[/bold]\n"
        "  [cyan]--verbose[/cyan]  / [cyan]-v[/cyan]              Show per-node details\n"
        "  [cyan]--quiet[/cyan]    / [cyan]-q[/cyan]              One-line summary only\n"
        "  [cyan]--json[/cyan]                                    Machine-readable JSON to stdout\n"
        "  [cyan]--output <file>[/cyan]                           Save JSON report to file\n\n"
        "[bold]Tools:[/bold]\n"
        "  [cyan]xscan install katana httpx dalfox subfinder ffuf[/cyan]\n"
        "  [cyan]xscan install --list[/cyan]                       Show all available tools\n\n"
        "[bold]Other:[/bold]\n"
        "  [cyan]xscan chat[/cyan]                                 Ask Ollama about your scan\n"
        "  [cyan]xscan skills list[/cyan]                          Browse skill packs\n"
        "  [cyan]xscan models list[/cyan]                          List Ollama models\n"
        "  [cyan]xscan --fix[/cyan]                                Environment health check"
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

_con = Console(highlight=False, stderr=False)
app.add_typer(help_app, name="help", rich_help_panel="Other")


# ---------------------------------------------------------------------------
# --fix flag on root
# ---------------------------------------------------------------------------

def _fix_callback(value: bool) -> None:
    if value:
        _run_fix()
        raise typer.Exit()


def _version_callback(value: bool) -> None:
    if value:
        from xscan import __version__
        _con.print(f"[bold cyan]XScan[/bold cyan] [yellow]{__version__}[/yellow]")
        raise typer.Exit()


@app.callback(invoke_without_command=False)
def root_callback(
    fix: bool = typer.Option(
        False, "--fix",
        callback=_fix_callback, is_eager=True,
        help="Check environment and auto-repair problems.",
    ),
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=_version_callback, is_eager=True,
        help="Show version.",
    ),
) -> None:
    """XScan — Local AI-powered XSS scanner."""


# ===========================================================================
# xscan xss <target>
# ===========================================================================

@app.command("xss")
def cmd_xss(
    target: str = typer.Argument(
        None,
        help="Target URL or domain. Required unless --urls or --stdin is specified.",
    ),
    urls: Optional[str] = typer.Option(
        None, "--urls", "-u",
        help="Path to file containing target URLs (one per line).",
    ),
    stdin: bool = typer.Option(
        False, "--stdin",
        help="Read target URLs from stdin (one per line).",
    ),
    profile: str = typer.Option(
        "balanced", "--profile", "-p",
        help="Scan depth: fast | balanced | deep",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-node details."),
    debug: bool   = typer.Option(False, "--debug",         help="Show full internal state."),
    quiet: bool   = typer.Option(False, "--quiet", "-q",   help="Output summary line only."),
    json_out: bool= typer.Option(False, "--json",          help="Machine-readable JSON output."),
    no_llm: bool  = typer.Option(False, "--no-llm",        help="Disable Ollama analysis."),
    spa: bool     = typer.Option(False, "--spa",           help="Force SPA mode: probe REST/API endpoints (auto-detected for Angular/React/Vue)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file."),
) -> None:
    """
    Run an XSS scan against a target.

    \b
    Profile options:
      fast      Crawl + reflect + report. No LLM, no DOM analysis. (~10s)
      balanced  Reflect + DOM + stored + LLM triage. (default, ~60s)
      deep      Full taint graph + LLM + iterative validation. (~5min)

    \b
    Multiple targets:
      --urls <file>   Scan every URL in a file (one per line) sequentially
      --stdin         Read URLs from stdin (one per line)

    \b
    Examples:
      xscan xss example.com
      xscan xss example.com --profile fast
      xscan xss example.com --profile deep
      xscan xss example.com --no-llm
      xscan xss example.com --verbose
      xscan xss example.com --quiet
      xscan xss example.com --json
      xscan xss example.com --output report.json
      xscan xss http://127.0.0.1:3000/ --spa
      xscan xss http://127.0.0.1:3000/ --spa --no-llm --profile fast
      xscan xss --urls targets.txt
      xscan xss -u targets.txt --profile fast --output results.json
      cat targets.txt | xscan xss --stdin --quiet
    """
    import uuid

    import xscan.nodes.registry  # noqa — registers all nodes

    # Generate a scan ID without touching the database
    scan_id = uuid.uuid4().hex[:8].upper()

    # Multi-target mode: scan a file of URLs / stdin sequentially.
    if urls or stdin:
        from xscan.cli.multi_target import run_multi_target_scan
        _PROFILE_WF = {"fast": "xss-fast", "balanced": "xss-balanced", "deep": "xss-deep"}
        wf_name = _PROFILE_WF.get(profile, "xss-balanced")
        run_multi_target_scan(
            scan_id=scan_id,
            urls_file=urls,
            use_stdin=stdin,
            profile=profile,
            wf_name=wf_name,
            verbose=verbose,
            debug=debug,
            quiet=quiet,
            json_out=json_out,
            no_llm=no_llm,
            spa=spa,
            output=output,
            console=_con,
        )
        return

    if not target:
        _con.print(
            "[red]No target.[/red]  Provide a URL, or use "
            "[cyan]--urls <file>[/cyan] / [cyan]--stdin[/cyan].\n"
        )
        raise typer.Exit(1)

    from xscan.cli.renderer import TerminalRenderer
    from xscan.core.events import ScanSummary
    from xscan.core.dag.engine import DAGEngine
    from xscan.core.dag.checkpoint import MemoryCheckpoint
    from xscan.core.scope.engine import ScopeEngine
    from xscan.core.scope.policy import PolicyEngine
    from xscan.schemas.scan import Target
    from xscan.workflows.loader import WorkflowLoader
    from xscan.events import bus
    from xscan.schemas.events import EventType

    _PROFILE_WF = {"fast": "xss-fast", "balanced": "xss-balanced", "deep": "xss-deep"}
    wf_name = _PROFILE_WF.get(profile, "xss-balanced")

    # Normalise target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    resolved = Target.from_url(target)

    # Set up renderer and wire to EventBus
    renderer = TerminalRenderer(
        console=_con,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
        json_mode=json_out,
    )
    renderer.start(scan_id, resolved.url, profile, wf_name)

    # Subscribe renderer to node events
    bus.subscribe(EventType.NODE_STARTED,   renderer.handle_domain_event)
    bus.subscribe(EventType.NODE_COMPLETED, renderer.handle_domain_event)
    bus.subscribe(EventType.NODE_FAILED,    renderer.handle_domain_event)

    # Clear any previous interrupt signal before starting
    from xscan.validation.http import clear_stop
    clear_stop()

    t0 = time.monotonic()
    run = None

    try:
        loader   = WorkflowLoader()
        workflow = loader.load(wf_name)
        scope    = ScopeEngine.from_target(scan_id, resolved.url)
        policy   = PolicyEngine()
        cp       = MemoryCheckpoint()

        engine = DAGEngine(
            workflow=workflow,
            scope=scope,
            policy=policy,
            checkpoint=cp,
            no_llm=no_llm,
        )
        run = engine.execute(
            scan_id=scan_id,
            inputs={
                "target_url": resolved.url,
                "scan_id":    scan_id,
                "profile":    profile,
                "spa_mode":   True if spa else None,
            },
        )

    except KeyboardInterrupt:
        from xscan.validation.http import request_stop
        request_stop()
        _con.print("\n[yellow]Scan interrupted.[/yellow]\n")
        raise typer.Exit(130)
    except Exception as exc:
        _con.print(f"\n[red]Scan failed:[/red] {exc}\n")
        raise typer.Exit(1)
    finally:
        bus.unsubscribe(EventType.NODE_STARTED,   renderer.handle_domain_event)
        bus.unsubscribe(EventType.NODE_COMPLETED, renderer.handle_domain_event)
        bus.unsubscribe(EventType.NODE_FAILED,    renderer.handle_domain_event)

    if run is None:
        raise typer.Exit(1)

    # Build summary from run outputs
    # Collect last-node outputs by merging all completed node outputs.
    # IMPORTANT: iterate in dependency order (node_results preserves insertion).
    # To avoid key collisions (e.g. 'technologies' overwritten by a later node),
    # we capture specific keys from the node that owns them.
    all_outputs: dict = {}
    technologies_from_recon: list[str] = []
    for node_id, nr in run.node_results.items():
        out = nr.output or {}
        all_outputs.update(out)
        # Grab technologies specifically from the recon/technology-detect node
        # before any later node can overwrite the key in all_outputs
        if "technologies" in out and out["technologies"]:
            technologies_from_recon = [str(t) for t in out["technologies"]]

    duration = time.monotonic() - t0
    # Candidate stores, newest pipeline first (fusion merges reflected + DOM +
    # stored + tool observations; xss_candidates is the pre-fusion store).
    candidates = (
        all_outputs.get("fused_candidates")
        or all_outputs.get("xss_candidates")
        or all_outputs.get("triaged_candidates")
        or all_outputs.get("candidates")
        or []
    )
    if not isinstance(candidates, list):
        candidates = []
    dom_candidates = all_outputs.get("dom_candidates", [])
    if not isinstance(dom_candidates, list):
        dom_candidates = []
    llm_likely = sum(1 for c in candidates if isinstance(c, dict) and c.get("llm_likely_vulnerable") is True)

    # technologies: prefer the value captured directly from the recon node
    # (avoids last-writer-wins collision from merged all_outputs)
    raw_techs = technologies_from_recon or all_outputs.get("technologies", [])
    if isinstance(raw_techs, (list, tuple, set)):
        technologies: list[str] = [str(t) for t in raw_techs]
    else:
        technologies = []

    summary = ScanSummary(
        scan_id=scan_id,
        target_url=resolved.url,
        profile=profile,
        status=run.status if isinstance(run.status, str) else run.status.value,
        duration_s=round(duration, 1),
        urls_crawled=all_outputs.get("crawl_count", 0),
        forms_found=len(all_outputs.get("forms", []) or []),
        inputs_analyzed=all_outputs.get("inputs_analyzed", 0),
        reflections=all_outputs.get("candidate_count", 0),
        candidates=len(candidates),
        llm_likely=llm_likely,
        # Report node owns the authoritative count; fall back to whatever the
        # validation stage (xss-validate / dom-confirm) recorded.
        confirmed_findings=(
            all_outputs.get("finding_count") or all_outputs.get("confirmed_count", 0)
        ),
        technologies=technologies,
    )
    renderer.finish(summary)

    # Save JSON report if requested
    if output and not json_out:
        import json
        Path(output).write_text(
            json.dumps(summary.model_dump(), indent=2),
            encoding="utf-8",
        )
        if not quiet:
            _con.print(f"[dim]Report saved: {output}[/dim]\n")


# ===========================================================================
# xscan recon <target>
# ===========================================================================

@app.command("recon")
def cmd_recon(
    target: str = typer.Argument(..., help="Target URL or domain."),
    deep: bool  = typer.Option(False, "--deep", "-d", help="Deep recon: subdomain enum + FFUF directory discovery."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-node details."),
    quiet: bool   = typer.Option(False, "--quiet", "-q", help="Output summary line only."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file."),
) -> None:
    """
    Run reconnaissance only — no XSS probing.

    Performs technology detection, passive subdomain enumeration,
    HTTP probing, and endpoint inventory.

    \b
    Examples:
      xscan recon example.com
      xscan recon example.com --deep
      xscan recon example.com --verbose
      xscan recon example.com --output recon.json
    """
    import xscan.nodes.registry  # noqa — registers all nodes
    from xscan.cli.renderer import TerminalRenderer
    from xscan.core.events import ScanSummary
    from xscan.core.dag.engine import DAGEngine
    from xscan.core.scope.engine import ScopeEngine
    from xscan.core.scope.policy import PolicyEngine
    from xscan.schemas.scan import Target
    from xscan.workflows.loader import WorkflowLoader
    from xscan.events import bus
    from xscan.schemas.events import EventType

    wf_name = "recon-deep" if deep else "recon-only"

    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    resolved = Target.from_url(target)

    import uuid
    scan_id = uuid.uuid4().hex[:8].upper()

    renderer = TerminalRenderer(
        console=_con, verbose=verbose, quiet=quiet,
        debug=False, json_mode=False,
    )
    renderer.start(scan_id, resolved.url, "recon", wf_name)

    bus.subscribe(EventType.NODE_STARTED,   renderer.handle_domain_event)
    bus.subscribe(EventType.NODE_COMPLETED, renderer.handle_domain_event)
    bus.subscribe(EventType.NODE_FAILED,    renderer.handle_domain_event)

    t0 = time.monotonic()
    run = None

    try:
        loader   = WorkflowLoader()
        workflow = loader.load(wf_name)
        scope    = ScopeEngine.from_target(scan_id, resolved.url)
        policy   = PolicyEngine()
        from xscan.core.dag.checkpoint import MemoryCheckpoint
        cp       = MemoryCheckpoint()

        engine = DAGEngine(
            workflow=workflow, scope=scope, policy=policy,
            checkpoint=cp, no_llm=True,
        )
        run = engine.execute(
            scan_id=scan_id,
            inputs={"target_url": resolved.url, "scan_id": scan_id},
        )
    except KeyboardInterrupt:
        _con.print("\n[yellow]Recon interrupted.[/yellow]\n")
        raise typer.Exit(130)
    except Exception as exc:
        _con.print(f"\n[red]Recon failed:[/red] {exc}\n")
        raise typer.Exit(1)
    finally:
        bus.unsubscribe(EventType.NODE_STARTED,   renderer.handle_domain_event)
        bus.unsubscribe(EventType.NODE_COMPLETED, renderer.handle_domain_event)
        bus.unsubscribe(EventType.NODE_FAILED,    renderer.handle_domain_event)

    if run is None:
        raise typer.Exit(1)

    all_outputs: dict = {}
    technologies_from_recon: list[str] = []
    for node_id, nr in run.node_results.items():
        out = nr.output or {}
        all_outputs.update(out)
        if "technologies" in out and out["technologies"]:
            technologies_from_recon = [str(t) for t in out["technologies"]]

    duration = time.monotonic() - t0
    raw_techs = technologies_from_recon or all_outputs.get("technologies", [])
    technologies: list[str] = [str(t) for t in raw_techs] if isinstance(raw_techs, (list, tuple, set)) else []

    summary = ScanSummary(
        scan_id=scan_id,
        target_url=resolved.url,
        profile="recon-deep" if deep else "recon-only",
        status=run.status if isinstance(run.status, str) else run.status.value,
        duration_s=round(duration, 1),
        urls_crawled=all_outputs.get("endpoint_count", len(all_outputs.get("endpoint_urls", []))),
        inputs_analyzed=0,
        technologies=technologies,
    )
    renderer.finish(summary)

    if output:
        import json
        data = {
            "scan_id":       scan_id,
            "target":        resolved.url,
            "profile":       summary.profile,
            "duration_s":    summary.duration_s,
            "technologies":  technologies,
            "endpoints":     all_outputs.get("endpoint_urls", []),
            "live_urls":     all_outputs.get("live_urls", []),
            "assets":        all_outputs.get("assets", []),
        }
        Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        if not quiet:
            _con.print(f"[dim]Report saved: {output}[/dim]\n")


# ===========================================================================
# xscan chat
# ===========================================================================

@app.command("chat")
def cmd_chat(
    message: list[str] = typer.Argument(None, help="Message (no quotes needed)."),
    scan_id: Optional[str] = typer.Option(None, "--scan", help="Reference a specific scan ID."),
) -> None:
    """
    Chat with Ollama about your scans, targets, and findings.

    \b
    Examples:
      xscan chat
      xscan chat what did the last scan find
      xscan chat why did the scanner find nothing
      xscan chat --scan A1B2C3D4
    """
    # Join multi-word message — allows `xscan chat why did it find nothing` without quotes
    initial_message = " ".join(message).strip() if message else None
    from xscan.llm.providers.ollama import OllamaProvider
    from xscan.skills import skill_manager
    from xscan.storage.database import get_db
    from xscan.storage.repositories.scan import ScanRepository
    import readline  # noqa — enables arrow keys in input()

    provider = OllamaProvider()
    if not provider.ping():
        _con.print("[red]Ollama is not reachable.[/red]  Start it with: [cyan]ollama serve[/cyan]\n")
        raise typer.Exit(1)

    # Load scan context
    scan_context = ""
    db = get_db()
    repo = ScanRepository(db)
    if scan_id:
        scan = repo.get(scan_id)
    else:
        recent = repo.list_recent(limit=1)
        scan = recent[0] if recent else None

    if scan:
        scan_context = (
            f"Most recent scan context:\n"
            f"  Target:   {scan.target.url}\n"
            f"  Scan ID:  {scan.id}\n"
            f"  Profile:  {scan.profile}\n"
            f"  Status:   {scan.status}\n"
            f"  Workflow: {scan.workflow_name}\n"
        )

    # Load relevant skills
    skill_manager.load_all()
    skills = skill_manager.for_context(category="analysis")
    skill_text = skill_manager.render(skills)

    system_prompt = f"""\
You are XScan Assistant — an expert in XSS vulnerabilities and web security.
You have access to XScan's scan results and skill knowledge.
Answer questions about scan results, XSS findings, and security concepts.
Be concise and practical. Do not make up scan results.

{scan_context}
{skill_text}
"""

    from xscan.schemas.llm import LLMRequest
    model = provider.active_model()

    _con.print(f"\n[bold cyan]XScan Chat[/bold cyan]  [dim]model: {model}[/dim]")
    if scan:
        _con.print(f"[dim]Scan context: {scan.id}  {scan.target.url}[/dim]")
    _con.print("[dim]Type 'exit' or Ctrl+C to quit.[/dim]\n")

    def _ask(user_msg: str) -> str:
        req = LLMRequest(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_msg,
            specialist="chat",
            timeout=120,
        )
        try:
            resp = provider.complete(req)
            return resp.raw_text
        except Exception as exc:
            return f"[error] {exc}"

    # Single message mode
    if initial_message:
        _con.print(f"[bold]You:[/bold] {initial_message}\n")
        answer = _ask(initial_message)
        _con.print(f"[cyan]XScan:[/cyan] {answer}\n")
        return

    # Interactive loop
    try:
        while True:
            try:
                user_input = input("You: ").strip()
            except EOFError:
                break
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                break
            answer = _ask(user_input)
            _con.print(f"\n[cyan]XScan:[/cyan] {answer}\n")
    except KeyboardInterrupt:
        pass

    _con.print("\n[dim]Bye.[/dim]\n")


# ===========================================================================
# xscan install <tool>
# ===========================================================================

@app.command("install")
def cmd_install(
    tools: Optional[list[str]] = typer.Argument(None, help="Tool name(s) to install."),
    list_available: bool = typer.Option(False, "--list", "-l", help="List available tools."),
) -> None:
    """
    Install security tools into ~/.xscan/bin/.

    Uses Go install via WSL2 (Windows) or natively (Linux/macOS).

    \b
    Examples:
      xscan install katana
      xscan install katana httpx dnsx nuclei
      xscan install --list
    """
    from xscan.tools.installers.universal import UniversalInstaller

    installer = UniversalInstaller()

    if list_available or not tools:
        _con.print("\n[bold]Available tools:[/bold]\n")
        from xscan.tools.installers.go_installer import INSTALL_RECIPES as GO_R
        from xscan.tools.installers.universal import _NODE_RECIPES, _PYTHON_RECIPES
        from xscan.tools.installers.go_installer import GoInstaller
        from xscan.config.defaults import XSCAN_HOME
        go_installer = GoInstaller()
        table = Table(box=box.SIMPLE_HEAD, header_style="bold blue", padding=(0, 1))
        table.add_column("Tool", style="cyan", min_width=18)
        table.add_column("Type", min_width=8)
        table.add_column("Description", min_width=36)
        table.add_column("Installed", min_width=10)
        for name_t, recipe in GO_R.items():
            installed = "[green]yes[/green]" if go_installer.is_installed(name_t) else "[dim]no[/dim]"
            table.add_row(name_t, "go", recipe["description"], installed)
        for name_t, recipe in _PYTHON_RECIPES.items():
            if "git_url" in recipe:
                installed_path = XSCAN_HOME / "tools" / name_t
                installed = "[green]yes[/green]" if installed_path.exists() else "[dim]no[/dim]"
                table.add_row(name_t, "python", recipe.get("description", ""), installed)
        for name_t, recipe in _NODE_RECIPES.items():
            tools_dir = XSCAN_HOME / "tools" / name_t
            artifacts = recipe.get("artifacts", [])
            built = any((tools_dir / a).exists() for a in artifacts)
            installed = "[green]yes[/green]" if built else "[dim]no[/dim]"
            table.add_row(name_t, "node", recipe.get("description", ""), installed)
        _con.print(table)
        _con.print("\n[dim]Install by name or GitHub URL:[/dim]")
        _con.print("  [cyan]xscan install katana[/cyan]")
        _con.print("  [cyan]xscan install https://github.com/s0md3v/XSStrike.git[/cyan]\n")
        return

    if not tools:
        _con.print("[red]Provide tool name(s) or use --list.[/red]\n")
        raise typer.Exit(1)

    _con.print()
    for tool_name in tools:
        _con.print(f"[bold]Installing[/bold] [cyan]{tool_name}[/cyan]...")
        result = installer.install(
            tool_name,
            progress_cb=lambda msg: _con.print(f"  [dim]{msg}[/dim]"),
        )
        if result.success:
            detail = result.note or result.binary_path or result.install_dir
            _con.print(f"  [green]OK[/green]  {result.tool_name}  [dim]{detail}[/dim]\n")
        else:
            _con.print(f"  [red]FAIL[/red]  {result.error}\n")


# ===========================================================================
# xscan skills
# ===========================================================================

@app.command("skills")
def cmd_skills(
    subcommand: str = typer.Argument("list", help="list | show | install | search"),
    name: Optional[str] = typer.Argument(None, help="Skill name or file path."),
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Search skills by tag."),
) -> None:
    """
    Manage XScan skill packs.

    Skills are Markdown knowledge files injected into Ollama context
    during candidate analysis. They make Ollama more accurate for
    specific frameworks and attack patterns.

    \b
    Sub-commands:
      list                 List all skills
      show <name>          Show a skill's content
      install <path.md>    Install a skill from a Markdown file
      search               Search skills by tag or keyword

    \b
    Examples:
      xscan skills list
      xscan skills show jquery
      xscan skills show dom-xss
      xscan skills install ~/my-skill.md
      xscan skills search --query react
    """
    from xscan.skills import skill_manager
    skill_manager.load_all()
    sub = subcommand.lower()

    # ------------------------------------------------------------------
    if sub == "list":
        skills = skill_manager.list()
        if not skills:
            _con.print("\n[dim]No skills found.[/dim]\n")
            return
        _con.print("\n[bold]Skills[/bold]\n")
        table = Table(box=box.SIMPLE_HEAD, header_style="bold blue", padding=(0, 1))
        table.add_column("Name", style="cyan", min_width=22)
        table.add_column("Category", min_width=12)
        table.add_column("Tags")
        for s in skills:
            table.add_row(s.name, s.category, "  ".join(s.tags[:5]))
        _con.print(table)
        _con.print(
            f"\n[dim]{len(skills)} skills loaded.  "
            "User skills: [cyan]~/.xscan/skills/[/cyan][/dim]\n"
        )

    # ------------------------------------------------------------------
    elif sub == "show":
        if not name:
            _con.print("[red]Provide a skill name.[/red]  Example: xscan skills show jquery\n")
            raise typer.Exit(1)
        skill = skill_manager.get(name)
        if not skill:
            available = [s.name for s in skill_manager.list()]
            _con.print(f"[red]Skill not found:[/red] {name!r}\n"
                       f"Available: {', '.join(available)}\n")
            raise typer.Exit(1)
        _con.print()
        _con.print(Panel(
            skill.content,
            title=f"[cyan]{skill.display_name}[/cyan]  "
                  f"[dim]({skill.category}  tags: {', '.join(skill.tags)})[/dim]",
            expand=False,
        ))

    # ------------------------------------------------------------------
    elif sub == "install":
        if not name:
            _con.print("[red]Provide a skill file path.[/red]  "
                       "Example: xscan skills install ~/my-skill.md\n")
            raise typer.Exit(1)
        path = Path(name).expanduser()
        if not path.exists():
            _con.print(f"[red]File not found:[/red] {path}\n")
            raise typer.Exit(1)
        skill = skill_manager.install(path)
        _con.print(f"\n[green]Installed:[/green] [cyan]{skill.name}[/cyan]  "
                   f"[dim]tags: {', '.join(skill.tags)}[/dim]\n")

    # ------------------------------------------------------------------
    elif sub == "search":
        q = query or name or ""
        if not q:
            _con.print("[red]Provide a search query.[/red]  "
                       "Example: xscan skills search --query jquery\n")
            raise typer.Exit(1)
        results = skill_manager.for_context(
            techs=[q], context=q, category=q
        )
        if not results:
            _con.print(f"\n[dim]No skills matched '{q}'.[/dim]\n")
            return
        _con.print(f"\n[bold]Skills matching '{q}':[/bold]\n")
        for s in results:
            _con.print(f"  [cyan]{s.name:<22}[/cyan]  [dim]{', '.join(s.tags)}[/dim]")
        _con.print()

    else:
        _con.print(f"[red]Unknown sub-command:[/red] {subcommand}\n"
                   "Available: [cyan]list  show  install  search[/cyan]\n")
        raise typer.Exit(1)


# ===========================================================================
# xscan --fix  (also available as `xscan fix`)
# ===========================================================================

def _run_fix() -> None:
    """Run health checks and attempt repairs."""
    from xscan.services.doctor import DoctorService

    _con.print()
    _con.print("[bold cyan]XScan Environment Check[/bold cyan]\n")

    service = DoctorService()
    report  = service.run(fix=False)  # report only — do not auto-install

    for result in report.results:
        icon = "[green]ok [/green]" if result.ok else "[red]ERR[/red]"
        _con.print(f"  {icon}  [cyan]{result.name:<18}[/cyan]  {result.detail}")
        if not result.ok and result.fix_available:
            _con.print(f"         [dim]Fix: {result.fix_description}[/dim]")

    _con.print()
    if report.all_ok:
        _con.print("[green]Environment is healthy.[/green]\n")
    else:
        _con.print(
            "[yellow]Some checks failed.[/yellow]  "
            "Run [cyan]xscan install katana httpx dalfox subfinder ffuf[/cyan] "
            "to install missing tools.\n"
        )


@app.command("fix", hidden=True)
def cmd_fix_alias() -> None:
    """Alias for xscan --fix."""
    _run_fix()


# ===========================================================================
# Secondary commands (available but not in the primary surface)
# ===========================================================================

@app.command("models")
def cmd_models(
    subcommand: Optional[str] = typer.Argument(None),
    name: Optional[str] = typer.Argument(None),
) -> None:
    """
    Manage local Ollama models.

    \b
    Usage:  xscan models list | use MODEL | test [MODEL]
    """
    from xscan.llm.providers.ollama import OllamaProvider
    sub = (subcommand or "list").lower()
    provider = OllamaProvider()

    if sub == "list":
        status = provider.status_dict()
        if not status.get("reachable"):
            _con.print("[red]Ollama not reachable.[/red]  Run: [cyan]ollama serve[/cyan]\n")
            raise typer.Exit(1)
        ver = f"  [dim]v{status['version']}[/dim]" if status.get("version") else ""
        _con.print(f"\n[bold]Ollama[/bold]{ver}  [green]running[/green]\n")
        table = Table(box=box.SIMPLE_HEAD, header_style="bold blue", padding=(0, 1))
        table.add_column("Model", style="cyan", min_width=26)
        table.add_column("Size", justify="right", min_width=8)
        table.add_column("Status", min_width=10)
        for m in status.get("models", []):
            st = "[green]loaded[/green]" if m.get("running") else "[dim]available[/dim]"
            table.add_row(m["name"], m.get("size_human", ""), st)
        _con.print(table)
        _con.print()

    elif sub == "use":
        if not name:
            _con.print("[red]Provide a model name.[/red]\n")
            raise typer.Exit(1)
        from xscan.services.models import ModelService
        ModelService().use(name)
        _con.print(f"\n[green]OK[/green]  Active model: [cyan]{name}[/cyan]\n")

    elif sub == "test":
        model = name or provider.active_model()
        _con.print(f"\nTesting [cyan]{model}[/cyan] ...  [dim](Ctrl+C to cancel)[/dim]")
        try:
            ok, resp = provider.test_generate(model)
        except KeyboardInterrupt:
            _con.print("\n[yellow]Cancelled.[/yellow]")
            raise typer.Exit(130)
        if ok:
            _con.print(f"[green]OK[/green]  {resp[:100]}\n")
        else:
            _con.print(f"[red]FAIL[/red]  {resp}\n")
            raise typer.Exit(1)


@app.command("scan", rich_help_panel="Other", hidden=True)
def cmd_scan_alias(
    target: str  = typer.Argument(...),
    profile: str = typer.Option("balanced", "--profile", "-p"),
    verbose: bool= typer.Option(False, "--verbose", "-v"),
    quiet: bool  = typer.Option(False, "--quiet", "-q"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    spa: bool    = typer.Option(False, "--spa"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Alias for 'xss'. Use: xscan xss <target>"""
    cmd_xss(
        target=target, profile=profile, verbose=verbose,
        debug=False, quiet=quiet, json_out=False,
        no_llm=no_llm, spa=spa, output=output,
    )


@app.command("version", rich_help_panel="Other")
def cmd_version() -> None:
    """Show version info."""
    import platform
    try:
        from xscan import __version__
    except ImportError:
        __version__ = "dev"
    _con.print()
    _con.print(Panel(
        f"[bold cyan]XScan[/bold cyan]  [yellow]{__version__}[/yellow]\n\n"
        f"Python    {sys.version.split()[0]}\n"
        f"Platform  {platform.system()} {platform.release()}",
        title="Version", expand=False,
    ))


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        _con.print("\n[yellow]Interrupted.[/yellow]")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
