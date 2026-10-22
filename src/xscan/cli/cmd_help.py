"""
xscan help
==========
Dedicated help command backed by the centralised Help Engine.

Supported forms:

  xscan help                          → guided "What are you trying to do?" menu
  xscan help <topic>                  → render documentation for topic
  xscan help search "<query>"         → full-text search across docs
  xscan help topics                   → list every available topic
  xscan help getting-started          → specific topic (examples)
  xscan help concepts/dag             → path-style topic
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from xscan.help.engine import HelpEngine

app = typer.Typer(
    name="help",
    help="Show detailed help and documentation.",
    invoke_without_command=True,
    no_args_is_help=False,
)

_console = Console()
_engine: Optional[HelpEngine] = None


def _get_engine() -> HelpEngine:
    global _engine
    if _engine is None:
        _engine = HelpEngine()
    return _engine


# ---------------------------------------------------------------------------
# Main callback — handles `xscan help`, `xscan help <topic>`, and
# `xscan help search "<query>"`
# ---------------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def help_main(
    ctx: typer.Context,
    topic: Optional[str] = typer.Argument(
        default=None,
        help=(
            "Topic to read, or 'search' to run a query. "
            "Examples: getting-started, concepts/dag, workflows, troubleshooting"
        ),
    ),
    query: Optional[str] = typer.Argument(
        default=None,
        help=(
            "Search query (only used when TOPIC is 'search'). "
            "Example: xscan help search \"how do I add a crawler\""
        ),
    ),
) -> None:
    """
    Show documentation for a topic, run a search, or display the guided menu.

    \b
    Usage:
      xscan help                          Guided topic menu
      xscan help <topic>                  Read a topic
      xscan help search "<query>"         Search documentation
      xscan help topics                   List all topics

    \b
    Examples:
      xscan help getting-started
      xscan help concepts/dag
      xscan help workflows
      xscan help troubleshooting
      xscan help search "how do I add a crawler"
      xscan help search "switch LLM"
    """
    engine = _get_engine()

    # If a sub-command was invoked, Typer handles it; skip the callback body.
    if ctx.invoked_subcommand is not None:
        return

    # `xscan help` → guided menu
    if topic is None:
        raise SystemExit(engine.show_guided_menu())

    # `xscan help topics` → full topic list
    if topic.lower() == "topics":
        raise SystemExit(engine.show_topic_list())

    # `xscan help search "<query>"` → free-text search
    if topic.lower() == "search":
        if not query:
            _console.print(
                "\n[red]Error:[/red] Provide a search query.\n"
                "Example: [cyan]xscan help search \"how do I add a crawler\"[/cyan]\n"
            )
            raise SystemExit(1)
        raise SystemExit(engine.show_search(query))

    # `xscan help <topic>` → render the topic
    raise SystemExit(engine.show_topic(topic))


# ---------------------------------------------------------------------------
# xscan help search (also reachable as a sub-command for discoverability)
# ---------------------------------------------------------------------------

@app.command("search")
def help_search(
    query: str = typer.Argument(..., help="Search query, e.g. \"how do I add a crawler\""),
) -> None:
    """Search XScan documentation for a keyword or question."""
    engine = _get_engine()
    raise SystemExit(engine.show_search(query))


# ---------------------------------------------------------------------------
# xscan help topics
# ---------------------------------------------------------------------------

@app.command("topics")
def help_topics() -> None:
    """List every available help topic."""
    engine = _get_engine()
    raise SystemExit(engine.show_topic_list())
