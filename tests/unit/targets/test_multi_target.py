"""
Multi-target scanning tests
===========================
Cover the URL-file loader and the sequential multi-target runner that backs
``xscan xss --urls <file>`` / ``xscan xss --stdin``.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from xscan.cli import multi_target as mt
from xscan.targets import TargetLoader

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeNodeResult:
    def __init__(self, output: dict) -> None:
        self.output = output


class _FakeRun:
    def __init__(self, outputs: list[dict]) -> None:
        self.node_results = {f"n{i}": _FakeNodeResult(o) for i, o in enumerate(outputs)}


@pytest.fixture()
def urls_file(tmp_path: Path) -> Path:
    p = tmp_path / "targets.txt"
    p.write_text(
        "# a comment\n"
        "https://a.example.com/\n"
        "\n"
        "https://b.example.com/x?q=1\n"
        "https://a.example.com/   # duplicate\n"
        "not a url at all\n",
        encoding="utf-8",
    )
    return p


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def test_load_from_file_dedupes_and_skips_comments(urls_file: Path) -> None:
    messages: list[str] = []
    ts = TargetLoader(progress_cb=messages.append).load_from_file(
        str(urls_file), assessment_id="T1"
    )

    # 4 lines were "valid-ish": a, b, a (dup), "not a url at all" (invalid).
    urls = [t.normalized_url for t in ts]
    assert urls == ["https://a.example.com/", "https://b.example.com/x?q=1"]
    assert len(ts.valid_targets) == 2
    assert len(ts.blocked_targets) == 0
    # Progress message reports the deduplicated count, not the raw line count.
    assert any("Loaded 2 targets" in m for m in messages)


def test_load_from_file_counts_track_deduped_targets(urls_file: Path) -> None:
    ts = TargetLoader().load_from_file(str(urls_file), assessment_id="T1")
    # target_id is deterministic on the normalized URL
    assert len({t.target_id for t in ts}) == len(ts) == 2


def test_to_queue_only_includes_valid_targets(urls_file: Path) -> None:
    loader = TargetLoader()
    ts = loader.load_from_file(str(urls_file), assessment_id="T1")
    queue = loader.to_queue(ts)
    assert queue.total_targets == 2
    assert queue.is_complete() is False


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------

def test_multi_target_scans_each_target_sequentially(
    urls_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_inputs: list[str] = []

    def fake_execute(self, *, scan_id, inputs):  # noqa: ANN001, ANN201
        seen_inputs.append(inputs["target_url"])
        return _FakeRun([
            {"fused_candidates": [{"param": "q"}], "finding_count": 1},
        ])

    monkeypatch.setattr(mt.DAGEngine, "execute", fake_execute)

    cap = Console(record=True, width=120)
    mt.run_multi_target_scan(
        scan_id="MT123456",
        urls_file=str(urls_file),
        use_stdin=False,
        profile="fast",
        wf_name="xss-fast",
        verbose=False,
        debug=False,
        quiet=False,
        json_out=False,
        no_llm=True,
        spa=False,
        output=None,
        console=cap,
    )

    # Every target was scanned, once, in file order.
    assert seen_inputs == [
        "https://a.example.com/",
        "https://b.example.com/x?q=1",
    ]
    text = cap.export_text()
    assert "Multi-Target Scan Complete" in text
    assert "Total Candidates" in text
    assert "Total Findings" in text


def test_multi_target_quiet_summary(
    urls_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        mt.DAGEngine,
        "execute",
        lambda self, *, scan_id, inputs: _FakeRun([{"candidates": [1, 2]}]),
    )

    cap = Console(record=True, width=120)
    mt.run_multi_target_scan(
        scan_id="MTQUIET1",
        urls_file=str(urls_file),
        use_stdin=False,
        profile="fast",
        wf_name="xss-fast",
        verbose=False,
        debug=False,
        quiet=True,
        json_out=False,
        no_llm=True,
        spa=False,
        output=None,
        console=cap,
    )
    text = cap.export_text()
    assert "2/2 targets" in text
    assert "4 candidates" in text


def test_multi_target_json_output(
    urls_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    monkeypatch.setattr(
        mt.DAGEngine,
        "execute",
        lambda self, *, scan_id, inputs: _FakeRun([{"finding_count": 0}]),
    )

    cap = Console(record=True, width=120)
    mt.run_multi_target_scan(
        scan_id="MTJSON001",
        urls_file=str(urls_file),
        use_stdin=False,
        profile="fast",
        wf_name="xss-fast",
        verbose=False,
        debug=False,
        quiet=False,
        json_out=True,
        no_llm=True,
        spa=False,
        output=None,
        console=cap,
    )
    data = json.loads(cap.export_text())
    assert data["scan_id"] == "MTJSON001"
    assert data["targets"]["total"] == 2
    assert len(data["target_results"]) == 2


def test_cli_dispatch_urls_flag_invokes_multi_target(
    urls_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from xscan.cli.main import app as cli_app

    calls: dict = {}

    def fake_run(**kwargs):  # noqa: ANN003, ANN202
        calls.update(kwargs)

    monkeypatch.setattr(mt, "run_multi_target_scan", fake_run)

    result = CliRunner().invoke(cli_app, ["xss", "--urls", str(urls_file), "--no-llm"])
    assert result.exit_code == 0, result.output
    assert calls["urls_file"] == str(urls_file)
    assert calls["use_stdin"] is False
    assert calls["wf_name"] == "xss-balanced"


def test_cli_dispatch_no_target_exits_nonzero() -> None:
    from typer.testing import CliRunner

    from xscan.cli.main import app as cli_app

    result = CliRunner().invoke(cli_app, ["xss"])
    assert result.exit_code == 1
    assert "No target" in result.output


def test_multi_target_failed_target_is_recorded(
    urls_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self, *, scan_id, inputs):  # noqa: ANN001, ANN201
        raise RuntimeError("connection refused")

    monkeypatch.setattr(mt.DAGEngine, "execute", boom)

    cap = Console(record=True, width=120)
    mt.run_multi_target_scan(
        scan_id="MTFAIL001",
        urls_file=str(urls_file),
        use_stdin=False,
        profile="fast",
        wf_name="xss-fast",
        verbose=False,
        debug=False,
        quiet=False,
        json_out=True,
        no_llm=True,
        spa=False,
        output=None,
        console=cap,
    )
    import json
    data = json.loads(cap.export_text())
    assert data["targets"]["failed"] == 2
    assert all(r["status"] == "failed" for r in data["target_results"])
