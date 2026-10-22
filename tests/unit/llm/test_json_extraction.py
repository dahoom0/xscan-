"""
Tests for SpecialistBase._extract_json and the retry contract.

Real-world failure this pins: a local model replies to the iterative planner
with prose / fenced / truncated output, the single parse attempt fails, and
the scan falls back to the heuristic planner with
"No valid JSON found in LLM response". Every shape below must now parse.
"""
from __future__ import annotations

import json

import pytest

from xscan.errors import SpecialistOutputError
from xscan.llm.specialists.base import SpecialistBase, _balance_json


class TestCleanJson:
    def test_plain_object(self):
        assert SpecialistBase._extract_json('{"a": 1}') == {"a": 1}

    def test_prose_wrapped(self):
        text = 'Sure! Here is my plan:\n{"candidates": []}\nHope this helps.'
        assert SpecialistBase._extract_json(text) == {"candidates": []}

    def test_fenced_json(self):
        text = '```json\n{"a": 1}\n```'
        assert SpecialistBase._extract_json(text) == {"a": 1}

    def test_think_blocks_stripped(self):
        text = '<think>let me reason...</think>\n{"a": 1}'
        assert SpecialistBase._extract_json(text) == {"a": 1}

    def test_top_level_array_rejected(self):
        with pytest.raises(SpecialistOutputError):
            SpecialistBase._extract_json('[1, 2, 3]')


class TestRepairedJson:
    def test_trailing_comma(self):
        assert SpecialistBase._extract_json('{"a": [1, 2,], "b": 3,}') == {"a": [1, 2], "b": 3}

    def test_smart_quotes(self):
        text = '{"analysis": “done”}'
        assert SpecialistBase._extract_json(text) == {"analysis": "done"}

    def test_prose_with_braces_in_text(self):
        # Braces inside prose before the real object must not break extraction
        text = 'The {short} version:\n{"ok": true}'
        assert SpecialistBase._extract_json(text) == {"ok": True}


class TestTruncatedJson:
    def test_balance_completes_nested_object(self):
        assert json.loads(_balance_json('{"candidates": [{"payload": "x"}')) == \
            {"candidates": [{"payload": "x"}]}

    def test_balance_closes_open_string(self):
        assert json.loads(_balance_json('{"analysis": "still typ')) == \
            {"analysis": "still typ"}

    def test_truncated_mid_candidates(self):
        text = '{"analysis": "none", "candidates": [{"priority": 1, "payload": ";alert(1)//"'
        data = SpecialistBase._extract_json(text)
        assert data["analysis"] == "none"
        assert data["candidates"][0]["payload"] == ";alert(1)//"

    def test_truncated_with_escape(self):
        text = '{"a": "line\\'
        data = SpecialistBase._extract_json(text)
        assert "a" in data


class _TestSpecialist(SpecialistBase):
    """Concrete minimal specialist for exercising the run() contract."""

    specialist_name = "test"

    def __init__(self, parse) -> None:
        self._parse = parse
        self.specialist_name = "test"
        self.system_prompt = "sys"
        self.default_timeout = 1
        self.default_max_tokens = 10
        self.json_retries = 1

    def build_prompt(self, input_data):
        return "task"

    def parse_output(self, raw_text: str):
        return self._parse(raw_text)


class TestRetryContract:
    def test_retry_sends_corrective_prompt(self, monkeypatch):
        """A broken first reply triggers one corrective follow-up with the raw text echoed."""
        from xscan.schemas.llm import SpecialistInput, SpecialistOutput

        def parse(raw: str):
            data = json.loads(raw)
            return _Out(specialist="test", reasoning=data.get("candidates") and "x" or "ok")

        specialist = _TestSpecialist(parse)

        prompts: list[str] = []
        replies = [
            "I think the plan is good but let me explain instead of JSON.",
            '{"candidates": []}',
        ]

        class _Resp:
            def __init__(self, text: str) -> None:
                self.raw_text = text
                self.success = True

        def fake_complete(request):
            prompts.append(request.user_prompt)
            return _Resp(replies[len(prompts) - 1])

        monkeypatch.setattr(
            "xscan.llm.specialists.base.get_gateway",
            lambda: type("G", (), {"complete": staticmethod(fake_complete)}),
        )

        class _In(SpecialistInput):
            pass

        class _Out(SpecialistOutput):
            specialist: str = "test"

        out = specialist.run(_In(scan_id="S"))
        assert out.raw_response == '{"candidates": []}'
        assert len(prompts) == 2
        assert "Your previous reply was not valid JSON" in prompts[1]
        assert "explain instead of JSON" in prompts[1]

    def test_no_retry_after_exhaustion(self, monkeypatch):
        """When every attempt fails to parse, the error keeps the raw text."""
        from xscan.schemas.llm import SpecialistInput

        def parse(raw: str):
            raise SpecialistOutputError("No valid JSON found in LLM response", raw=raw)

        specialist = _TestSpecialist(parse)

        calls: list[int] = []

        class _Resp:
            def __init__(self) -> None:
                self.raw_text = "not json at all"
                self.success = True

        def fake_complete(request):
            calls.append(1)
            return _Resp()

        monkeypatch.setattr(
            "xscan.llm.specialists.base.get_gateway",
            lambda: type("G", (), {"complete": staticmethod(fake_complete)}),
        )

        class _In(SpecialistInput):
            pass

        with pytest.raises(SpecialistOutputError) as exc:
            specialist.run(_In(scan_id="S"))
        assert len(calls) == 2          # initial + 1 retry
        assert exc.value.context["raw"].startswith("not json")
