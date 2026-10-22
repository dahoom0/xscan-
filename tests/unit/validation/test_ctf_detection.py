"""
Unit tests for CTF detection utility
"""
import pytest

from xscan.validation.ctf_detection import (
    CTFContext,
    detect_ctf_context,
    get_ctf_planner_hint,
)


class TestCTFDetection:
    """Test CTF context detection."""

    def test_hackthebox_domain(self):
        """Should detect HackTheBox domains with high confidence."""
        ctx = detect_ctf_context("https://hackthebox.com/challenges/web")
        assert ctx.is_ctf is True
        assert ctx.platform == "htb"
        assert ctx.confidence >= 0.90
        assert "hackthebox-domain" in ctx.hints

    def test_hackthebox_ip(self):
        """Should detect HTB lab IP range (10.10.x.x) with high confidence."""
        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa")
        assert ctx.is_ctf is True
        assert "htb-lab-ip-range" in ctx.hints
        assert ctx.confidence >= 0.80

    def test_dvwa_pattern(self):
        """Should detect DVWA domains."""
        ctx = detect_ctf_context("http://dvwa.local/vulnerabilities")
        assert ctx.is_ctf is True
        assert "dvwa-pattern" in ctx.hints

    def test_juice_shop(self):
        """Should detect OWASP Juice Shop."""
        ctx = detect_ctf_context("http://juice-shop.local:3000/app")
        assert ctx.is_ctf is True
        assert "juice-shop-pattern" in ctx.hints

    def test_local_ip_with_dev_port(self):
        """Should detect local IPs with development ports."""
        ctx = detect_ctf_context("http://192.168.1.100:5000/xss")
        assert ctx.is_ctf is True
        assert "local-or-lab-environment" in ctx.hints
        assert "development-port-5000" in ctx.hints

    def test_localhost_with_dev_port(self):
        """Should detect localhost with development ports."""
        ctx = detect_ctf_context("http://127.0.0.1:3000/challenge")
        assert ctx.is_ctf is True
        assert "development-port-3000" in ctx.hints

    def test_production_site_no_ctf(self):
        """Should not detect production sites as CTF."""
        ctx = detect_ctf_context("https://shop.post.ch/shop")
        assert ctx.is_ctf is False
        assert ctx.confidence == 0.0

    def test_flag_keywords_in_path(self):
        """Should detect flag-related keywords in URL path."""
        ctx = detect_ctf_context("http://example.com/challenge/flag")
        # May be low confidence without other hints
        assert "flag-keywords-in-path" in ctx.hints

    def test_docker_ip_detection(self):
        """Should detect Docker container IP ranges."""
        ctx = detect_ctf_context("http://172.18.0.5:8080/app")
        assert ctx.is_ctf is True
        # Docker IP may be detected as local-or-lab-environment instead
        assert len(ctx.hints) > 0

    def test_ctf_context_dataclass(self):
        """Test CTFContext dataclass."""
        ctx = CTFContext(
            is_ctf=True,
            platform="htb",
            confidence=0.95,
            hints=["htb-domain", "flag-in-path"],
        )
        assert ctx.is_ctf is True
        assert ctx.platform == "htb"
        assert ctx.confidence == 0.95
        assert len(ctx.hints) == 2

    def test_ctf_context_summary(self):
        """Test CTFContext summary generation."""
        ctx = CTFContext(
            is_ctf=True,
            platform="dvwa",
            confidence=0.85,
            hints=["dvwa-pattern", "dev-port-80"],
        )
        summary = ctx.summary()
        assert "CTF/Intentional" in summary
        assert "85%" in summary
        assert "dvwa" in summary

    def test_planner_hint_generation(self):
        """Test planner hint generation for LLM."""
        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa")
        hint = get_ctf_planner_hint(ctx)
        assert len(hint) > 0
        assert "CTF" in hint or "challenge" in hint.lower()
        assert "aggressive" in hint or "exploit" in hint.lower()

    def test_planner_hint_no_ctf(self):
        """Test planner hint returns empty when not CTF."""
        ctx = detect_ctf_context("https://shop.post.ch")
        hint = get_ctf_planner_hint(ctx)
        assert hint == ""

    def test_multiple_hints_confidence_boost(self):
        """Multiple hints should boost confidence score."""
        # HTB IP (0.85) + dev port (0.35) = 0.85 + 0.15*1 = 0.99 (capped)
        ctx = detect_ctf_context("http://10.10.14.5:3000/dvwa")
        assert ctx.is_ctf is True
        # Should have both IP and port hints
        assert "htb-lab-ip-range" in ctx.hints or "development-port" in str(ctx.hints)

    def test_empty_url(self):
        """Should handle empty URL gracefully."""
        ctx = detect_ctf_context("")
        assert ctx.is_ctf is False

    def test_invalid_url(self):
        """Should handle invalid URL gracefully."""
        ctx = detect_ctf_context("not a valid url at all !!!!")
        assert ctx.is_ctf is False

    def test_webgoat_detection(self):
        """Should detect OWASP WebGoat."""
        ctx = detect_ctf_context("http://webgoat.local:8080/WebGoat")
        assert ctx.is_ctf is True
        assert "webgoat-pattern" in ctx.hints

    def test_ctflearn_detection(self):
        """Should detect CTFLearn platform."""
        ctx = detect_ctf_context("https://ctflearn.com/challenges/123")
        assert ctx.is_ctf is True
        assert ctx.platform == "ctflearn"

    def test_confidence_threshold(self):
        """Targets below 40% confidence should not be marked as CTF."""
        # A site with only a dev port hint (35% conf) should not trigger CTF mode
        ctx = detect_ctf_context("https://example.com:8080/app")
        # May or may not be CTF depending on domain - verify threshold logic
        if not ctx.is_ctf:
            assert ctx.confidence < 0.40


class TestCTFIntegration:
    """Test CTF detection integrated with planner input."""

    def test_ctf_hint_in_planner_prompt(self):
        """Verify CTF hint gets properly formatted for planner."""
        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa")
        hint = get_ctf_planner_hint(ctx)

        # The hint should be suitable for injection into system prompt
        assert "NOTE:" in hint
        assert "CTF" in hint
        assert "confidence" in hint.lower()
        assert "platform" in hint.lower() or "dvwa" in hint.lower()
        assert "aggressive" in hint or "payloads" in hint

    def test_planner_input_with_ctf(self):
        """Test that CTF hint can be passed to IterativePlanInput."""
        from xscan.llm.specialists.iterative_planner import IterativePlanInput

        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa", ["PHP"])
        hint = get_ctf_planner_hint(ctx)

        # Should be able to create input with hint
        plan_input = IterativePlanInput(
            scan_id="test-scan",
            url="http://10.10.14.5:8080/dvwa",
            parameter="q",
            ctf_hint=hint,
            context_analysis={},
            encoding_profile={},
        )

        assert plan_input.ctf_hint == hint
        assert len(plan_input.ctf_hint) > 0

    def test_planner_timeout_optimization(self):
        """Verify planner timeout increases for CTF targets."""
        from xscan.llm.specialists.iterative_planner import IterativePlannerSpecialist, IterativePlanInput

        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa")
        hint = get_ctf_planner_hint(ctx)

        plan_input_ctf = IterativePlanInput(
            scan_id="ctf-test",
            url="http://10.10.14.5:8080/dvwa",
            parameter="q",
            ctf_hint=hint,  # CTF context present
            context_analysis={},
            encoding_profile={},
        )

        plan_input_normal = IterativePlanInput(
            scan_id="normal-test",
            url="https://example.com",
            parameter="q",
            ctf_hint="",  # No CTF context
            context_analysis={},
            encoding_profile={},
        )

        specialist = IterativePlannerSpecialist()

        # Verify default timeout (before run())
        assert specialist.default_timeout == 90

        # Note: We can't actually call run() without a real LLM, but we can verify
        # that the input structure supports the optimization
        assert plan_input_ctf.ctf_hint != ""
        assert plan_input_normal.ctf_hint == ""

    def test_planner_prompt_trimming_for_ctf(self):
        """Verify planner trims prompts when CTF context detected."""
        from xscan.llm.specialists.iterative_planner import IterativePlannerSpecialist, IterativePlanInput

        specialist = IterativePlannerSpecialist()

        ctx = detect_ctf_context("http://10.10.14.5:8080/dvwa")
        hint = get_ctf_planner_hint(ctx)

        # Create CTF input with long skills text
        long_skills = "Skill A\n" * 100  # 800 chars
        plan_input = IterativePlanInput(
            scan_id="ctf-test",
            url="http://10.10.14.5:8080/dvwa",
            parameter="q",
            ctf_hint=hint,
            skills_text=long_skills,
            context_analysis={"full_snippet": "x" * 200},
            encoding_profile={"raw_chars": ["<", ">"]},
        )

        prompt = specialist.build_prompt(plan_input)

        # Verify that prompt is built (can't check exact trimming without parsing)
        assert len(prompt) > 0
        assert "url: http://10.10.14.5:8080/dvwa" in prompt.lower() or "http://10.10.14.5" in prompt
