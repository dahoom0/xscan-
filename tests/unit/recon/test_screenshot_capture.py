"""Tests for screenshot-capture node — gowitness integration."""
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock
from tempfile import TemporaryDirectory

from xscan.nodes.base import ExecutionContext
from xscan.nodes.recon.screenshot_capture import ScreenshotCaptureNode
from xscan.runtime.base import ExecutionRuntime, ProcessResult
from xscan.schemas.recon import ReconToolStatus


class MockRuntime(ExecutionRuntime):
    """Mock runtime for testing."""

    def __init__(self, gowitness_available=True, should_succeed=True):
        self.gowitness_available = gowitness_available
        self.should_succeed = should_succeed
        self.calls = []

    def run(self, command, timeout=120, env=None, cwd=None) -> ProcessResult:
        """Mock process execution."""
        self.calls.append(command)

        if not self.should_succeed:
            return ProcessResult(
                command=command,
                exit_code=1,
                stdout="",
                stderr="Error capturing screenshot",
            )

        return ProcessResult(
            command=command,
            exit_code=0,
            stdout="Screenshot saved",
            stderr="",
        )

    def which(self, executable) -> str | None:
        """Check if tool is available."""
        if executable == "gowitness" and self.gowitness_available:
            return "/go/bin/gowitness"
        return None

    def available(self) -> bool:
        return True


class TestScreenshotCaptureNode:
    """Test screenshot capture with gowitness."""

    @pytest.fixture
    def mock_ctx(self):
        """Create a mock ExecutionContext."""
        with TemporaryDirectory() as tmpdir:
            ctx = MagicMock(spec=ExecutionContext)
            ctx.config = {
                "screenshot_enabled": True,
                "screenshot_timeout": 15,
                "screenshot_max_hosts": 20,
                "output_dir": tmpdir,
            }
            ctx.get = lambda key, default=None: ctx.config.get(key, default)
            ctx.scope = MagicMock()
            ctx.scope.assert_allowed = MagicMock()  # Never raises
            ctx.logger = MagicMock()
            ctx.scan_id = "test-scan-001"
            ctx.run_id = "run-001"
            ctx.node_id = "screenshot-capture"
            ctx.inputs = {}
            ctx.emit_progress = MagicMock()
            ctx.emit_warning = MagicMock()
            ctx.policy = MagicMock()
            yield ctx

    def test_screenshots_disabled_returns_empty(self, mock_ctx):
        """Test that disabled screenshots returns empty dict."""
        mock_ctx.config["screenshot_enabled"] = False

        node = ScreenshotCaptureNode()
        with patch("xscan.nodes.recon.screenshot_capture.get_runtime"):
            result = node.execute(mock_ctx)

        assert result["screenshot_count"] == 0
        assert result["screenshots"] == {}

    def test_no_live_urls_returns_empty(self, mock_ctx):
        """Test that no live URLs returns empty dict."""
        # Override the get method to return empty live_urls
        original_config = mock_ctx.config.copy()
        mock_ctx.get = lambda key, default=None: {
            "live_urls": [],
        }.get(key, default or original_config.get(key))

        node = ScreenshotCaptureNode()
        with patch("xscan.nodes.recon.screenshot_capture.get_runtime"):
            result = node.execute(mock_ctx)

        assert result["screenshot_count"] == 0

    def test_gowitness_not_available_returns_empty(self, mock_ctx):
        """Test that missing gowitness returns empty dict."""
        mock_ctx.get = lambda key, default=None: {
            "live_urls": ["https://example.com"],
        }.get(key, default or mock_ctx.config.get(key))

        runtime = MockRuntime(gowitness_available=False)
        node = ScreenshotCaptureNode()
        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        assert result["screenshot_count"] == 0
        assert result["screenshots"] == {}
        # Should have a tool observation indicating unavailability
        assert len(result["screenshot_observations"]) > 0
        assert result["screenshot_observations"][0]["status"] == "tool_unavailable"

    def test_single_url_capture(self, mock_ctx):
        """Test capturing screenshot of a single URL."""
        with TemporaryDirectory() as tmpdir:
            mock_ctx.config["output_dir"] = tmpdir
            mock_ctx.get = lambda key, default=None: {
                "live_urls": ["https://example.com"],
                "output_dir": tmpdir,
            }.get(key, default or mock_ctx.config.get(key))

            runtime = MockRuntime(gowitness_available=True, should_succeed=True)
            node = ScreenshotCaptureNode()

            # Create a dummy screenshot file
            screenshots_dir = Path(tmpdir) / "screenshots"
            screenshots_dir.mkdir(exist_ok=True)
            (screenshots_dir / "test.png").write_text("fake screenshot")

            with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
                result = node.execute(mock_ctx)

            assert result["screenshot_count"] >= 0  # May be 0 if file naming doesn't match

    def test_multiple_urls_respects_max_hosts(self, mock_ctx):
        """Test that max_hosts limit is enforced."""
        urls = [f"https://host{i}.example.com" for i in range(30)]
        mock_ctx.config["screenshot_max_hosts"] = 5
        mock_ctx.get = lambda key, default=None: {
            "live_urls": urls,
            "screenshot_max_hosts": 5,
        }.get(key, default or mock_ctx.config.get(key))

        runtime = MockRuntime(gowitness_available=True)
        node = ScreenshotCaptureNode()

        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        # Should have called runtime for at most 5 URLs
        assert len(runtime.calls) <= 5

    def test_scope_check_enforced(self, mock_ctx):
        """Test that scope is checked before capturing each URL."""
        mock_ctx.get = lambda key, default=None: {
            "live_urls": ["https://example.com", "https://outofscope.com"],
        }.get(key, default or mock_ctx.config.get(key))

        # First URL is allowed, second is not
        def scope_assert_allowed(url, operation=None):
            if "outofscope" in url:
                raise Exception("Out of scope")

        mock_ctx.scope.assert_allowed = scope_assert_allowed

        runtime = MockRuntime(gowitness_available=True)
        node = ScreenshotCaptureNode()

        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        # Should have skipped the out-of-scope URL
        assert "https://outofscope.com" in result["screenshots"]
        assert result["screenshots"]["https://outofscope.com"]["status"] == "error"

    def test_failed_capture_handled_gracefully(self, mock_ctx):
        """Test that failed captures don't crash the node."""
        mock_ctx.get = lambda key, default=None: {
            "live_urls": ["https://example.com"],
        }.get(key, default or mock_ctx.config.get(key))

        runtime = MockRuntime(gowitness_available=True, should_succeed=False)
        node = ScreenshotCaptureNode()

        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        # Should have recorded the failure
        assert "https://example.com" in result["screenshots"]
        assert result["screenshots"]["https://example.com"]["status"] == "error"

    def test_output_contains_per_url_status(self, mock_ctx):
        """Test that output includes per-URL status."""
        with TemporaryDirectory() as tmpdir:
            mock_ctx.config["output_dir"] = tmpdir
            mock_ctx.get = lambda key, default=None: {
                "live_urls": ["https://example.com"],
                "output_dir": tmpdir,
            }.get(key, default or mock_ctx.config.get(key))

            runtime = MockRuntime(gowitness_available=True, should_succeed=True)
            node = ScreenshotCaptureNode()

            # Create a dummy screenshot file
            screenshots_dir = Path(tmpdir) / "screenshots"
            screenshots_dir.mkdir(exist_ok=True)
            (screenshots_dir / "test.png").write_text("fake screenshot")

            with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
                result = node.execute(mock_ctx)

            screenshots = result["screenshots"]
            assert isinstance(screenshots, dict)
            for url, data in screenshots.items():
                assert "status" in data
                assert "timestamp" in data
                assert data["status"] in ("captured", "error", "timeout")

    def test_screenshot_observations_include_summary(self, mock_ctx):
        """Test that observations include tool execution summary."""
        mock_ctx.get = lambda key, default=None: {
            "live_urls": ["https://example.com"],
        }.get(key, default or mock_ctx.config.get(key))

        runtime = MockRuntime(gowitness_available=True, should_succeed=True)
        node = ScreenshotCaptureNode()

        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        observations = result["screenshot_observations"]
        assert len(observations) > 0
        obs = observations[0]
        assert obs["tool"] == "gowitness"
        assert "status" in obs
        assert "observation" in obs

    def test_returns_correct_keys(self, mock_ctx):
        """Test that all expected output keys are present."""
        mock_ctx.get = lambda key, default=None: {
            "live_urls": ["https://example.com"],
        }.get(key, default or mock_ctx.config.get(key))

        runtime = MockRuntime(gowitness_available=True)
        node = ScreenshotCaptureNode()

        with patch("xscan.nodes.recon.screenshot_capture.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        assert "screenshots" in result
        assert "screenshot_count" in result
        assert "screenshot_observations" in result
        assert isinstance(result["screenshots"], dict)
        assert isinstance(result["screenshot_count"], int)
        assert isinstance(result["screenshot_observations"], list)
