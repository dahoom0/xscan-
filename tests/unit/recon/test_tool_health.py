"""Tests for tool-health node — pre-flight tool validation."""
import pytest
from unittest.mock import MagicMock, patch

from xscan.nodes.base import ExecutionContext
from xscan.nodes.recon.tool_health import ToolHealthNode
from xscan.runtime.base import ExecutionRuntime, ProcessResult
from xscan.schemas.tool import ToolStatus


class MockRuntime(ExecutionRuntime):
    """Mock runtime for testing."""

    def __init__(self, available_tools=None, versions=None):
        self.available_tools = available_tools or {}
        self.versions = versions or {}

    def run(self, command, timeout=120, env=None, cwd=None) -> ProcessResult:
        """Mock process execution."""
        # Extract tool name from command (either full path or just name)
        tool_name = command[0]
        if "/" in tool_name or "\\" in tool_name:
            tool_name = tool_name.split("/")[-1].split("\\")[-1].replace(".exe", "")
        
        for available_name in self.available_tools.keys():
            if available_name in tool_name:
                version = self.versions.get(available_name, "1.0.0")
                return ProcessResult(
                    command=command,
                    exit_code=0,
                    stdout=version,
                    stderr="",
                )
        
        return ProcessResult(
            command=command,
            exit_code=1,
            stdout="",
            stderr="not found",
        )

    def which(self, executable) -> str | None:
        """Check if tool is available."""
        return self.available_tools.get(executable)

    def available(self) -> bool:
        return True


class TestToolHealthNode:
    """Test tool health checking."""

    @pytest.fixture
    def mock_ctx(self):
        """Create a mock ExecutionContext."""
        ctx = MagicMock(spec=ExecutionContext)
        ctx.config = {
            "required_tools": ["subfinder", "assetfinder", "httpx"],
            "optional_tools": ["amass", "ffuf", "gowitness", "nuclei"],
        }
        ctx.get = lambda key, default=None: ctx.config.get(key, default or {}.get(key))
        ctx.logger = MagicMock()
        ctx.scan_id = "test-scan-001"
        ctx.run_id = "run-001"
        ctx.node_id = "tool-health"
        ctx.inputs = {}
        ctx.emit_progress = MagicMock()
        ctx.emit_warning = MagicMock()
        
        # Mock scope and policy
        ctx.scope = MagicMock()
        ctx.policy = MagicMock()
        
        return ctx

    def test_all_tools_available(self, mock_ctx):
        """Test when all required tools are available."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                "httpx": "/go/bin/httpx",
                "amass": "/go/bin/amass",
                "ffuf": "/go/bin/ffuf",
                "gowitness": "/go/bin/gowitness",
                "nuclei": "/go/bin/nuclei",
            },
            versions={
                "subfinder": "2.5.1",
                "assetfinder": "1.0.0",
                "httpx": "1.3.5",
                "amass": "3.24.1",
                "ffuf": "2.0.0",
                "gowitness": "3.0.0",
                "nuclei": "3.0.0",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        assert result["tool_count_available"] >= 3
        assert result["tool_count_missing"] == 0
        assert "subfinder" in result["available_tools"]
        assert "assetfinder" in result["available_tools"]
        assert "httpx" in result["available_tools"]

        assert result["tool_count_available"] >= 3
        assert result["tool_count_missing"] == 0
        assert "subfinder" in result["available_tools"]
        assert "assetfinder" in result["available_tools"]
        assert "httpx" in result["available_tools"]

    def test_missing_required_tool(self, mock_ctx):
        """Test when a required tool is missing."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                # assetfinder missing
                "httpx": "/go/bin/httpx",
            },
            versions={
                "subfinder": "2.5.1",
                "httpx": "1.3.5",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        assert "assetfinder" in result["missing_tools"]
        assert result["tool_count_missing"] >= 1

    def test_optional_tools_gracefully_missing(self, mock_ctx):
        """Test that missing optional tools don't cause warnings."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                "httpx": "/go/bin/httpx",
                # gowitness missing (optional)
            },
            versions={
                "subfinder": "2.5.1",
                "assetfinder": "1.0.0",
                "httpx": "1.3.5",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        # Should still have all required tools
        assert "subfinder" in result["available_tools"]
        assert "assetfinder" in result["available_tools"]
        assert "httpx" in result["available_tools"]

    def test_tool_status_dict_structure(self, mock_ctx):
        """Test that tool_status dict has correct structure."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                "httpx": "/go/bin/httpx",
            },
            versions={
                "subfinder": "2.5.1",
                "assetfinder": "1.0.0",
                "httpx": "1.3.5",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        tool_status = result["tool_status"]
        assert "subfinder" in tool_status
        assert tool_status["subfinder"]["status"] == "installed"
        assert "2.5.1" in tool_status["subfinder"]["version"]
        assert tool_status["subfinder"]["binary_path"] == "/go/bin/subfinder"

    def test_missing_tool_has_error_message(self, mock_ctx):
        """Test that missing tools include an error message."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                # httpx missing
            },
            versions={
                "subfinder": "2.5.1",
                "assetfinder": "1.0.0",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        tool_status = result["tool_status"]
        assert tool_status["httpx"]["status"] == "missing"
        assert "error" in tool_status["httpx"]
        assert len(tool_status["httpx"]["error"]) > 0

    def test_output_keys_present(self, mock_ctx):
        """Test that all expected output keys are present."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                "httpx": "/go/bin/httpx",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        assert "tool_status" in result
        assert "available_tools" in result
        assert "missing_tools" in result
        assert "tool_count_total" in result
        assert "tool_count_available" in result
        assert "tool_count_missing" in result

    def test_metrics_consistency(self, mock_ctx):
        """Test that count metrics are consistent."""
        runtime = MockRuntime(
            available_tools={
                "subfinder": "/go/bin/subfinder",
                "assetfinder": "/go/bin/assetfinder",
                "httpx": "/go/bin/httpx",
            }
        )

        node = ToolHealthNode()
        with patch("xscan.nodes.recon.tool_health.get_runtime", return_value=runtime):
            result = node.execute(mock_ctx)

        available = result["tool_count_available"]
        missing = result["tool_count_missing"]
        total = result["tool_count_total"]

        # Total should be sum of required (3) + optional (4) = 7
        # Available should be 3, Missing should be 4
        assert available + missing == total, f"available({available}) + missing({missing}) != total({total})"
        assert len(result["available_tools"]) == available
        assert len(result["missing_tools"]) == missing
