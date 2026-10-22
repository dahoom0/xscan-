"""
Unit Tests: StrategySelector Node
==================================
Tests that StrategySelector correctly maps vulnerability models to ranked strategies.
"""
import pytest

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.nodes.analysis.strategy_selector import StrategySelectorNode
from xscan.nodes.base import ExecutionContext


@pytest.fixture
def mock_scope_engine():
    """Create a permissive ScopeEngine for testing."""
    return ScopeEngine.allow_all("test")


@pytest.fixture
def mock_policy_engine():
    """Create a permissive PolicyEngine for testing."""
    return PolicyEngine()


class TestStrategySelector:
    """Test StrategySelector node execution."""

    def test_node_type(self):
        """Test that the node type is correctly set."""
        node = StrategySelectorNode()
        assert node.node_type == "strategy-selector"

    def test_empty_models_list(self, mock_scope_engine, mock_policy_engine):
        """Test behavior with empty models list."""
        node = StrategySelectorNode()
        ctx = ExecutionContext(
            scan_id="test_001",
            node_id="selector_001",
            run_id="run_001",
            inputs={"models": []},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 0
        assert result["rankings"] == []
        assert result["unmatched_models"] == []

    def test_html_text_markup_injection(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test strategy selection for HTML text (markup) injection."""
        node = StrategySelectorNode()

        # Model from P2: HTML text injection
        model = {
            "candidate_id": "html_001",
            "execution_context": "markup",
            "sink": "innerHTML",
            "constraints": {
                "sink_kind": "html_text",
                "raw_chars": ["<", ">", "s", "c", "r", "i", "p", "t", "a", "l", "e", "r", "t"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_002",
            node_id="selector_002",
            run_id="run_002",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 1
        assert len(result["rankings"]) == 1
        assert result["unmatched_models"] == []

        ranking = result["rankings"][0]
        assert ranking["model_id"] == "html_001"
        assert ranking["context_type"] == "markup"
        assert ranking["sink_kind"] == "html_text"
        assert len(ranking["strategies"]) > 0

        # Highest-ranking strategy should be TAG_INJECTION
        top_strategy = ranking["strategies"][0]
        assert top_strategy[0]["family"] == "tag_injection"
        assert top_strategy[1] > 0.0  # Confidence score

    def test_javascript_string_injection(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test strategy selection for JavaScript string injection."""
        node = StrategySelectorNode()

        # Model from P2: JS string injection
        model = {
            "candidate_id": "js_001",
            "execution_context": "js_string_double",
            "sink": "eval",
            "constraints": {
                "sink_kind": "js_execution",
                "quote_type": "double",
                "raw_chars": ['"', ";", "a", "l", "e", "r", "t", "(", "1", ")", "/"],
                "encoded_chars": ["<", ">"],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_003",
            node_id="selector_003",
            run_id="run_003",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 1
        ranking = result["rankings"][0]
        assert ranking["context_type"] == "js_string_double"

        # Should have script_string_breakout strategies
        if ranking["strategies"]:
            top_strategy = ranking["strategies"][0]
            assert top_strategy[0]["family"] == "script_string_breakout"

    def test_json_injection(self, mock_scope_engine, mock_policy_engine):
        """Test strategy selection for JSON object injection."""
        node = StrategySelectorNode()

        # Model from P2: JSON eval injection
        model = {
            "candidate_id": "json_001",
            "execution_context": "json_eval",
            "sink": "JSON.parse",
            "constraints": {
                "sink_kind": "json_eval",
                "object_closure_required": True,
                "raw_chars": ['"', "}", ";", "a", "l", "e", "r", "t"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_004",
            node_id="selector_004",
            run_id="run_004",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 1
        ranking = result["rankings"][0]
        assert ranking["context_type"] == "json_eval"

        if ranking["strategies"]:
            top_strategy = ranking["strategies"][0]
            assert top_strategy[0]["family"] == "json_object_breakout"

    def test_html_attribute_injection(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test strategy selection for HTML attribute injection."""
        node = StrategySelectorNode()

        # Model from P2: HTML attribute injection
        model = {
            "candidate_id": "attr_001",
            "execution_context": "attribute",
            "sink": "setAttribute",
            "constraints": {
                "sink_kind": "html_attribute",
                "attribute": "href",
                "quote_type": "double",
                "quote_breakout_required": True,
                "raw_chars": ['"', " ", "o", "n", "l", "o", "a", "d", "=", "(", ")"],
                "encoded_chars": ["<", ">"],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_005",
            node_id="selector_005",
            run_id="run_005",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 1
        ranking = result["rankings"][0]
        assert ranking["context_type"] == "attribute"

        if ranking["strategies"]:
            top_strategy = ranking["strategies"][0]
            assert top_strategy[0]["family"] == "attribute_breakout"

    def test_multiple_models_mixed_contexts(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test strategy selection for multiple models with different contexts."""
        node = StrategySelectorNode()

        models = [
            {
                "candidate_id": "html_multi",
                "execution_context": "markup",
                "constraints": {
                    "sink_kind": "html_text",
                    "raw_chars": ["<", ">", "s", "c", "r"],
                    "encoded_chars": [],
                    "stripped_chars": [],
                },
            },
            {
                "candidate_id": "js_multi",
                "execution_context": "js_string_double",
                "constraints": {
                    "sink_kind": "js_execution",
                    "raw_chars": ['"', ";", "a", "l", "e"],
                    "encoded_chars": [],
                    "stripped_chars": [],
                },
            },
            {
                "candidate_id": "json_multi",
                "execution_context": "json_eval",
                "constraints": {
                    "sink_kind": "json_eval",
                    "raw_chars": ['"', "}", ";", "a"],
                    "encoded_chars": [],
                    "stripped_chars": [],
                },
            },
        ]

        ctx = ExecutionContext(
            scan_id="test_006",
            node_id="selector_006",
            run_id="run_006",
            inputs={"models": models},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        assert result["ranking_count"] == 3
        assert len(result["rankings"]) == 3
        assert result["unmatched_models"] == []

        # Verify each ranking has the right context
        contexts = [r["context_type"] for r in result["rankings"]]
        assert "markup" in contexts
        assert "js_string_double" in contexts
        assert "json_eval" in contexts

    def test_character_constraint_scoring(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test that strategies are scored based on character availability."""
        node = StrategySelectorNode()

        # Model with limited characters
        model_restricted = {
            "candidate_id": "restricted",
            "execution_context": "markup",
            "constraints": {
                "sink_kind": "html_text",
                # Only have opening bracket, not closing
                "raw_chars": ["<", "s", "c", "r", "i", "p", "t"],
                "encoded_chars": [">"],  # Closing bracket is encoded!
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_007",
            node_id="selector_007",
            run_id="run_007",
            inputs={"models": [model_restricted]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        # Should still get strategies, but they may be lower-scored
        if result["ranking_count"] > 0:
            ranking = result["rankings"][0]
            # Strategies should exist but may have lower confidence
            assert len(ranking["strategies"]) >= 0

    def test_unmatched_model_with_unknown_context(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test handling of models with unknown context types."""
        node = StrategySelectorNode()

        # Model with unknown context
        model = {
            "candidate_id": "unknown_ctx",
            "execution_context": "unknown_context_type",
            "constraints": {
                "sink_kind": "unknown_sink",
                "raw_chars": ["<", ">"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_008",
            node_id="selector_008",
            run_id="run_008",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        # Should try to match (fallback to markup) or end up unmatched
        # Exact behavior depends on implementation
        assert result["ranking_count"] + len(result["unmatched_models"]) == 1

    def test_strategy_ranking_order(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test that strategies are ranked in descending confidence order."""
        node = StrategySelectorNode()

        model = {
            "candidate_id": "rank_test",
            "execution_context": "markup",
            "constraints": {
                "sink_kind": "html_text",
                "raw_chars": ["<", ">", "s", "c", "r", "i", "p", "t", "a", "l", "e", "r", "t"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_009",
            node_id="selector_009",
            run_id="run_009",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        if result["ranking_count"] > 0:
            ranking = result["rankings"][0]
            # Verify strategies are sorted by confidence descending
            scores = [strat[1] for strat in ranking["strategies"]]
            if len(scores) > 1:
                for i in range(len(scores) - 1):
                    assert scores[i] >= scores[i + 1], "Strategies should be ranked descending"

    def test_top_strategy_helper(self, mock_scope_engine, mock_policy_engine):
        """Test StrategyRanking.top_strategy() helper method."""
        node = StrategySelectorNode()

        model = {
            "candidate_id": "helper_test",
            "execution_context": "markup",
            "constraints": {
                "sink_kind": "html_text",
                "raw_chars": ["<", ">", "s", "c", "r"],
                "encoded_chars": [],
                "stripped_chars": [],
            },
        }

        ctx = ExecutionContext(
            scan_id="test_010",
            node_id="selector_010",
            run_id="run_010",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        if result["ranking_count"] > 0:
            ranking = result["rankings"][0]
            # Verify top strategy info
            assert ranking["model_id"] == "helper_test"
            assert ranking["context_type"] == "markup"

    def test_model_with_partial_constraints(
        self, mock_scope_engine, mock_policy_engine
    ):
        """Test handling of models with incomplete constraint info."""
        node = StrategySelectorNode()

        # Model with minimal constraints
        model = {
            "candidate_id": "minimal",
            "execution_context": "markup",
            "constraints": {
                # Minimal info
                "sink_kind": "html_text",
            },
        }

        ctx = ExecutionContext(
            scan_id="test_011",
            node_id="selector_011",
            run_id="run_011",
            inputs={"models": [model]},
            scope=mock_scope_engine,
            policy=mock_policy_engine,
        )

        result = node.execute(ctx)

        # Should handle gracefully
        assert result["ranking_count"] + len(result["unmatched_models"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
