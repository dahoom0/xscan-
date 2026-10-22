"""
StrategySelector Node
=====================
Maps VulnerabilityModel instances to ranked synthesis strategies.

This is the Phase 3 component:
  VulnerabilityModel (P2)
    -> StrategySelector (P3) [THIS COMPONENT]
      -> ConstraintDrivenSynthesis (P4)

The selector:
1. Accepts VulnerabilityModel instances (output from P2)
2. Analyzes the execution context, constraints, and sink kind
3. Selects applicable strategy families
4. Ranks them by feasibility based on character constraints
5. Returns StrategyRanking for each model

This enables P4 to choose the most promising strategies for payload generation.
"""
from __future__ import annotations

from typing import Any

from xscan.nodes.base import ExecutionContext, NodeBase
from xscan.schemas.synthesis_strategy import (
    ALL_STRATEGIES,
    StrategyRanking,
    SynthesisStrategy,
)


class StrategySelectorNode(NodeBase):
    """
    Select and rank synthesis strategies for VulnerabilityModel instances.

    This node:
    1. Receives typed VulnerabilityModel instances (from P2)
    2. Analyzes execution context, constraints, and sink kind
    3. Filters applicable strategies
    4. Ranks by feasibility (character availability, syntax requirements)
    5. Returns ranked StrategyRanking for each model

    Enforces:
    - Every strategy ranking is grounded in model constraints
    - Ranking is deterministic (same model → same ranking)
    - Highest-confidence strategies come first
    - Rationale explains why each strategy was selected/ranked
    """

    node_type = "strategy-selector"

    def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
        """
        Select and rank strategies for vulnerability models.

        Inputs:
          - models: list[dict] VulnerabilityModel instances (from P2)

        Outputs:
          - rankings: list[StrategyRanking] (strategy selections for each model)
          - ranking_count: int
          - unmatched_models: list[str] models with no applicable strategies
        """
        models: list[dict[str, Any]] = ctx.get("models", [])

        ctx.logger.info(
            "StrategySelector: ranking strategies for %d models",
            len(models),
        )

        rankings: list[StrategyRanking] = []
        unmatched_models: list[str] = []

        for model in models:
            try:
                model_id = str(model.get("candidate_id") or model.get("id") or "unknown")
                context_type = str(model.get("execution_context", "unknown"))
                sink_kind = str(model.get("constraints", {}).get("sink_kind", "unknown"))

                # Get constraints for ranking
                constraints = model.get("constraints", {})

                # Select strategies for this model's context
                ranking = self._rank_strategies_for_model(
                    model_id=model_id,
                    context_type=context_type,
                    sink_kind=sink_kind,
                    constraints=constraints,
                )

                if ranking.strategies:
                    rankings.append(ranking)
                    ctx.logger.debug(
                        "  Model %s (%s / %s): %d strategies ranked",
                        model_id,
                        context_type,
                        sink_kind,
                        len(ranking.strategies),
                    )
                else:
                    unmatched_models.append(model_id)
                    ctx.logger.warning(
                        "  Model %s (%s / %s): no applicable strategies",
                        model_id,
                        context_type,
                        sink_kind,
                    )

            except Exception as exc:
                model_id = str(model.get("candidate_id", "unknown"))
                ctx.logger.warning(
                    "Failed to rank strategies for model %s: %s",
                    model_id,
                    exc,
                )
                unmatched_models.append(model_id)

        ctx.logger.info(
            "StrategySelector: ranked %d models, %d with applicable strategies, %d unmatched",
            len(models),
            len(rankings),
            len(unmatched_models),
        )

        return {
            "rankings": [r.model_dump(mode="json") for r in rankings],
            "ranking_count": len(rankings),
            "unmatched_models": unmatched_models,
        }

    def _rank_strategies_for_model(
        self,
        model_id: str,
        context_type: str,
        sink_kind: str,
        constraints: dict[str, Any],
    ) -> StrategyRanking:
        """
        Select and rank applicable strategies for a specific model.

        Algorithm:
        1. Find strategies for this context type
        2. Filter by applicability (constraints match)
        3. Score each by character feasibility
        4. Sort by confidence (highest first)
        5. Return ranked list
        """
        ranking = StrategyRanking(
            model_id=model_id,
            context_type=context_type,
            sink_kind=sink_kind,
        )

        # Map context_type to strategy key in ALL_STRATEGIES
        strategy_key = self._context_to_strategy_key(context_type)

        # Get candidate strategies for this context
        candidate_strategies = ALL_STRATEGIES.get(strategy_key, [])

        if not candidate_strategies:
            return ranking  # Empty ranking

        # Get character constraints
        raw_chars = set(constraints.get("raw_chars", []))
        encoded_chars = set(constraints.get("encoded_chars", []))
        stripped_chars = set(constraints.get("stripped_chars", []))

        # Score each strategy
        scored_strategies: list[tuple[SynthesisStrategy, float]] = []

        for strategy in candidate_strategies:
            # Check if strategy is applicable to this sink_kind
            if strategy.trigger_constraints and not self._constraints_match(
                constraints, strategy.trigger_constraints
            ):
                continue

            # Score strategy techniques
            technique_scores = []
            for technique in strategy.techniques:
                score = self._score_technique(
                    technique,
                    raw_chars=raw_chars,
                    encoded_chars=encoded_chars,
                    stripped_chars=stripped_chars,
                )
                technique_scores.append(score)

            # Overall strategy score is average of technique scores
            if technique_scores:
                avg_score = sum(technique_scores) / len(technique_scores)
                scored_strategies.append((strategy, avg_score))

        # Sort by confidence (highest first)
        scored_strategies.sort(key=lambda x: x[1], reverse=True)

        ranking.strategies = scored_strategies
        return ranking

    def _context_to_strategy_key(self, context_type: str) -> str:
        """Map execution context type to strategy registry key."""
        context_map = {
            "markup": "markup",
            "html_text": "markup",
            "html_attribute": "attribute",
            "attribute": "attribute",
            "js_string_double": "js_string_double",
            "js_string_single": "js_string_double",  # Similar strategies
            "js_string": "js_string_double",
            "js_expression": "js_string_double",
            "json_eval": "json_eval",
            "json_string": "json_eval",
        }
        return context_map.get(context_type, "markup")  # Default to markup

    def _constraints_match(
        self,
        model_constraints: dict[str, Any],
        strategy_triggers: dict[str, Any],
    ) -> bool:
        """Check if model constraints match strategy trigger conditions."""
        for key, expected_value in strategy_triggers.items():
            actual_value = model_constraints.get(key)
            if actual_value != expected_value:
                return False
        return True

    def _score_technique(
        self,
        technique: Any,
        raw_chars: set[str],
        encoded_chars: set[str],
        stripped_chars: set[str],
    ) -> float:
        """
        Score a synthesis technique based on character availability.

        Score factors:
        - All required chars available: high score (0.8-1.0)
        - Most required chars available: medium score (0.5-0.8)
        - Few required chars available: low score (0.0-0.5)
        - Uses avoided chars: penalty (-0.2)
        """
        score = technique.feasibility_score or 0.5

        # Check required chars
        required_chars = set(technique.requires_chars)
        if required_chars:
            available = len(required_chars & raw_chars)
            total = len(required_chars)
            char_ratio = available / total if total > 0 else 0.0
            # Scale to 0.5-1.0 range
            score = 0.5 + (0.5 * char_ratio)

        # Check avoided chars
        avoided_chars = set(technique.avoids_chars)
        if avoided_chars:
            bad_chars_used = len(avoided_chars & raw_chars)
            if bad_chars_used > 0:
                score -= 0.2

        # Check for encoded/stripped blocker chars
        critical_chars = set(technique.requires_chars)
        encoded_critical = len(critical_chars & encoded_chars)
        stripped_critical = len(critical_chars & stripped_chars)
        if encoded_critical > 0 or stripped_critical > 0:
            score *= 0.5  # Significant penalty for blocked chars

        return max(0.0, min(1.0, score))  # Clamp to 0.0-1.0


# Helper to create a strategy for testing/validation
def _make_test_strategy(
    strategy_id: str,
    family: str,
    context: str,
    rationale: str = "",
) -> SynthesisStrategy:
    """Create a minimal SynthesisStrategy for testing."""
    from xscan.schemas.synthesis_strategy import (
        SynthesisFamilyType,
        SynthesisTechnique,
    )

    return SynthesisStrategy(
        id=strategy_id,
        family=SynthesisFamilyType.TAG_INJECTION,
        applicable_contexts=[context],
        rationale=rationale or f"Test strategy for {context}",
        techniques=[
            SynthesisTechnique(
                name="test_technique",
                description="Test technique",
                requires_chars=["<", ">", "a"],
            ),
        ],
    )
