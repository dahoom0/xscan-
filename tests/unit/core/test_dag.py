"""Tests for WorkflowGraph, NodeRegistry, NodeBase, and DAGEngine."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from xscan.core.dag.graph import WorkflowGraph
from xscan.core.dag.node_registry import NodeRegistry
from xscan.core.dag.engine import DAGEngine
from xscan.core.dag.checkpoint import Checkpoint
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import WorkflowValidationError, DAGError
from xscan.nodes.base import NodeBase, ExecutionContext
from xscan.schemas.workflow import Workflow, WorkflowNode, NodeStatus, WorkflowRun
from xscan.storage.database import Database


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_workflow(nodes_spec: list[dict]) -> Workflow:
    nodes = [WorkflowNode(**s) for s in nodes_spec]
    return Workflow(name="test", nodes=nodes)


@pytest.fixture
def simple_workflow() -> Workflow:
    return make_workflow([
        {"id": "a", "type": "echo", "depends_on": []},
        {"id": "b", "type": "echo", "depends_on": ["a"]},
        {"id": "c", "type": "echo", "depends_on": ["a"]},
        {"id": "d", "type": "echo", "depends_on": ["b", "c"]},
    ])


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "test.db")
    d.connect()
    d.migrate()
    return d


@pytest.fixture
def fresh_registry() -> NodeRegistry:
    reg = NodeRegistry()

    class EchoNode(NodeBase):
        node_type = "echo"
        def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
            return {"echoed": ctx.node_id}

    reg.register("echo")(EchoNode)
    return reg


@pytest.fixture
def scope() -> ScopeEngine:
    return ScopeEngine.allow_all("test-scan")


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine()


# ---------------------------------------------------------------------------
# WorkflowGraph tests
# ---------------------------------------------------------------------------

class TestWorkflowGraph:
    def test_topo_order_linear(self):
        wf = make_workflow([
            {"id": "a", "type": "t", "depends_on": []},
            {"id": "b", "type": "t", "depends_on": ["a"]},
            {"id": "c", "type": "t", "depends_on": ["b"]},
        ])
        g = WorkflowGraph(wf)
        order = g.topological_order()
        assert order.index("a") < order.index("b") < order.index("c")

    def test_execution_waves_parallel(self, simple_workflow: Workflow):
        g = WorkflowGraph(simple_workflow)
        waves = g.execution_waves()
        # a must be alone in wave 0
        assert waves[0] == ["a"]
        # b and c can be in same wave
        assert set(waves[1]) == {"b", "c"}
        assert waves[2] == ["d"]

    def test_detects_cycle(self):
        wf = make_workflow([
            {"id": "a", "type": "t", "depends_on": ["b"]},
            {"id": "b", "type": "t", "depends_on": ["a"]},
        ])
        with pytest.raises(WorkflowValidationError, match="cycle"):
            WorkflowGraph.from_workflow(wf)

    def test_detects_unknown_dependency(self):
        wf = make_workflow([
            {"id": "a", "type": "t", "depends_on": ["nonexistent"]},
        ])
        with pytest.raises(WorkflowValidationError, match="unknown node"):
            WorkflowGraph.from_workflow(wf)

    def test_single_node_workflow(self):
        wf = make_workflow([{"id": "only", "type": "t", "depends_on": []}])
        g = WorkflowGraph.from_workflow(wf)
        assert g.topological_order() == ["only"]
        assert g.execution_waves() == [["only"]]

    def test_dependencies_of(self, simple_workflow: Workflow):
        g = WorkflowGraph(simple_workflow)
        assert g.dependencies_of("d") == {"b", "c"}
        assert g.dependencies_of("a") == set()

    def test_dependents_of(self, simple_workflow: Workflow):
        g = WorkflowGraph(simple_workflow)
        assert g.dependents_of("a") == {"b", "c"}
        assert g.dependents_of("d") == set()


# ---------------------------------------------------------------------------
# NodeRegistry tests
# ---------------------------------------------------------------------------

class TestNodeRegistry:
    def test_register_and_get(self):
        reg = NodeRegistry()

        class FakeNode(NodeBase):
            node_type = "fake"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                return {}

        reg.register("fake")(FakeNode)
        assert reg.get("fake") is FakeNode

    def test_get_unregistered_raises(self):
        reg = NodeRegistry()
        with pytest.raises(DAGError, match="Unknown node type"):
            reg.get("not-registered")

    def test_is_registered(self, fresh_registry: NodeRegistry):
        assert fresh_registry.is_registered("echo") is True
        assert fresh_registry.is_registered("missing") is False


# ---------------------------------------------------------------------------
# NodeBase tests
# ---------------------------------------------------------------------------

class TestNodeBase:
    def test_successful_execute(self, scope: ScopeEngine, policy: PolicyEngine):
        class SuccessNode(NodeBase):
            node_type = "success"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                return {"result": "ok"}

        ctx = ExecutionContext(
            scan_id="s1", node_id="n1", run_id="r1",
            inputs={}, scope=scope, policy=policy,
        )
        result = SuccessNode().run(ctx)
        assert result.status == NodeStatus.COMPLETED
        assert result.output["result"] == "ok"
        assert result.started_at is not None
        assert result.finished_at is not None

    def test_failed_execute_captured(self, scope: ScopeEngine, policy: PolicyEngine):
        class FailNode(NodeBase):
            node_type = "fail"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                raise ValueError("deliberate failure")

        ctx = ExecutionContext(
            scan_id="s1", node_id="n1", run_id="r1",
            inputs={}, scope=scope, policy=policy,
        )
        result = FailNode().run(ctx)
        assert result.status == NodeStatus.FAILED
        assert "deliberate failure" in (result.error or "")


# ---------------------------------------------------------------------------
# DAGEngine integration tests
# ---------------------------------------------------------------------------

class TestDAGEngine:
    def test_full_execution(
        self,
        simple_workflow: Workflow,
        db: Database,
        fresh_registry: NodeRegistry,
        scope: ScopeEngine,
        policy: PolicyEngine,
    ):
        from xscan.schemas.scan import Scan, Target
        from xscan.storage.repositories.scan import ScanRepository
        scan = Scan(id="scan-1", target=Target.from_url("https://example.com"))
        ScanRepository(db).save(scan)

        cp = Checkpoint(db)
        engine = DAGEngine(
            workflow=simple_workflow,
            scope=scope,
            policy=policy,
            checkpoint=cp,
            node_registry=fresh_registry,
        )
        run = engine.execute("scan-1", inputs={"start": "value"})
        assert run.status == NodeStatus.COMPLETED
        assert len(run.node_results) == 4
        for nid in ["a", "b", "c", "d"]:
            assert run.node_results[nid].status == NodeStatus.COMPLETED

    def test_outputs_flow_between_nodes(
        self,
        db: Database,
        scope: ScopeEngine,
        policy: PolicyEngine,
    ):
        """Verify that a node's output is available to downstream nodes."""
        reg = NodeRegistry()

        class ProducerNode(NodeBase):
            node_type = "producer"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                return {"message": "hello from producer"}

        class ConsumerNode(NodeBase):
            node_type = "consumer"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                msg = ctx.get("message", "")
                return {"received": msg}

        reg.register("producer")(ProducerNode)
        reg.register("consumer")(ConsumerNode)

        wf = make_workflow([
            {"id": "prod", "type": "producer", "depends_on": []},
            {"id": "cons", "type": "consumer", "depends_on": ["prod"]},
        ])
        cp = Checkpoint(db)
        engine = DAGEngine(wf, scope, policy, cp, node_registry=reg)
        run = engine.execute("scan-2")

        assert run.node_results["cons"].output["received"] == "hello from producer"

    def test_failed_node_stops_execution(
        self,
        db: Database,
        scope: ScopeEngine,
        policy: PolicyEngine,
    ):
        reg = NodeRegistry()

        class OkNode(NodeBase):
            node_type = "ok"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                return {}

        class BrokenNode(NodeBase):
            node_type = "broken"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                raise RuntimeError("forced failure")

        reg.register("ok")(OkNode)
        reg.register("broken")(BrokenNode)

        wf = make_workflow([
            {"id": "start", "type": "ok", "depends_on": []},
            {"id": "fail",  "type": "broken", "depends_on": ["start"]},
            {"id": "after", "type": "ok", "depends_on": ["fail"]},
        ])
        cp = Checkpoint(db)
        engine = DAGEngine(wf, scope, policy, cp, node_registry=reg)
        run = engine.execute("scan-3")

        assert run.status == NodeStatus.FAILED
        assert "after" not in run.node_results  # never ran

    def test_checkpoint_and_resume(
        self,
        db: Database,
        scope: ScopeEngine,
        policy: PolicyEngine,
    ):
        """Completed nodes must be skipped on resume."""
        reg = NodeRegistry()
        call_counts: dict[str, int] = {"a": 0, "b": 0}

        class NodeA(NodeBase):
            node_type = "node-a"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                call_counts["a"] += 1
                return {"a_done": True}

        class NodeB(NodeBase):
            node_type = "node-b"
            def execute(self, ctx: ExecutionContext) -> dict[str, Any]:
                call_counts["b"] += 1
                return {"b_done": True}

        reg.register("node-a")(NodeA)
        reg.register("node-b")(NodeB)

        wf = make_workflow([
            {"id": "a", "type": "node-a", "depends_on": []},
            {"id": "b", "type": "node-b", "depends_on": ["a"]},
        ])

        # First run
        cp = Checkpoint(db)
        engine1 = DAGEngine(wf, scope, policy, cp, node_registry=reg)
        run1 = engine1.execute("scan-4")
        assert run1.status == NodeStatus.COMPLETED
        assert call_counts == {"a": 1, "b": 1}

        # Resume — both nodes were completed, neither should re-run
        engine2 = DAGEngine(
            wf, scope, policy, cp,
            node_registry=reg,
            resume_run_id=run1.id,
        )
        run2 = engine2.execute("scan-4")
        assert run2.status == NodeStatus.COMPLETED
        # Counts unchanged — nodes were skipped
        assert call_counts == {"a": 1, "b": 1}


# ---------------------------------------------------------------------------
# WorkflowLoader / Validator tests
# ---------------------------------------------------------------------------

class TestWorkflowLoader:
    def test_load_builtin_recon_only(self):
        from xscan.workflows.loader import WorkflowLoader
        loader = WorkflowLoader()
        wf = loader.load("recon-only")
        assert wf.name == "recon-only"
        assert len(wf.nodes) >= 2

    def test_load_builtin_xss_balanced(self):
        from xscan.workflows.loader import WorkflowLoader
        loader = WorkflowLoader()
        wf = loader.load("xss-balanced")
        node_ids = [n.id for n in wf.nodes]
        assert "scope-validation" in node_ids
        assert "crawl" in node_ids
        assert "report" in node_ids

    def test_missing_workflow_raises(self):
        from xscan.workflows.loader import WorkflowLoader
        loader = WorkflowLoader()
        with pytest.raises(WorkflowValidationError, match="not found"):
            loader.load("does-not-exist-xyz")

    def test_list_available_contains_builtins(self):
        from xscan.workflows.loader import WorkflowLoader
        loader = WorkflowLoader()
        available = loader.list_available()
        assert "recon-only" in available
        assert "xss-fast" in available
        assert "xss-balanced" in available
        assert "xss-deep" in available


class TestWorkflowValidator:
    def test_valid_workflow_passes(self):
        from xscan.workflows.validator import WorkflowValidator
        wf = make_workflow([
            {"id": "a", "type": "echo", "depends_on": []},
            {"id": "b", "type": "echo", "depends_on": ["a"]},
        ])
        result = WorkflowValidator(check_registry=False).validate(wf)
        assert result.valid

    def test_cycle_is_invalid(self):
        from xscan.workflows.validator import WorkflowValidator
        wf = make_workflow([
            {"id": "a", "type": "t", "depends_on": ["b"]},
            {"id": "b", "type": "t", "depends_on": ["a"]},
        ])
        result = WorkflowValidator(check_registry=False).validate(wf)
        assert not result.valid
        assert any("cycle" in e.lower() for e in result.errors)

    def test_unknown_dep_is_invalid(self):
        from xscan.workflows.validator import WorkflowValidator
        wf = make_workflow([
            {"id": "a", "type": "t", "depends_on": ["ghost"]},
        ])
        result = WorkflowValidator(check_registry=False).validate(wf)
        assert not result.valid

    def test_assert_valid_raises(self):
        from xscan.workflows.validator import WorkflowValidator
        wf = make_workflow([
            {"id": "x", "type": "t", "depends_on": ["missing"]},
        ])
        with pytest.raises(WorkflowValidationError):
            WorkflowValidator(check_registry=False).assert_valid(wf)

    def test_unregistered_type_is_warning_not_error(self, fresh_registry: NodeRegistry):
        from xscan.workflows.validator import WorkflowValidator
        wf = make_workflow([
            {"id": "a", "type": "not-in-registry", "depends_on": []},
        ])
        result = WorkflowValidator(check_registry=True).validate(wf)
        assert result.valid  # not an error
        assert any("not registered" in w for w in result.warnings)
