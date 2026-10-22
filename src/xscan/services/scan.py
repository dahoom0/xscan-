"""
ScanService
===========
Orchestrates a scan end-to-end via the DAG engine.
Called by the CommandDispatcher — never by CLI commands directly.

Flow:
  1. Validate target + scope
  2. Create Scan record (persisted)
  3. Load workflow
  4. Build ScopeEngine, PolicyEngine, Checkpoint
  5. Execute DAG
  6. Publish SCAN_COMPLETED event
  7. Return WorkflowRun
"""
from __future__ import annotations

import logging
from datetime import datetime, UTC
from typing import Any, Callable

from xscan.config import get_settings
from xscan.core.dag.engine import DAGEngine
from xscan.core.dag.checkpoint import Checkpoint
from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import ScopeError, WorkflowValidationError
from xscan.events import bus
from xscan.schemas.events import DomainEvent, EventType
from xscan.schemas.scan import Scan, ScanProfile, ScanStatus, Target
from xscan.schemas.workflow import WorkflowRun
from xscan.storage.database import get_db
from xscan.storage.repositories.scan import ScanRepository
from xscan.workflows.loader import WorkflowLoader
from xscan.workflows.validator import WorkflowValidator

# Register all built-in DAG nodes so the registry is populated
import xscan.nodes.registry  # noqa: F401

logger = logging.getLogger(__name__)

_PROFILE_WORKFLOW = {
    "fast":     "xss-fast",
    "balanced": "xss-balanced",
    "deep":     "xss-deep",
}


class ScanService:
    """
    Application service for running scans.

    Usage (via dispatcher only)::

        ScanService().run(target="https://example.com", profile="balanced")
    """

    def run(
        self,
        target: str,
        profile: str = "balanced",
        workflow_name: str | None = None,
        no_llm: bool = False,
        research: bool = False,
        auth_session: str | None = None,
        project: str | None = None,
        resume_scan_id: str | None = None,
        output_path: str | None = None,
        output_format: str = "terminal",
        progress_cb: Callable[[str, str, str], None] | None = None,
    ) -> WorkflowRun:
        settings = get_settings()
        db = get_db()
        scan_repo = ScanRepository(db)

        # Resolve target
        resolved_target = Target.from_url(target)

        # Determine workflow
        wf_name = workflow_name or _PROFILE_WORKFLOW.get(profile, "xss-balanced")

        # Resume existing scan or create new
        if resume_scan_id:
            scan = scan_repo.get(resume_scan_id)
            if scan is None:
                raise ScopeError(f"Scan '{resume_scan_id}' not found for resume.")
            logger.info("Resuming scan %s", scan.id)
        else:
            scan = Scan(
                target=resolved_target,
                profile=ScanProfile(profile),
                workflow_name=wf_name,
                no_llm=no_llm,
                research_enabled=research,
                auth_session=auth_session,
                project=project,
                status=ScanStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            scan_repo.save(scan)
            bus.publish(DomainEvent(
                type=EventType.SCAN_STARTED,
                scan_id=scan.id,
                payload={"target": resolved_target.url, "workflow": wf_name},
            ))
            logger.info("Scan %s started  target=%s  workflow=%s", scan.id, resolved_target.url, wf_name)

        # Pre-flight health checks — fail fast if core dependencies missing
        from xscan.services.doctor import DoctorService
        doctor = DoctorService()
        health = doctor.run(fix=False, json_output=False)
        
        # For profiles that need tools, fail if core tools are missing
        profile_requires_tools = profile in ("balanced", "deep", "fast")
        if profile_requires_tools and not health.all_ok:
            failed_checks = {r.name for r in health.failed}
            # Only fail on tool/wsl checks for now; config/ollama failures are degraded
            blocking = failed_checks & {"tools", "wsl"}
            if blocking:
                scan_repo.update_status(scan.id, ScanStatus.FAILED,
                    f"Pre-flight check failed: {', '.join(blocking)}. Run 'xscan doctor' for details.")
                logger.error("Pre-flight check failed: %s", blocking)
                raise ScopeError(
                    f"Pre-flight health check failed (blocking): {', '.join(blocking)}. "
                    f"Run 'xscan doctor' to diagnose and repair."
                )
        
        # Warn on degraded checks
        degraded_checks = {r.name: r.detail for r in health.failed}
        if degraded_checks:
            logger.warning("Pre-flight checks degraded: %s", degraded_checks)

        # Load + validate workflow
        loader = WorkflowLoader()
        try:
            workflow = loader.load(wf_name)
            WorkflowValidator(check_registry=True).assert_valid(workflow)
        except WorkflowValidationError as exc:
            scan_repo.update_status(scan.id, ScanStatus.FAILED, str(exc))
            raise

        # Build platform components
        scope_engine = ScopeEngine.from_target(scan.id, resolved_target.url)
        policy_engine = PolicyEngine()
        checkpoint = Checkpoint(db)

        # Find resume run ID if resuming
        resume_run_id: str | None = None
        if resume_scan_id:
            existing_run = checkpoint.load_latest_for_scan(scan.id)
            if existing_run:
                resume_run_id = existing_run.id

        # Execute DAG
        dag_engine = DAGEngine(
            workflow=workflow,
            scope=scope_engine,
            policy=policy_engine,
            checkpoint=checkpoint,
            no_llm=no_llm,
            resume_run_id=resume_run_id,
            progress_cb=progress_cb,
        )

        try:
            run = dag_engine.execute(
                scan_id=scan.id,
                inputs={
                    "target_url": resolved_target.url,
                    "scan_id":    scan.id,
                    "profile":    profile,
                    "degraded":   bool(degraded_checks),
                    "degradation_reason": "; ".join(
                        f"{name}: {detail}" for name, detail in degraded_checks.items()
                    ),
                },
            )
            # Mark degraded if pre-flight checks failed
            if degraded_checks:
                run.degraded = True
                run.degradation_reason = "; ".join(
                    f"{name}: {detail}" for name, detail in degraded_checks.items()
                )
        except Exception as exc:
            scan_repo.update_status(scan.id, ScanStatus.FAILED, str(exc))
            bus.publish(DomainEvent(
                type=EventType.SCAN_FAILED,
                scan_id=scan.id,
                payload={"error": str(exc)},
            ))
            raise

        # Update scan status
        final_status = ScanStatus.COMPLETED if run.status.value == "completed" else ScanStatus.FAILED
        scan_repo.update_status(scan.id, final_status)
        bus.publish(DomainEvent(
            type=EventType.SCAN_COMPLETED,
            scan_id=scan.id,
            payload={"run_id": run.id, "status": run.status},
        ))
        logger.info("Scan %s finished  status=%s", scan.id, final_status)
        return run
