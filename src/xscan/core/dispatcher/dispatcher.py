"""
CommandDispatcher
=================
Routes CLI command invocations to the correct ApplicationService.

Rules:
  - CLI commands call dispatcher.scan(...), dispatcher.recon(...), etc.
  - Dispatcher constructs the service and delegates.
  - No business logic lives here — only routing + dependency wiring.
  - Services are imported lazily to keep CLI startup fast.
"""
from __future__ import annotations

from typing import Any


class CommandDispatcher:
    """
    Single entry point from CLI to the application layer.

    Usage (in CLI command)::

        from xscan.core.dispatcher import CommandDispatcher
        dispatcher = CommandDispatcher()
        dispatcher.scan(target="https://example.com", profile="balanced")
    """

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(
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
        progress_cb: Any = None,
    ) -> Any:
        from xscan.services.scan import ScanService
        return ScanService().run(
            target=target,
            profile=profile,
            workflow_name=workflow_name,
            no_llm=no_llm,
            research=research,
            auth_session=auth_session,
            project=project,
            resume_scan_id=resume_scan_id,
            output_path=output_path,
            output_format=output_format,
            progress_cb=progress_cb,
        )

    # ------------------------------------------------------------------
    # Recon
    # ------------------------------------------------------------------

    def recon(self, target: str, profile: str = "balanced") -> Any:
        from xscan.services.scan import ScanService
        return ScanService().run(
            target=target,
            profile=profile,
            workflow_name="recon-only",
        )

    # ------------------------------------------------------------------
    # Doctor
    # ------------------------------------------------------------------

    def doctor(self, fix: bool = False, json_output: bool = False) -> Any:
        from xscan.services.doctor import DoctorService
        return DoctorService().run(fix=fix, json_output=json_output)

    # ------------------------------------------------------------------
    # Models
    # ------------------------------------------------------------------

    def models_list(self) -> Any:
        from xscan.services.models import ModelService
        return ModelService().list()

    def models_use(self, model: str) -> Any:
        from xscan.services.models import ModelService
        return ModelService().use(model)

    def models_test(self, model: str | None = None) -> Any:
        from xscan.services.models import ModelService
        return ModelService().test(model)

    def models_info(self, model: str) -> Any:
        from xscan.services.models import ModelService
        return ModelService().info(model)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def tools_list(self) -> Any:
        from xscan.services.tools import ToolService
        return ToolService().list()

    def tools_check(self, name: str | None = None, all_tools: bool = False) -> Any:
        from xscan.services.tools import ToolService
        return ToolService().check(name=name, all_tools=all_tools)

    def tools_inspect(self, name: str) -> Any:
        from xscan.services.tools import ToolService
        return ToolService().inspect(name)

    # ------------------------------------------------------------------
    # Workflow
    # ------------------------------------------------------------------

    def workflow_list(self) -> list[str]:
        from xscan.workflows.loader import WorkflowLoader
        return WorkflowLoader().list_available()

    def workflow_inspect(self, name: str) -> Any:
        from xscan.workflows.loader import WorkflowLoader
        from xscan.workflows.validator import WorkflowValidator
        wf = WorkflowLoader().load(name)
        WorkflowValidator(check_registry=False).assert_valid(wf)
        return wf
