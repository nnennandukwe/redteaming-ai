from __future__ import annotations

from concurrent.futures import Executor, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Type

from redteaming_ai.adapters import normalize_target_spec, resolve_target_spec
from redteaming_ai.agents import RedTeamOrchestrator
from redteaming_ai.api_logging import log_event, request_logging_context
from redteaming_ai.storage import RunStorage

AssessmentRunner = Callable[[RunStorage, str, Dict[str, Any]], None]


def default_assessment_runner(
    storage: RunStorage, run_id: str, target: Dict[str, Any]
) -> None:
    spec = normalize_target_spec(
        target_type=target.get("target_type"),
        target_provider=target.get("target_provider"),
        target_model=target.get("target_model"),
        target_config=target.get("target_config"),
    )
    _, target_app = resolve_target_spec(spec)
    orchestrator = RedTeamOrchestrator(
        storage=storage,
        run_id=run_id,
        campaign_config=target.get("campaign_config"),
    )
    orchestrator.run_attack_suite(target_app)


class AssessmentService:
    """Thin service layer between HTTP handlers and storage/orchestration."""

    def __init__(
        self,
        *,
        db_path: Optional[Path] = None,
        executor: Optional[Executor] = None,
        assessment_runner: Optional[AssessmentRunner] = None,
        storage_cls: Type[RunStorage] = RunStorage,
    ):
        self.db_path = db_path
        self.storage_cls = storage_cls
        self.executor = executor or ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="redteam-api"
        )
        self._owns_executor = executor is None
        self.assessment_runner = assessment_runner or default_assessment_runner

    def close(self) -> None:
        if self._owns_executor and hasattr(self.executor, "shutdown"):
            self.executor.shutdown(wait=False)

    def _open_storage(self) -> RunStorage:
        storage = self.storage_cls(db_path=self.db_path)
        storage.init_db()
        return storage

    def create_assessment(
        self,
        target_provider: Optional[str] = None,
        target_model: Optional[str] = None,
        target_type: str = "vulnerable_llm_app",
        target_config: Optional[Dict[str, Any]] = None,
        campaign_config: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with request_logging_context(request_id):
            try:
                spec = normalize_target_spec(
                    target_type=target_type,
                    target_provider=target_provider,
                    target_model=target_model,
                    target_config=target_config,
                )
            except ValueError as exc:
                log_event(
                    "assessment.validation_failed",
                    level=30,
                    operation="create_assessment",
                    outcome="failure",
                    reason="target_validation_failed",
                    error_type=exc.__class__.__name__,
                    remediation=(
                        "Verify target_type, target_provider, and target_model inputs."
                    ),
                    target_type=target_type,
                    target_provider=target_provider,
                    target_model=target_model,
                )
                raise

            storage = self._open_storage()
            try:
                run_id = storage.create_run(
                    target_type=spec.target_type,
                    target_provider=spec.target_provider,
                    target_model=spec.target_model,
                    target_config=spec.target_config,
                    campaign_config=campaign_config,
                )
            finally:
                storage.close()

            log_event(
                "assessment.queued",
                operation="create_assessment",
                outcome="accepted",
                run_id=run_id,
                run_status="running",
                target_type=spec.target_type,
                target_provider=spec.target_provider,
                target_model=spec.target_model,
            )

            runner_target = spec.to_dict()
            runner_target["campaign_config"] = campaign_config
            self.executor.submit(
                self._execute_assessment,
                run_id,
                runner_target,
                request_id,
            )
            run = self.get_assessment(run_id)
            if not run:
                raise ValueError(f"Run {run_id} was not created")
            return run

    def get_assessment(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run:
                return None
            return self._build_assessment_response(run)
        finally:
            storage.close()

    def get_report(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run or run["status"] != "completed":
                return None
            return storage.get_report_artifact(run_id)
        finally:
            storage.close()

    def get_evidence(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run:
                return None
            evidence = storage.get_run_evidence(run_id)
            evidence["target_type"] = run.get("target_type")
            evidence["target_provider"] = run.get("target_provider")
            evidence["target_model"] = run.get("target_model")
            evidence["target_config"] = run.get("target_config", {})
            if "campaign" not in evidence:
                evidence["campaign"] = self._campaign_from_run(run)
            return evidence
        finally:
            storage.close()

    def export_report(self, run_id: str, format: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run or run["status"] != "completed":
                return None
            exported = storage.export_report(run_id, format)
            return {
                "format": format,
                "content": exported["report"] if format == "json" else exported["content"],
                "media_type": exported["content_type"],
                "filename": exported["filename"],
            }
        finally:
            storage.close()

    def _execute_assessment(
        self,
        run_id: str,
        target: Dict[str, Any],
        request_id: Optional[str] = None,
    ) -> None:
        with request_logging_context(request_id):
            log_event(
                "assessment.execution_started",
                operation="execute_assessment",
                outcome="started",
                run_id=run_id,
                run_status="running",
                target_type=target.get("target_type"),
                target_provider=target.get("target_provider"),
                target_model=target.get("target_model"),
            )

            storage = self._open_storage()
            try:
                self.assessment_runner(storage, run_id, target)
            except Exception as exc:
                log_event(
                    "assessment.execution_failed",
                    level=40,
                    operation="execute_assessment",
                    outcome="failure",
                    reason="assessment_runner_failed",
                    error_type=exc.__class__.__name__,
                    remediation=(
                        "Inspect the run status for failure details before retrying."
                    ),
                    run_id=run_id,
                    run_status="failed",
                    target_type=target.get("target_type"),
                    target_provider=target.get("target_provider"),
                    target_model=target.get("target_model"),
                )
                storage.mark_run_failed(run_id, str(exc))
            else:
                run = storage.get_run(run_id)
                log_event(
                    "assessment.execution_completed",
                    operation="execute_assessment",
                    outcome="success",
                    run_id=run_id,
                    run_status=run["status"] if run else "unknown",
                    target_type=target.get("target_type"),
                    target_provider=target.get("target_provider"),
                    target_model=target.get("target_model"),
                )
            finally:
                storage.close()

    def _build_assessment_response(self, run: Dict[str, Any]) -> Dict[str, Any]:
        summary = None
        if run["status"] == "completed" and run.get("report"):
            summary = run["report"].get("summary")

        return {
            "id": run["id"],
            "target_id": run.get("target_id"),
            "target_type": run.get("target_type"),
            "target_provider": run.get("target_provider"),
            "target_model": run.get("target_model"),
            "target_config": run.get("target_config", {}),
            "status": run["status"],
            "started_at": run.get("started_at"),
            "completed_at": run.get("completed_at"),
            "duration_seconds": run.get("duration_seconds"),
            "error_message": run.get("error_message"),
            "summary": summary,
            "campaign": self._campaign_from_run(run),
        }

    @staticmethod
    def _campaign_from_run(run: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        report = run.get("report") or {}
        if report.get("campaign") is not None:
            return report.get("campaign")
        return run.get("campaign_config")
