from __future__ import annotations

from concurrent.futures import Executor, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from redteaming_ai.agents import RedTeamOrchestrator
from redteaming_ai.storage import DEFAULT_TARGET_TYPE, RunStorage
from redteaming_ai.target import VulnerableLLMApp

AssessmentRunner = Callable[[RunStorage, str, Dict[str, Any]], None]


def default_assessment_runner(
    storage: RunStorage, run_id: str, target: Dict[str, Any]
) -> None:
    if target["target_type"] != DEFAULT_TARGET_TYPE:
        raise ValueError(f"Unsupported target type: {target['target_type']}")

    target_app = VulnerableLLMApp()
    orchestrator = RedTeamOrchestrator(storage=storage, run_id=run_id)
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

    def create_target(
        self,
        name: str,
        target_type: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        storage = self._open_storage()
        try:
            return storage.create_target(name, target_type, provider, model, config)
        finally:
            storage.close()

    def list_targets(self) -> List[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            return storage.list_targets()
        finally:
            storage.close()

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            return storage.get_target(target_id)
        finally:
            storage.close()

    def create_assessment(self, target_id: str) -> Dict[str, Any]:
        storage = self._open_storage()
        try:
            target = storage.get_target(target_id)
            if not target:
                raise ValueError(f"Target {target_id} not found")
            run_id = storage.create_queued_run(target_id)
            run = storage.get_run(run_id)
        finally:
            storage.close()

        self.executor.submit(self._execute_assessment, run_id, target_id)
        if run is None:
            raise ValueError(f"Run {run_id} was not created")
        return run

    def get_assessment(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            return storage.get_run(run_id)
        finally:
            storage.close()

    def get_report(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run:
                return None
            report = storage.regenerate_report(run_id) if run["attempts"] else {
                "summary": {},
                "attacks_by_type": {},
                "leaked_data_types": [],
                "results": [],
            }
            vulnerabilities = []
            if run["report"]:
                vulnerabilities = run["report"].get("vulnerabilities", [])

            return {
                "id": run["id"],
                "target_id": run["target_id"],
                "target_name": run["target_name"],
                "target_type": run["target_type"],
                "target_provider": run["target_provider"],
                "target_model": run["target_model"],
                "status": run["status"],
                "queued_at": run["queued_at"],
                "started_at": run["started_at"],
                "completed_at": run["completed_at"],
                "duration_seconds": run["duration_seconds"],
                "error_message": run["error_message"],
                "summary": report.get("summary", {}),
                "attacks_by_type": report.get("attacks_by_type", {}),
                "leaked_data_types": report.get("leaked_data_types", []),
                "vulnerabilities": vulnerabilities,
                "results": report.get("results", []),
            }
        finally:
            storage.close()

    def get_evidence(self, run_id: str) -> Optional[Dict[str, Any]]:
        storage = self._open_storage()
        try:
            run = storage.get_run(run_id)
            if not run:
                return None
            evidence = storage.get_run_evidence(run_id)
            evidence["target_id"] = run["target_id"]
            return evidence
        finally:
            storage.close()

    def _execute_assessment(self, run_id: str, target_id: str) -> None:
        storage = self._open_storage()
        try:
            target = storage.get_target(target_id)
            if not target:
                raise ValueError(f"Target {target_id} not found")
            storage.mark_run_started(run_id)
            self.assessment_runner(storage, run_id, target)
        except Exception as exc:
            storage.mark_run_failed(run_id, str(exc))
        finally:
            storage.close()
