from __future__ import annotations

from concurrent.futures import Executor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status

from redteaming_ai.api_models import (
    AssessmentCreateRequest,
    AssessmentResponse,
    EvidenceResponse,
    ReportResponse,
    TargetCreateRequest,
    TargetResponse,
)
from redteaming_ai.assessment_service import AssessmentRunner, AssessmentService
from redteaming_ai.storage import RunStorage


def _assessment_to_response(run: dict) -> AssessmentResponse:
    summary = None
    if run.get("report") and run["report"].get("summary"):
        summary = run["report"]["summary"]

    return AssessmentResponse(
        id=run["id"],
        target_id=run.get("target_id"),
        target_name=run.get("target_name"),
        target_type=run.get("target_type"),
        target_provider=run.get("target_provider"),
        target_model=run.get("target_model"),
        status=run["status"],
        queued_at=run["queued_at"],
        started_at=run.get("started_at"),
        completed_at=run.get("completed_at"),
        duration_seconds=run.get("duration_seconds"),
        error_message=run.get("error_message"),
        summary=summary,
    )


def get_assessment_service(request: Request) -> AssessmentService:
    return request.app.state.assessment_service


def create_app(
    *,
    db_path: Optional[Path] = None,
    executor: Optional[Executor] = None,
    assessment_runner: Optional[AssessmentRunner] = None,
    storage_cls=RunStorage,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.assessment_service = AssessmentService(
            db_path=db_path,
            executor=executor,
            assessment_runner=assessment_runner,
            storage_cls=storage_cls,
        )
        try:
            yield
        finally:
            app.state.assessment_service.close()

    app = FastAPI(
        title="redteaming-ai API",
        version="0.1.0",
        description="Backend API for launching assessments and retrieving reports.",
        lifespan=lifespan,
    )

    @app.post(
        "/targets",
        response_model=TargetResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_target(
        payload: TargetCreateRequest,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> TargetResponse:
        target = service.create_target(
            name=payload.name,
            target_type=payload.target_type,
            provider=payload.provider,
            model=payload.model,
            config=payload.config,
        )
        return TargetResponse(**target)

    @app.get("/targets", response_model=list[TargetResponse])
    def list_targets(
        service: AssessmentService = Depends(get_assessment_service),
    ) -> list[TargetResponse]:
        return [TargetResponse(**target) for target in service.list_targets()]

    @app.get("/targets/{target_id}", response_model=TargetResponse)
    def get_target(
        target_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> TargetResponse:
        target = service.get_target(target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        return TargetResponse(**target)

    @app.post(
        "/assessments",
        response_model=AssessmentResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_assessment(
        payload: AssessmentCreateRequest,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> AssessmentResponse:
        try:
            run = service.create_assessment(payload.target_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _assessment_to_response(run)

    @app.get("/assessments/{run_id}", response_model=AssessmentResponse)
    def get_assessment(
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> AssessmentResponse:
        run = service.get_assessment(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return _assessment_to_response(run)

    @app.get("/assessments/{run_id}/report", response_model=ReportResponse)
    def get_report(
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> ReportResponse:
        run = service.get_assessment(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Assessment not found")
        if run["status"] != "completed":
            raise HTTPException(
                status_code=409,
                detail="Assessment report is only available after completion",
            )

        report = service.get_report(run_id)
        if not report:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return ReportResponse(**report)

    @app.get("/assessments/{run_id}/evidence", response_model=EvidenceResponse)
    def get_evidence(
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> EvidenceResponse:
        evidence = service.get_evidence(run_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return EvidenceResponse(**evidence)

    return app


def main() -> None:
    uvicorn.run(
        "redteaming_ai.api:create_app",
        factory=True,
        host="127.0.0.1",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
