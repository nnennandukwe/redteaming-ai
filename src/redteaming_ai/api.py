from __future__ import annotations

import logging
from concurrent.futures import Executor
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from redteaming_ai.api_logging import (
    REQUEST_ID_HEADER,
    log_event,
    normalize_request_id,
    request_logging_context,
)
from redteaming_ai.api_models import (
    AssessmentCreateRequest,
    AssessmentResponse,
    EvidenceResponse,
    ReportResponse,
)
from redteaming_ai.assessment_service import AssessmentRunner, AssessmentService
from redteaming_ai.storage import RunStorage


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

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = normalize_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        started_at = perf_counter()

        with request_logging_context(request_id):
            log_event(
                "http.request_started",
                operation="http_request",
                outcome="started",
                method=request.method,
                path=request.url.path,
            )
            try:
                response = await call_next(request)
            except Exception:
                log_event(
                    "http.request_failed",
                    level=logging.ERROR,
                    operation="http_request",
                    outcome="failure",
                    method=request.method,
                    path=request.url.path,
                    remediation="Inspect the application traceback for the failed request.",
                )
                raise

            response.headers[REQUEST_ID_HEADER] = request_id
            log_event(
                "http.request_completed",
                level=(
                    logging.WARNING
                    if response.status_code >= status.HTTP_400_BAD_REQUEST
                    else logging.INFO
                ),
                operation="http_request",
                outcome=(
                    "failure"
                    if response.status_code >= status.HTTP_400_BAD_REQUEST
                    else "success"
                ),
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=int((perf_counter() - started_at) * 1000),
                run_id=getattr(request.state, "run_id", None),
            )
            return response

    @app.post(
        "/assessments",
        response_model=AssessmentResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_assessment(
        request: Request,
        payload: AssessmentCreateRequest,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> AssessmentResponse:
        try:
            campaign_config = {
                "attack_strategy": payload.attack_strategy,
                "attack_categories": payload.attack_categories,
                "attack_budget": payload.attack_budget,
                "seed": payload.seed,
            }
            run = service.create_assessment(
                target_type=payload.target_type,
                target_provider=payload.target_provider,
                target_model=payload.target_model,
                target_config=payload.target_config,
                campaign_config=campaign_config,
                request_id=request.state.request_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        request.state.run_id = run["id"]
        return AssessmentResponse(**run)

    @app.get("/assessments/{run_id}", response_model=AssessmentResponse)
    def get_assessment(
        request: Request,
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> AssessmentResponse:
        request.state.run_id = run_id
        run = service.get_assessment(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return AssessmentResponse(**run)

    @app.get("/assessments/{run_id}/report", response_model=ReportResponse)
    def get_report(
        request: Request,
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> ReportResponse:
        request.state.run_id = run_id
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
        request: Request,
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> EvidenceResponse:
        request.state.run_id = run_id
        evidence = service.get_evidence(run_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return EvidenceResponse(**evidence)

    @app.get("/assessments/{run_id}/report/export")
    def export_report(
        request: Request,
        run_id: str,
        format: str = Query("json", pattern="^(json|markdown)$"),
        service: AssessmentService = Depends(get_assessment_service),
    ):
        request.state.run_id = run_id
        run = service.get_assessment(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Assessment not found")
        if run["status"] != "completed":
            raise HTTPException(
                status_code=409,
                detail="Assessment report is only available after completion",
            )

        exported = service.export_report(run_id, format)
        if not exported:
            raise HTTPException(status_code=404, detail="Assessment not found")

        if format == "json":
            return JSONResponse(content=exported["content"])
        return PlainTextResponse(
            exported["content"],
            media_type=exported["media_type"],
        )

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
