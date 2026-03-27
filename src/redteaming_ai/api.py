from __future__ import annotations

import logging
from concurrent.futures import Executor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse

from redteaming_ai.api_models import (
    AssessmentCreateRequest,
    AssessmentResponse,
    EvidenceResponse,
    ReportResponse,
)
from redteaming_ai.assessment_service import AssessmentRunner, AssessmentService
from redteaming_ai.observability import (
    REQUEST_ID_HEADER,
    log_error,
    log_info,
    log_warning,
    request_id_context,
    resolve_request_id,
    safe_validation_errors,
    sanitize_text,
)
from redteaming_ai.storage import RunStorage

logger = logging.getLogger("redteaming_ai.api")


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
    async def request_id_middleware(request: Request, call_next):
        request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        with request_id_context(request_id):
            try:
                response = await call_next(request)
            except Exception as exc:
                log_error(
                    logger,
                    "request_processing",
                    "failed",
                    method=request.method,
                    path=request.url.path,
                    error_type=type(exc).__name__,
                    hint="Inspect application logs for the server-side failure.",
                )
                response = JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": "Internal Server Error"},
                )
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError):
        log_warning(
            logger,
            "request_validation",
            "invalid",
            method=request.method,
            path=request.url.path,
            validation_errors=safe_validation_errors(exc.errors()),
            hint="Fix the request payload so it matches the API schema.",
        )
        return await request_validation_exception_handler(request, exc)

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
            )
        except ValueError as exc:
            log_warning(
                logger,
                "assessment_create",
                "rejected",
                error_type=type(exc).__name__,
                target_type=payload.target_type,
                hint="Check target configuration and required fields.",
            )
            raise HTTPException(status_code=400, detail=sanitize_text(str(exc))) from exc
        log_info(
            logger,
            "assessment_create",
            "accepted",
            run_id=run["id"],
            target_type=payload.target_type,
            status=run["status"],
        )
        return AssessmentResponse(**run)

    @app.get("/assessments/{run_id}", response_model=AssessmentResponse)
    def get_assessment(
        run_id: str,
        service: AssessmentService = Depends(get_assessment_service),
    ) -> AssessmentResponse:
        run = service.get_assessment(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return AssessmentResponse(**run)

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

    @app.get("/assessments/{run_id}/report/export")
    def export_report(
        run_id: str,
        format: str = Query("json", pattern="^(json|markdown)$"),
        service: AssessmentService = Depends(get_assessment_service),
    ):
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
