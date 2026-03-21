import asyncio
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor

import httpx

from redteaming_ai.api import create_app
from redteaming_ai.storage import RunStorage


class InlineExecutor:
    def submit(self, fn, *args, **kwargs):
        future = Future()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - Future consumes this in tests
            future.set_exception(exc)
        else:
            future.set_result(result)
        return future


class QueuedExecutor:
    def __init__(self):
        self.calls = []

    def submit(self, fn, *args, **kwargs):
        future = Future()
        self.calls.append((fn, args, kwargs, future))
        return future


async def _run_with_client(app, callback):
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await callback(client)


async def _create_target(client):
    response = await client.post(
        "/targets",
        json={
            "name": "Demo API Target",
            "target_type": "vulnerable_llm_app",
            "provider": "mock",
            "model": "demo-model",
            "config": {"mode": "api"},
        },
    )
    assert response.status_code == 201
    return response.json()


def test_targets_endpoints(tmp_path):
    app = create_app(db_path=tmp_path / "runs.db", executor=InlineExecutor())

    async def scenario(client):
        target = await _create_target(client)
        list_response = await client.get("/targets")
        get_response = await client.get(f"/targets/{target['id']}")
        docs_response = await client.get("/docs")
        invalid_target_response = await client.post(
            "/targets",
            json={
                "name": "Bad target",
                "target_type": "unsupported_target",
                "config": {},
            },
        )
        return list_response, get_response, docs_response, invalid_target_response

    list_response, get_response, docs_response, invalid_target_response = asyncio.run(
        _run_with_client(app, scenario)
    )

    assert list_response.status_code == 200
    assert len(list_response.json()) == 1
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Demo API Target"
    assert docs_response.status_code == 200
    assert invalid_target_response.status_code == 422


def test_assessment_endpoints_complete_and_return_report_and_evidence(tmp_path):
    app = create_app(db_path=tmp_path / "runs.db", executor=InlineExecutor())

    async def scenario(client):
        target = await _create_target(client)
        create_response = await client.post(
            "/assessments", json={"target_id": target["id"]}
        )
        assert create_response.status_code == 202
        run_id = create_response.json()["id"]
        assessment_response = await client.get(f"/assessments/{run_id}")
        report_response = await client.get(f"/assessments/{run_id}/report")
        evidence_response = await client.get(f"/assessments/{run_id}/evidence")
        return assessment_response, report_response, evidence_response

    assessment_response, report_response, evidence_response = asyncio.run(
        _run_with_client(app, scenario)
    )

    assert assessment_response.status_code == 200
    assert assessment_response.json()["status"] == "completed"
    assert report_response.status_code == 200
    assert report_response.json()["summary"]["total_attacks"] > 0
    assert report_response.json()["vulnerabilities"]
    assert evidence_response.status_code == 200
    assert evidence_response.json()["attempts"]


def test_unknown_target_and_run_return_404(tmp_path):
    app = create_app(db_path=tmp_path / "runs.db", executor=InlineExecutor())

    async def scenario(client):
        create_response = await client.post(
            "/assessments", json={"target_id": "missing-target"}
        )
        assessment_response = await client.get("/assessments/missing-run")
        report_response = await client.get("/assessments/missing-run/report")
        evidence_response = await client.get("/assessments/missing-run/evidence")
        return create_response, assessment_response, report_response, evidence_response

    create_response, assessment_response, report_response, evidence_response = (
        asyncio.run(_run_with_client(app, scenario))
    )

    assert create_response.status_code == 404
    assert assessment_response.status_code == 404
    assert report_response.status_code == 404
    assert evidence_response.status_code == 404


def test_report_is_unavailable_before_completion_and_evidence_is_available_while_running(
    tmp_path,
):
    started = threading.Event()
    release = threading.Event()

    def blocking_runner(storage, run_id, target):
        started.set()
        release.wait(timeout=5)
        storage.complete_run(run_id, 0.1)
        storage.save_report(
            run_id,
            {"total_attacks": 0, "successful_attacks": 0, "success_rate": 0.0, "duration": 0.1},
            [],
            [],
        )

    app = create_app(
        db_path=tmp_path / "runs.db",
        executor=ThreadPoolExecutor(max_workers=1),
        assessment_runner=blocking_runner,
    )

    async def scenario(client):
        target = await _create_target(client)
        create_response = await client.post(
            "/assessments", json={"target_id": target["id"]}
        )
        run_id = create_response.json()["id"]

        assert started.wait(timeout=5)

        report_response = await client.get(f"/assessments/{run_id}/report")
        evidence_response = await client.get(f"/assessments/{run_id}/evidence")

        release.set()
        deadline = time.time() + 5
        assessment_response = None
        while time.time() < deadline:
            assessment_response = await client.get(f"/assessments/{run_id}")
            if assessment_response.json()["status"] == "completed":
                break
            time.sleep(0.05)
        return report_response, evidence_response, assessment_response

    report_response, evidence_response, assessment_response = asyncio.run(
        _run_with_client(app, scenario)
    )

    assert report_response.status_code == 409
    assert evidence_response.status_code == 200
    assert evidence_response.json()["status"] == "running"
    assert assessment_response is not None
    assert assessment_response.status_code == 200
    assert assessment_response.json()["status"] == "completed"


def test_failed_assessment_and_worker_uses_fresh_connection(tmp_path):
    records = []

    class TrackingRunStorage(RunStorage):
        @property
        def conn(self):
            conn = super().conn
            records.append((threading.get_ident(), id(conn)))
            return conn

    def failing_runner(storage, run_id, target):
        raise RuntimeError("boom")

    app = create_app(
        db_path=tmp_path / "runs.db",
        executor=ThreadPoolExecutor(max_workers=1),
        assessment_runner=failing_runner,
        storage_cls=TrackingRunStorage,
    )

    async def scenario(client):
        target = await _create_target(client)
        create_response = await client.post(
            "/assessments", json={"target_id": target["id"]}
        )
        run_id = create_response.json()["id"]

        deadline = time.time() + 5
        assessment = None
        while time.time() < deadline:
            assessment = await client.get(f"/assessments/{run_id}")
            if assessment.json()["status"] == "failed":
                break
            time.sleep(0.05)
        return assessment

    assessment = asyncio.run(_run_with_client(app, scenario))

    assert assessment is not None
    assert assessment.status_code == 200
    assert assessment.json()["status"] == "failed"
    assert "boom" in assessment.json()["error_message"]
    assert len({thread_id for thread_id, _ in records}) >= 2
    assert len({conn_id for _, conn_id in records}) >= 2
