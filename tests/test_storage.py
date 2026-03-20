import os
import tempfile
from pathlib import Path

import pytest

from redteaming_ai.storage import RunStorage


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def storage(temp_db):
    s = RunStorage(db_path=temp_db)
    s.init_db()
    yield s
    s.close()


def test_create_run(storage):
    run_id = storage.create_run(
        target_provider="mock", target_model=None, target_config={"test": True}
    )
    assert run_id is not None
    assert len(run_id) == 36

    run = storage.get_run(run_id)
    assert run["target_provider"] == "mock"
    assert run["target_config"] == {"test": True}


def test_record_attempt(storage):
    run_id = storage.create_run("mock", None, {})

    attempt_id = storage.record_attempt(
        run_id=run_id,
        agent_name="Test Agent",
        attack_type="prompt_injection",
        payload="test payload",
        response="test response",
        success=True,
        data_leaked=["credentials", "api_keys"],
    )

    assert attempt_id is not None

    run = storage.get_run(run_id)
    assert len(run["attempts"]) == 1
    assert run["attempts"][0]["payload"] == "test payload"
    assert run["attempts"][0]["success"] == 1
    assert run["attempts"][0]["data_leaked_json"] == '["credentials", "api_keys"]'


def test_complete_run(storage):
    run_id = storage.create_run("mock", None, {})

    storage.complete_run(run_id, 12.5)

    run = storage.get_run(run_id)
    assert run["completed_at"] is not None
    assert run["duration_seconds"] == 12.5


def test_save_report(storage):
    run_id = storage.create_run("mock", None, {})
    storage.complete_run(run_id, 10.0)

    summary = {
        "total_attacks": 10,
        "successful_attacks": 3,
        "success_rate": 30.0,
        "duration": 10.0,
    }

    report_id = storage.save_report(
        run_id=run_id,
        summary=summary,
        vulnerabilities=["No input sanitization"],
        leaked_data_types=["credentials"],
    )

    run = storage.get_run(run_id)
    assert run["report"] is not None
    assert run["report"]["run_id"] == run_id


def test_list_runs(storage):
    for i in range(3):
        run_id = storage.create_run("mock", None, {"run": i})
        storage.complete_run(run_id, 1.0)

    runs = storage.list_runs(limit=10)
    assert len(runs) == 3


def test_regenerate_report(storage):
    run_id = storage.create_run("mock", None, {})

    storage.record_attempt(
        run_id, "Agent1", "prompt_injection", "payload1", "response1", True, ["data1"]
    )
    storage.record_attempt(
        run_id, "Agent2", "data_exfiltration", "payload2", "response2", False, []
    )
    storage.complete_run(run_id, 5.0)

    report = storage.regenerate_report(run_id)

    assert report["summary"]["total_attacks"] == 2
    assert report["summary"]["successful_attacks"] == 1
    assert report["summary"]["success_rate"] == 50.0
    assert "data1" in report["leaked_data_types"]


def test_delete_run(storage):
    run_id = storage.create_run("mock", None, {})
    storage.record_attempt(run_id, "Agent", "test", "p", "r", False, [])
    storage.complete_run(run_id, 1.0)
    storage.save_report(run_id, {}, [], [])

    storage.delete_run(run_id)

    assert storage.get_run(run_id) is None


def test_get_stats(storage):
    run_id = storage.create_run("mock", None, {})
    storage.record_attempt(run_id, "Agent", "test", "p", "r", True, ["data"])
    storage.complete_run(run_id, 10.0)

    stats = storage.get_stats()
    assert stats["total_runs"] == 1
    assert stats["completed_runs"] == 1
    assert stats["total_attempts"] == 1
    assert stats["total_duration_seconds"] == 10.0
