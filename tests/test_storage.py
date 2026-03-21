import sqlite3
import tempfile
from pathlib import Path

import pytest

from redteaming_ai.agents import PromptInjectionAgent
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

    storage.save_report(
        run_id=run_id,
        summary=summary,
        vulnerabilities=["No input sanitization"],
        leaked_data_types=["credentials"],
    )

    run = storage.get_run(run_id)
    assert run["report"] is not None
    assert run["report"]["run_id"] == run_id
    assert run["report"]["leaked_data_types_json"] == '["credentials"]'


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
    assert stats["total_targets"] == 1
    assert stats["total_runs"] == 1
    assert stats["completed_runs"] == 1
    assert stats["total_attempts"] == 1
    assert stats["total_duration_seconds"] == 10.0


def test_full_response_is_preserved_in_storage(storage):
    long_message = "sensitive-" * 40

    class DummyTarget:
        def process_message(self, _payload):
            return {"message": long_message, "vulnerable": True}

    agent = PromptInjectionAgent()
    agent.attack_payloads = ["payload"]

    result = agent.attack(DummyTarget())[0]
    assert result.response == long_message

    run_id = storage.create_run("mock", None, {"test": True})
    storage.record_attempt(
        run_id=run_id,
        agent_name=result.agent_name,
        attack_type=result.attack_type,
        payload=result.payload,
        response=result.response,
        success=result.success,
        data_leaked=result.data_leaked,
    )

    run = storage.get_run(run_id)
    assert run["attempts"][0]["response"] == long_message


def test_compare_runs_returns_summary_and_attack_deltas(storage):
    first_run = storage.create_run("mock", None, {"suite": "baseline"})
    storage.record_attempt(
        first_run, "Agent1", "prompt_injection", "p1", "r1", True, ["credentials"]
    )
    storage.record_attempt(first_run, "Agent2", "jailbreak", "p2", "r2", False, [])
    storage.complete_run(first_run, 10.0)

    second_run = storage.create_run("mock", None, {"suite": "candidate"})
    storage.record_attempt(
        second_run, "Agent1", "prompt_injection", "p1", "r1", True, ["credentials"]
    )
    storage.record_attempt(
        second_run, "Agent2", "jailbreak", "p2", "r2", True, ["api_keys"]
    )
    storage.record_attempt(
        second_run, "Agent3", "data_exfiltration", "p3", "r3", False, []
    )
    storage.complete_run(second_run, 15.0)

    comparison = storage.compare_runs(first_run, second_run)

    assert comparison["summary_delta"]["total_attacks"] == 1
    assert comparison["summary_delta"]["successful_attacks"] == 1
    assert comparison["summary_delta"]["duration"] == 5.0
    assert comparison["attack_type_deltas"]["jailbreak"]["delta"]["successful"] == 1
    assert comparison["attack_type_deltas"]["data_exfiltration"]["run_a"]["total"] == 0
    assert comparison["leaked_data"]["only_in_run_b"] == ["api_keys"]


def test_init_db_migrates_v1_runs_to_targets_schema(temp_db):
    conn = sqlite3.connect(temp_db)
    conn.execute("""
        CREATE TABLE _schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "INSERT INTO _schema_version (version, applied_at) VALUES (1, ?)",
        ("2026-03-20T00:00:00",),
    )
    conn.execute("""
        CREATE TABLE runs (
            id TEXT PRIMARY KEY,
            target_provider TEXT,
            target_model TEXT,
            target_config_json TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_seconds REAL
        )
    """)
    conn.execute("""
        INSERT INTO runs (
            id, target_provider, target_model, target_config_json, started_at
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        "legacy-run",
        "mock",
        "demo-model",
        '{"mode":"legacy"}',
        "2026-03-20T00:00:00",
    ))
    conn.commit()
    conn.close()

    storage = RunStorage(db_path=temp_db)
    storage.init_db()

    run = storage.get_run("legacy-run")
    stats = storage.get_stats()

    assert run["target_id"] is not None
    assert run["target_provider"] == "mock"
    assert run["target_model"] == "demo-model"
    assert run["target_config"] == {"mode": "legacy"}
    assert stats["total_targets"] == 1
    assert storage.conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 2

    storage.close()
