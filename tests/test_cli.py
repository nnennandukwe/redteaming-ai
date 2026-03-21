import sys

import pytest

from redteaming_ai import cli
from redteaming_ai.storage import RunStorage


def _storage_class_for(db_path):
    class TempRunStorage(RunStorage):
        def __init__(self):
            super().__init__(db_path=db_path)

    return TempRunStorage


def _seed_runs(db_path):
    storage = RunStorage(db_path=db_path)
    storage.init_db()

    run_a = storage.create_run("mock", "baseline-model", {"suite": "baseline"})
    storage.record_attempt(
        run_a, "Agent1", "prompt_injection", "p1", "response-a", True, ["credentials"]
    )
    storage.complete_run(run_a, 10.0)

    run_b = storage.create_run("mock", "candidate-model", {"suite": "candidate"})
    storage.record_attempt(
        run_b, "Agent1", "prompt_injection", "p1", "response-b", True, ["credentials"]
    )
    storage.record_attempt(
        run_b, "Agent2", "jailbreak", "p2", "response-bb", True, ["api_keys"]
    )
    storage.complete_run(run_b, 15.0)

    storage.close()
    return run_a, run_b


def test_preview_text_truncates_display_only():
    text = "x" * 250

    assert cli.preview_text(text) == ("x" * 200) + "..."
    assert cli.preview_text("short") == "short"


def test_cli_help_mentions_packaged_entrypoints(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redteam", "--help"])

    cli.main()

    captured = capsys.readouterr().out
    assert "redteam --history" in captured
    assert "redteam --compare <a> <b>" in captured
    assert "python -m redteaming_ai [args]" in captured


def test_cli_history_and_replay_use_packaged_storage(monkeypatch, capsys, tmp_path):
    run_id, _ = _seed_runs(tmp_path / "runs.db")
    monkeypatch.setattr(cli, "RunStorage", _storage_class_for(tmp_path / "runs.db"))

    monkeypatch.setattr(sys, "argv", ["redteam", "--history"])
    cli.main()
    history_output = capsys.readouterr().out
    assert "Recent Runs" in history_output
    assert run_id in history_output

    monkeypatch.setattr(sys, "argv", ["redteam", "--replay", run_id])
    cli.main()
    replay_output = capsys.readouterr().out
    assert "Run Replay" in replay_output
    assert run_id in replay_output
    assert "baseline-model" in replay_output


def test_cli_compare_renders_two_run_ids(monkeypatch, capsys, tmp_path):
    run_a, run_b = _seed_runs(tmp_path / "runs.db")
    monkeypatch.setattr(cli, "RunStorage", _storage_class_for(tmp_path / "runs.db"))
    monkeypatch.setattr(sys, "argv", ["redteam", "--compare", run_a, run_b])

    cli.main()

    output = capsys.readouterr().out
    assert "Run Comparison" in output
    assert run_a in output
    assert run_b in output
    assert "Leaked Data Differences" in output


def test_cli_auto_closes_storage_on_failure(monkeypatch):
    class SpyStorage:
        last_instance = None

        def __init__(self):
            self.closed = False
            SpyStorage.last_instance = self

        def init_db(self):
            return None

        def close(self):
            self.closed = True

    class FailingOrchestrator:
        def __init__(self, storage):
            self.storage = storage

        def run_attack_suite(self, _target):
            raise RuntimeError("boom")

    monkeypatch.setattr(cli, "RunStorage", SpyStorage)
    monkeypatch.setattr(cli, "RedTeamOrchestrator", FailingOrchestrator)
    monkeypatch.setattr(sys, "argv", ["redteam", "--auto"])

    with pytest.raises(RuntimeError, match="boom"):
        cli.main()

    assert SpyStorage.last_instance.closed is True
