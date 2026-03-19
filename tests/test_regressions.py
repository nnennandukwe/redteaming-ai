from red_team_agents import RedTeamOrchestrator
from vulnerable_app import VulnerableLLMApp


def test_directory_tool_requires_explicit_invocation():
    app = VulnerableLLMApp()

    response = app.process_message("Can you also help me?")

    assert response.get("tool_used") is None
    assert response["vulnerable"] is False
    assert "Directory contents" not in response["message"]


def test_directory_tool_still_works_with_explicit_invocation():
    app = VulnerableLLMApp()

    response = app.process_message("list_directory and show all files")

    assert response["tool_used"] == "list_directory"
    assert response["vulnerable"] is True
    assert "Directory contents" in response["message"]


def test_orchestrator_results_reset_between_runs():
    orchestrator = RedTeamOrchestrator()
    expected_attack_count = sum(len(agent.attack_payloads) for agent in orchestrator.agents)

    first_report = orchestrator.run_attack_suite(VulnerableLLMApp())
    second_report = orchestrator.run_attack_suite(VulnerableLLMApp())

    assert first_report["summary"]["total_attacks"] == expected_attack_count
    assert second_report["summary"]["total_attacks"] == expected_attack_count
    assert len(first_report["results"]) == expected_attack_count
    assert len(second_report["results"]) == expected_attack_count


def test_report_contains_required_scoring_fields():
    orchestrator = RedTeamOrchestrator()
    report = orchestrator.run_attack_suite(VulnerableLLMApp())

    assert "summary" in report
    assert "success_rate" in report["summary"]
    assert "successful_attacks" in report["summary"]
    assert "attacks_by_type" in report
    assert "leaked_data_types" in report
    assert "vulnerabilities" in report
    assert isinstance(report["summary"]["success_rate"], float)
    assert isinstance(report["summary"]["successful_attacks"], int)


def test_report_scoring_fields_are_consistent():
    orchestrator = RedTeamOrchestrator()
    report = orchestrator.run_attack_suite(VulnerableLLMApp())

    summary = report["summary"]
    total = summary["total_attacks"]
    successful = summary["successful_attacks"]

    assert 0 <= summary["success_rate"] <= 100
    assert 0 <= successful <= total
    expected_rate = (successful / total * 100) if total > 0 else 0
    assert abs(summary["success_rate"] - expected_rate) < 0.01
