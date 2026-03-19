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
