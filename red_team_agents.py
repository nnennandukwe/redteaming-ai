"""
Backward-compatibility wrapper.
Core implementation moved to src/redteaming_ai/agents.py
"""

from redteaming_ai.agents import (
    AttackResult,
    DataExfiltrationAgent,
    JailbreakAgent,
    PromptInjectionAgent,
    RedTeamAgent,
    RedTeamOrchestrator,
)

__all__ = [
    "AttackResult",
    "DataExfiltrationAgent",
    "JailbreakAgent",
    "PromptInjectionAgent",
    "RedTeamAgent",
    "RedTeamOrchestrator",
]


if __name__ == "__main__":
    from rich.console import Console

    from redteaming_ai.target import VulnerableLLMApp

    console = Console()
    console.print("[bold green]Initializing Red Team Demo...[/bold green]")

    target = VulnerableLLMApp()
    orchestrator = RedTeamOrchestrator()
    report = orchestrator.run_attack_suite(target)

    console.print("\n[bold green]✓ Red Team Assessment Complete![/bold green]")
