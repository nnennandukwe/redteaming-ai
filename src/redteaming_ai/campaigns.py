"""Compatibility shim for legacy imports.

This module bridges the maintained corpus/generator subsystem into the
older agent imports without changing the existing agent implementation.
"""

from __future__ import annotations

from typing import Dict, List

from redteaming_ai.attack_corpus import VALID_ATTACK_TYPES, CampaignConfig
from redteaming_ai.attack_generation import (
    GeneratedAttack,
    GeneratedCampaign,
    generate_attack_campaign,
)

ATTACK_CATEGORIES = VALID_ATTACK_TYPES
ATTACK_STRATEGIES = ("corpus", "mutate", "fuzz")


def build_attack_campaign(config: CampaignConfig | None = None) -> GeneratedCampaign:
    return generate_attack_campaign(config)


def group_campaign_attacks(campaign: GeneratedCampaign) -> Dict[str, List[GeneratedAttack]]:
    grouped: Dict[str, List[GeneratedAttack]] = {attack_type: [] for attack_type in ATTACK_CATEGORIES}
    for attack in campaign.attacks:
        grouped.setdefault(attack.attack_type, []).append(attack)
    return grouped
