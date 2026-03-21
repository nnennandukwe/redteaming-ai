import json

import pytest

import redteaming_ai.attack_corpus as attack_corpus_module
import redteaming_ai.attack_generation as attack_generation_module
from redteaming_ai.attack_corpus import (
    VALID_ATTACK_TYPES,
    AttackCorpusEntry,
    CampaignConfig,
    load_attack_corpus,
)
from redteaming_ai.attack_generation import generate_attack_campaign


def test_corpus_assets_load_from_package_resources():
    entries = load_attack_corpus()

    assert entries
    assert all(isinstance(entry, AttackCorpusEntry) for entry in entries)
    assert {entry.attack_type for entry in entries} <= set(VALID_ATTACK_TYPES)


def test_disabled_corpus_entries_are_excluded_by_default():
    entries = load_attack_corpus(include_disabled=False)

    assert all(entry.enabled for entry in entries)
    assert "pi-004" not in {entry.id for entry in entries}


def test_corpus_order_is_stable_and_reviewable():
    entries = load_attack_corpus()

    assert [entry.id for entry in entries[:3]] == ["pi-001", "pi-002", "pi-003"]
    assert [entry.id for entry in entries[-3:]] == ["jb-001", "jb-002", "jb-003"]


def test_corpus_categories_filter_entries():
    entries = load_attack_corpus(["jailbreak"])

    assert entries
    assert {entry.attack_type for entry in entries} == {"jailbreak"}


def test_corpus_rejects_unknown_categories():
    with pytest.raises(ValueError, match="Unknown attack category"):
        load_attack_corpus(["not-a-real-category"])


def test_corpus_rejects_empty_payload_entries():
    with pytest.raises(ValueError, match="non-empty payload"):
        attack_corpus_module._validate_entry(
            {
                "id": "pi-empty",
                "attack_type": "prompt_injection",
                "payload": "   ",
            },
            filename="prompt_injection.json",
        )


def test_campaign_config_accepts_canonical_report_keys():
    config = CampaignConfig.from_mapping(
        {
            "strategy": "fuzz",
            "categories": ["jailbreak"],
            "attack_budget": 2,
            "seed": 5,
        }
    )

    assert config.attack_strategy == "fuzz"
    assert config.attack_categories == ["jailbreak"]
    assert config.attack_budget == 2
    assert config.seed == 5


def test_mutate_strategy_defensively_handles_empty_payloads(monkeypatch):
    empty_entry = AttackCorpusEntry(
        id="pi-empty",
        attack_type="prompt_injection",
        payload="",
        tags=[],
        enabled=True,
    )

    monkeypatch.setattr(
        attack_generation_module,
        "load_attack_corpus",
        lambda attack_categories=None, include_disabled=False: [empty_entry],
    )

    campaign = generate_attack_campaign(
        CampaignConfig(
            attack_strategy="mutate",
            attack_categories=["prompt_injection"],
            seed=7,
        )
    )

    assert len(campaign.attacks) == 1
    assert campaign.attacks[0].payload


def test_mutate_strategy_is_deterministic_for_same_seed():
    config = CampaignConfig(attack_strategy="mutate", seed=7)

    first = generate_attack_campaign(config)
    second = generate_attack_campaign(config)

    assert [attack.payload for attack in first.attacks] == [
        attack.payload for attack in second.attacks
    ]
    assert [attack.mutation_strategy for attack in first.attacks] == [
        attack.mutation_strategy for attack in second.attacks
    ]
    assert all(attack.payload != attack.source_payload for attack in first.attacks)


def test_fuzz_strategy_is_deterministic_per_seed_and_budget():
    config = CampaignConfig(attack_strategy="fuzz", seed=13, attack_budget=5)

    first = generate_attack_campaign(config)
    second = generate_attack_campaign(config)
    different = generate_attack_campaign(
        CampaignConfig(attack_strategy="fuzz", seed=14, attack_budget=5)
    )

    assert [attack.payload for attack in first.attacks] == [
        attack.payload for attack in second.attacks
    ]
    assert [attack.payload for attack in first.attacks] != [
        attack.payload for attack in different.attacks
    ]
    assert len(first.attacks) == 5


def test_campaign_coverage_tracks_selected_and_executed_entries():
    campaign = generate_attack_campaign(
        CampaignConfig(
            attack_categories=["prompt_injection", "jailbreak"],
            attack_strategy="corpus",
            seed=0,
        )
    )

    assert campaign.config.attack_categories == ["prompt_injection", "jailbreak"]
    assert set(campaign.coverage) == set(VALID_ATTACK_TYPES)
    assert campaign.coverage["data_exfiltration"].selected_total == 0
    assert campaign.coverage["prompt_injection"].executed_total == 3
    assert campaign.coverage["jailbreak"].executed_total == 3


def test_campaign_serializes_to_reviewable_dict():
    campaign = generate_attack_campaign(
        CampaignConfig(attack_strategy="mutate", seed=3)
    )
    payload = campaign.to_dict()

    assert payload["config"]["seed"] == 3
    assert payload["generated_attacks"] == len(campaign.attacks)
    assert json.loads(json.dumps(payload))["coverage"]["prompt_injection"][
        "selected_total"
    ] >= 1
