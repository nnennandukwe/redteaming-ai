from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from importlib import resources
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VALID_ATTACK_TYPES: Tuple[str, ...] = (
    "prompt_injection",
    "data_exfiltration",
    "jailbreak",
)

CORPUS_RESOURCE_PACKAGE = "redteaming_ai.corpus_assets"
CORPUS_RESOURCE_FILENAMES: Tuple[str, ...] = tuple(
    f"{attack_type}.json" for attack_type in VALID_ATTACK_TYPES
)


@dataclass(frozen=True)
class AttackCorpusEntry:
    id: str
    attack_type: str
    payload: str
    tags: List[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignConfig:
    attack_categories: List[str] = field(default_factory=lambda: list(VALID_ATTACK_TYPES))
    attack_strategy: str = "corpus"
    attack_budget: Optional[int] = None
    seed: int = 0

    def __post_init__(self) -> None:
        self.attack_categories = _normalize_attack_categories(self.attack_categories)
        if self.attack_strategy not in {"corpus", "mutate", "fuzz"}:
            raise ValueError(
                "attack_strategy must be one of: corpus, mutate, fuzz"
            )
        if self.attack_budget is not None and self.attack_budget < 0:
            raise ValueError("attack_budget must be >= 0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_categories": list(self.attack_categories),
            "attack_strategy": self.attack_strategy,
            "attack_budget": self.attack_budget,
            "seed": self.seed,
        }

    @classmethod
    def from_mapping(cls, value: Optional[Dict[str, Any]]) -> "CampaignConfig":
        if not value:
            return cls()
        attack_categories = value.get("attack_categories")
        if attack_categories is None:
            attack_categories = value.get("categories")
        attack_strategy = value.get("attack_strategy")
        if attack_strategy is None:
            attack_strategy = value.get("strategy", "corpus")
        return cls(
            attack_categories=attack_categories or list(VALID_ATTACK_TYPES),
            attack_strategy=attack_strategy or "corpus",
            attack_budget=value.get("attack_budget"),
            seed=value.get("seed", 0),
        )


def _normalize_attack_categories(categories: Optional[Sequence[str]]) -> List[str]:
    if categories is None:
        return list(VALID_ATTACK_TYPES)
    if isinstance(categories, str):
        categories = [categories]

    requested = []
    for category in categories:
        if category not in VALID_ATTACK_TYPES:
            raise ValueError(f"Unknown attack category: {category}")
        if category not in requested:
            requested.append(category)

    ordered = [category for category in VALID_ATTACK_TYPES if category in requested]
    return ordered


def _load_resource_json(filename: str) -> List[Dict[str, Any]]:
    package_files = resources.files(CORPUS_RESOURCE_PACKAGE)
    text = package_files.joinpath(filename).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError(f"Corpus resource {filename} must contain a JSON list")
    return data


def _validate_entry(raw_entry: Dict[str, Any], *, filename: str) -> AttackCorpusEntry:
    if not isinstance(raw_entry, dict):
        raise ValueError(f"Corpus entry in {filename} must be an object")

    required = {"id", "attack_type", "payload"}
    missing = [key for key in required if key not in raw_entry]
    if missing:
        raise ValueError(
            f"Corpus entry in {filename} is missing required keys: {', '.join(missing)}"
        )

    attack_type = raw_entry["attack_type"]
    if attack_type not in VALID_ATTACK_TYPES:
        raise ValueError(f"Corpus entry {raw_entry['id']} has invalid attack_type {attack_type}")

    tags = raw_entry.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError(f"Corpus entry {raw_entry['id']} must define tags as a list of strings")

    payload = str(raw_entry["payload"])
    if not payload.strip():
        raise ValueError(f"Corpus entry {raw_entry['id']} must define a non-empty payload")

    return AttackCorpusEntry(
        id=str(raw_entry["id"]),
        attack_type=str(attack_type),
        payload=payload,
        tags=list(tags),
        enabled=bool(raw_entry.get("enabled", True)),
    )


def load_attack_corpus(
    attack_categories: Optional[Sequence[str]] = None,
    *,
    include_disabled: bool = False,
) -> List[AttackCorpusEntry]:
    selected_categories = _normalize_attack_categories(attack_categories)
    selected_filenames = [
        filename
        for filename in CORPUS_RESOURCE_FILENAMES
        if filename.removesuffix(".json") in selected_categories
    ]

    entries: List[AttackCorpusEntry] = []
    for filename in selected_filenames:
        for raw_entry in _load_resource_json(filename):
            entry = _validate_entry(raw_entry, filename=filename)
            if entry.enabled or include_disabled:
                entries.append(entry)
    return entries


def group_corpus_by_type(
    entries: Iterable[AttackCorpusEntry],
) -> Dict[str, List[AttackCorpusEntry]]:
    grouped: Dict[str, List[AttackCorpusEntry]] = {key: [] for key in VALID_ATTACK_TYPES}
    for entry in entries:
        grouped.setdefault(entry.attack_type, []).append(entry)
    return grouped
