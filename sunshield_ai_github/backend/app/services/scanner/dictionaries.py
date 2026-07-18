from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class EnterpriseDictionaries:
    customers: list[str] = field(default_factory=list)
    project_codes: list[str] = field(default_factory=list)
    product_models: list[str] = field(default_factory=list)
    internal_domains: list[str] = field(default_factory=list)
    confidential_terms: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)

    @classmethod
    def empty(cls) -> "EnterpriseDictionaries":
        return cls()


def load_items_file(path: Path) -> list[str]:
    """Load a tiny YAML subset used by example enterprise dictionaries."""
    if not path.exists():
        return []
    items: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "items:":
            continue
        if line.startswith("- "):
            value = line[2:].strip().strip("\"'")
            if value:
                items.append(value)
    return items


def load_enterprise_dictionaries(config_dir: Path) -> EnterpriseDictionaries:
    return EnterpriseDictionaries(
        customers=load_items_file(config_dir / "customers.example.yaml"),
        project_codes=load_items_file(config_dir / "project_codes.example.yaml"),
        product_models=load_items_file(config_dir / "product_models.example.yaml"),
        internal_domains=load_items_file(config_dir / "internal_domains.example.yaml"),
        confidential_terms=load_items_file(config_dir / "confidential_terms.example.yaml"),
        allowlist=load_items_file(config_dir / "allowlist.example.yaml"),
        denylist=load_items_file(config_dir / "denylist.example.yaml"),
    )

