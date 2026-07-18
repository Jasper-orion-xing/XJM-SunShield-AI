from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256

from app.services.scanner.models import SensitiveEntity


class RedactionAction(StrEnum):
    KEEP = "keep"
    DELETE = "delete"
    MASK = "mask"
    CONSISTENT_LABEL = "consistent_label"
    HASH = "hash"
    GENERALIZE = "generalize"
    REVIEW = "review"


@dataclass
class ReplacementStore:
    namespace_id: str
    counters: dict[str, int] = field(default_factory=dict)
    mapping: dict[tuple[str, str], str] = field(default_factory=dict)

    def replacement_for(self, entity_type: str, original: str) -> str:
        digest = sha256(f"{self.namespace_id}:{entity_type}:{original}".encode("utf-8")).hexdigest()
        key = (entity_type, digest)
        if key not in self.mapping:
            self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
            self.mapping[key] = f"[{_display_name(entity_type)}{self.counters[entity_type]}]"
        return self.mapping[key]


def redact_text(
    text: str,
    entities: list[SensitiveEntity],
    *,
    namespace_id: str = "default",
    actions: dict[str, RedactionAction | str] | None = None,
) -> str:
    store = ReplacementStore(namespace_id=namespace_id)
    action_overrides = actions or {}
    output = text
    for entity in sorted(entities, key=lambda item: item.start, reverse=True):
        original = output[entity.start : entity.end]
        action = RedactionAction(action_overrides.get(entity.entity_id, entity.suggested_action))
        replacement = _replacement(action, entity.entity_type, original, store)
        output = output[: entity.start] + replacement + output[entity.end :]
    return output


def _replacement(
    action: RedactionAction,
    entity_type: str,
    original: str,
    store: ReplacementStore,
) -> str:
    if action == RedactionAction.KEEP:
        return original
    if action == RedactionAction.DELETE:
        return ""
    if action == RedactionAction.MASK:
        return _mask(original)
    if action == RedactionAction.HASH:
        return f"[HASH:{sha256(original.encode('utf-8')).hexdigest()[:12]}]"
    if action == RedactionAction.GENERALIZE:
        return _generalize_amount(original)
    if action == RedactionAction.REVIEW:
        return store.replacement_for(entity_type, original)
    return store.replacement_for(entity_type, original)


def _mask(value: str) -> str:
    compact = re.sub(r"\s+", "", value)
    if len(compact) <= 6:
        return "*" * len(value)
    return f"{compact[:3]}****{compact[-4:]}"


def _generalize_amount(value: str) -> str:
    return "[金额]"


def _display_name(entity_type: str) -> str:
    names = {
        "phone_number": "手机号",
        "email": "邮箱",
        "customer_name": "客户",
        "project_code": "项目编号",
        "product_model": "产品型号",
        "internal_domain": "内部域名",
        "internal_link": "内部链接",
        "api_key": "API密钥",
        "token": "Token",
        "secret": "Secret",
        "high_entropy": "高熵字符串",
    }
    return names.get(entity_type, entity_type)
