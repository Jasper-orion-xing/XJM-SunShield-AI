from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from uuid import uuid4

from app.services.scanner.dictionaries import EnterpriseDictionaries
from app.services.scanner.policy import ScannerPolicy


@dataclass(frozen=True)
class RuleMatch:
    entity_type: str
    start: int
    end: int
    confidence: float
    evidence: str
    suggested_action: str
    detector: str


REGEX_RULES: tuple[tuple[str, re.Pattern[str], float, str], ...] = (
    (
        "phone_number",
        re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
        0.96,
        "mask",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
        "consistent_label",
    ),
    (
        "chinese_id",
        re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"),
        0.95,
        "delete",
    ),
    (
        "bank_card",
        re.compile(r"(?<!\d)(?:\d[ -]?){16,19}(?!\d)"),
        0.78,
        "mask",
    ),
    (
        "quoted_amount",
        re.compile(r"(?:RMB|CNY|USD|EUR|￥|\$)?\s?\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?\s?(?:元|万元|美元|人民币)?|\d+(?:\.\d+)?\s?(?:万元|亿元|元|美元|人民币)"),
        0.82,
        "generalize",
    ),
    (
        "project_code",
        re.compile(r"\b[A-Z]{2,6}-[A-Z0-9]{2,8}-20\d{2}-\d{2,5}\b"),
        0.86,
        "consistent_label",
    ),
    (
        "product_model",
        re.compile(r"\b[A-Z][A-Za-z]{1,8}[-_][A-Z0-9]{1,8}(?:[-_][A-Z0-9]{1,8})?\b"),
        0.62,
        "review",
    ),
    (
        "internal_link",
        re.compile(r"\bhttps?://(?:[A-Za-z0-9-]+\.)*(?:local|lan|corp|internal|intranet)(?:/[^\s]*)?", re.IGNORECASE),
        0.9,
        "consistent_label",
    ),
    (
        "ip_address",
        re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2}\b"),
        0.85,
        "consistent_label",
    ),
    (
        "database_connection",
        re.compile(r"\b(?:postgresql|postgres|mysql|mongodb|redis)://[^\s\"']+", re.IGNORECASE),
        0.94,
        "delete",
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        0.99,
        "delete",
    ),
    (
        "access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0.98,
        "delete",
    ),
    (
        "api_key",
        re.compile(r"\b(?:sk|pk|rk|api)[-_][A-Za-z0-9]{20,}\b"),
        0.9,
        "delete",
    ),
    (
        "token",
        re.compile(r"\b(?:token|access_token|refresh_token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
        0.9,
        "delete",
    ),
    (
        "password",
        re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}", re.IGNORECASE),
        0.9,
        "delete",
    ),
    (
        "secret",
        re.compile(r"\b(?:secret|client_secret)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
        0.9,
        "delete",
    ),
)


def iter_regex_matches(text: str) -> Iterable[RuleMatch]:
    for entity_type, pattern, confidence, action in REGEX_RULES:
        for match in pattern.finditer(text):
            yield RuleMatch(
                entity_type=entity_type,
                start=match.start(),
                end=match.end(),
                confidence=confidence,
                evidence=f"Matched local {entity_type} rule",
                suggested_action=action,
                detector="local_regex",
            )


def iter_dictionary_matches(
    text: str,
    dictionaries: EnterpriseDictionaries,
) -> Iterable[RuleMatch]:
    sources = (
        ("customer_name", dictionaries.customers, 0.9, "consistent_label"),
        ("project_code", dictionaries.project_codes, 0.94, "consistent_label"),
        ("product_model", dictionaries.product_models, 0.9, "review"),
        ("internal_domain", dictionaries.internal_domains, 0.94, "consistent_label"),
        ("confidentiality_label", dictionaries.confidential_terms, 0.92, "delete"),
        ("denylist", dictionaries.denylist, 0.95, "delete"),
    )
    for entity_type, terms, confidence, action in sources:
        for term in terms:
            if not term:
                continue
            for match in re.finditer(re.escape(term), text, re.IGNORECASE):
                yield RuleMatch(
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    evidence=f"Matched enterprise dictionary term: {entity_type}",
                    suggested_action=action,
                    detector="enterprise_dictionary",
                )


def iter_high_entropy_matches(text: str) -> Iterable[RuleMatch]:
    token_pattern = re.compile(r"\b[A-Za-z0-9+/=_-]{28,}\b")
    for match in token_pattern.finditer(text):
        value = match.group(0)
        if _shannon_entropy(value) < 4.2:
            continue
        yield RuleMatch(
            entity_type="high_entropy",
            start=match.start(),
            end=match.end(),
            confidence=0.72,
            evidence="High entropy string with secret-like shape",
            suggested_action="review",
            detector="entropy",
        )


def filter_allowlisted(
    text: str,
    matches: Iterable[RuleMatch],
    allowlist: list[str],
) -> list[RuleMatch]:
    lowered_allowlist = [item.lower() for item in allowlist]
    kept: list[RuleMatch] = []
    for match in matches:
        value = text[match.start : match.end].lower()
        if any(allowed and allowed in value for allowed in lowered_allowlist):
            continue
        kept.append(match)
    return kept


def deduplicate_overlaps(matches: Iterable[RuleMatch], policy: ScannerPolicy) -> list[RuleMatch]:
    sorted_matches = sorted(
        matches,
        key=lambda match: (
            match.start,
            -(match.end - match.start),
            -policy.severity_for(match.entity_type),
            -match.confidence,
        ),
    )
    accepted: list[RuleMatch] = []
    for candidate in sorted_matches:
        if any(_overlaps(candidate, existing) for existing in accepted):
            continue
        accepted.append(candidate)
    return sorted(accepted, key=lambda match: (match.start, match.end))


def make_entity_id() -> str:
    return f"ent_{uuid4().hex[:12]}"


def _overlaps(left: RuleMatch, right: RuleMatch) -> bool:
    return left.start < right.end and right.start < left.end


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

