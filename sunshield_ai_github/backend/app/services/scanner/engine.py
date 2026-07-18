from __future__ import annotations

from hashlib import sha256

from app.services.scanner.dictionaries import EnterpriseDictionaries
from app.services.scanner.models import ScanResult, SensitiveEntity
from app.services.scanner.policy import ScannerPolicy
from app.services.scanner.risk import calculate_risk_score, classify_risk, recommend_route
from app.services.scanner.detect_secrets_adapter import iter_detect_secrets_matches
from app.services.scanner.rules import (
    deduplicate_overlaps,
    filter_allowlisted,
    iter_dictionary_matches,
    iter_high_entropy_matches,
    iter_regex_matches,
    make_entity_id,
)


def scan_text(
    text: str,
    *,
    target_platform: str = "public_ai",
    dictionaries: EnterpriseDictionaries | None = None,
    policy: ScannerPolicy | None = None,
) -> ScanResult:
    """Scan text locally and return explainable entities and aggregate risk."""
    active_policy = policy or ScannerPolicy.default()
    active_dictionaries = dictionaries or EnterpriseDictionaries.empty()

    raw_matches = [
        *iter_regex_matches(text),
        *iter_dictionary_matches(text, active_dictionaries),
        *iter_high_entropy_matches(text),
        *iter_detect_secrets_matches(text),
    ]
    allowed = filter_allowlisted(text, raw_matches, active_dictionaries.allowlist)
    unique_matches = deduplicate_overlaps(allowed, active_policy)

    entities = [
        SensitiveEntity(
            entity_id=_stable_entity_id(
                match.entity_type,
                match.start,
                match.end,
                text[match.start : match.end],
            ),
            entity_type=match.entity_type,
            start=match.start,
            end=match.end,
            confidence=match.confidence,
            severity=active_policy.severity_for(match.entity_type),
            evidence=match.evidence,
            suggested_action=match.suggested_action,
            detector=match.detector,
            location={"kind": "text", "start": match.start, "end": match.end},
        )
        for match in unique_matches
    ]
    risk_score = calculate_risk_score(entities, target_platform, active_policy)
    risk_level = classify_risk(risk_score, active_policy)
    return ScanResult(
        entities=entities,
        risk_score=risk_score,
        risk_level=risk_level,
        target_platform=target_platform,
        routing_recommendation=recommend_route(risk_level, target_platform),
    )


def _stable_entity_id(entity_type: str, start: int, end: int, value: str) -> str:
    digest = sha256(f"{entity_type}:{start}:{end}:{value}".encode("utf-8")).hexdigest()
    return f"ent_{digest[:12]}"
