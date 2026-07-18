from __future__ import annotations

from app.services.scanner.models import RiskLevel, SensitiveEntity
from app.services.scanner.policy import ScannerPolicy


def calculate_risk_score(
    entities: list[SensitiveEntity],
    target_platform: str,
    policy: ScannerPolicy,
) -> float:
    platform_coefficient = policy.target_coefficient_for(target_platform)
    score = 0.0
    type_counts: dict[str, int] = {}
    for entity in entities:
        type_counts[entity.entity_type] = type_counts.get(entity.entity_type, 0) + 1
        count_coefficient = 1 + min(type_counts[entity.entity_type] - 1, 8) * 0.12
        score += entity.severity * entity.confidence * count_coefficient
    return round(score * platform_coefficient, 2)


def classify_risk(score: float, policy: ScannerPolicy) -> RiskLevel:
    if score >= policy.critical_threshold:
        return RiskLevel.CRITICAL
    if score >= policy.high_threshold:
        return RiskLevel.HIGH
    if score >= policy.medium_threshold:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def recommend_route(risk_level: RiskLevel, target_platform: str) -> str:
    if risk_level == RiskLevel.CRITICAL:
        return "block_or_manual_review"
    if risk_level == RiskLevel.HIGH and target_platform in {"public_ai", "unknown_site"}:
        return "redact_before_public_ai_or_use_internal_model"
    if risk_level == RiskLevel.MEDIUM and target_platform == "public_ai":
        return "redact_before_public_ai"
    if target_platform in {"local_model", "internal_model"}:
        return "allowed_with_audit"
    return "allowed_after_user_confirmation"

