from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SensitiveEntity:
    entity_id: str
    entity_type: str
    start: int
    end: int
    confidence: float
    severity: int
    evidence: str
    suggested_action: str
    detector: str
    location: dict[str, Any] = field(default_factory=dict)

    @property
    def original_hash(self) -> str:
        key = f"{self.entity_type}:{self.start}:{self.end}:{self.evidence}"
        return sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScanResult:
    entities: list[SensitiveEntity]
    risk_score: float
    risk_level: RiskLevel
    target_platform: str
    routing_recommendation: str

    @property
    def entity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entity in self.entities:
            counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
        return counts

    def to_report(self) -> dict[str, Any]:
        """Return a report safe for audit logs: no original sensitive text."""
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "target_platform": self.target_platform,
            "routing_recommendation": self.routing_recommendation,
            "entity_counts": self.entity_counts,
            "entities": [
                {
                    "entity_id": entity.entity_id,
                    "entity_type": entity.entity_type,
                    "start": entity.start,
                    "end": entity.end,
                    "confidence": entity.confidence,
                    "severity": entity.severity,
                    "suggested_action": entity.suggested_action,
                    "detector": entity.detector,
                    "location": entity.location,
                }
                for entity in self.entities
            ],
        }

