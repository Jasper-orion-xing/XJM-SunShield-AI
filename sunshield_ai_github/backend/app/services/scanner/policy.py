from __future__ import annotations

from dataclasses import dataclass


DEFAULT_SEVERITY = {
    "phone_number": 4,
    "email": 3,
    "chinese_id": 5,
    "bank_card": 5,
    "quoted_amount": 4,
    "project_code": 4,
    "product_model": 3,
    "internal_domain": 4,
    "internal_link": 4,
    "confidentiality_label": 5,
    "api_key": 5,
    "token": 5,
    "secret": 5,
    "password": 5,
    "private_key": 5,
    "access_key": 5,
    "high_entropy": 4,
    "customer_name": 3,
    "denylist": 5,
}

TARGET_COEFFICIENTS = {
    "local_model": 0.5,
    "internal_model": 0.8,
    "approved_enterprise_model": 1.0,
    "public_ai": 1.5,
    "unknown_site": 2.0,
}


@dataclass(frozen=True)
class ScannerPolicy:
    severity: dict[str, int]
    target_coefficients: dict[str, float]
    low_threshold: float = 6.0
    medium_threshold: float = 14.0
    high_threshold: float = 26.0
    critical_threshold: float = 40.0

    @classmethod
    def default(cls) -> "ScannerPolicy":
        return cls(
            severity=DEFAULT_SEVERITY.copy(),
            target_coefficients=TARGET_COEFFICIENTS.copy(),
        )

    def severity_for(self, entity_type: str) -> int:
        return self.severity.get(entity_type, 2)

    def target_coefficient_for(self, target_platform: str) -> float:
        return self.target_coefficients.get(target_platform, 1.5)

