from __future__ import annotations

from typing import Iterable

from app.services.scanner.rules import RuleMatch


SECRET_TYPE_MAP = {
    "AWS Access Key": "access_key",
    "OpenAI Token": "api_key",
    "GitHub Token": "token",
    "GitLab Token": "token",
    "JSON Web Token": "token",
    "Private Key": "private_key",
    "Base64 High Entropy String": "high_entropy",
    "Hex High Entropy String": "high_entropy",
    "Secret Keyword": "secret",
    "Basic Auth Credentials": "password",
    "Slack Token": "token",
    "Stripe Access Key": "access_key",
    "SendGrid API Key": "api_key",
}


def iter_detect_secrets_matches(text: str) -> Iterable[RuleMatch]:
    """
    Scan uploaded text with detect-secrets when it is installed.

    The adapter intentionally degrades silently when the package is absent, so
    SunShield AI remains usable as a lightweight standalone Streamlit app.
    """
    try:
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import transient_settings
    except Exception:
        return []

    matches: list[RuleMatch] = []
    config = {
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "OpenAIDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "KeywordDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "SlackDetector"},
            {"name": "StripeDetector"},
            {"name": "SendGridDetector"},
            {"name": "Base64HighEntropyString", "limit": 4.5},
            {"name": "HexHighEntropyString", "limit": 3.2},
        ],
        "filters_used": [
            {"path": "detect_secrets.filters.heuristic.is_sequential_string"},
            {"path": "detect_secrets.filters.heuristic.is_potential_uuid"},
            {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
            {"path": "detect_secrets.filters.heuristic.is_templated_secret"},
            {"path": "detect_secrets.filters.heuristic.is_indirect_reference"},
            {"path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"},
        ],
    }

    cursor = 0
    with transient_settings(config):
        for line in text.splitlines(keepends=True):
            stripped = line.rstrip("\r\n")
            if stripped:
                for secret in scan_line(stripped):
                    secret_value = secret.secret_value or ""
                    if len(secret_value) < 8:
                        continue
                    if secret.type in {"Base64 High Entropy String", "Hex High Entropy String"} and len(
                        secret_value
                    ) < 24:
                        continue
                    relative_start = stripped.find(secret_value)
                    if relative_start < 0:
                        continue
                    entity_type = SECRET_TYPE_MAP.get(secret.type, "secret")
                    matches.append(
                        RuleMatch(
                            entity_type=entity_type,
                            start=cursor + relative_start,
                            end=cursor + relative_start + len(secret_value),
                            confidence=0.9,
                            evidence=f"Matched detect-secrets plugin: {secret.type}",
                            suggested_action="delete"
                            if entity_type
                            in {"api_key", "token", "secret", "password", "private_key", "access_key"}
                            else "review",
                            detector="detect_secrets",
                        )
                    )
            cursor += len(line)
    return matches
