from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from app.services.scanner.models import ScanResult


DB_PATH = Path(__file__).resolve().parents[3] / "sunshield_ai.sqlite3"


@dataclass(frozen=True)
class AuditRecord:
    record_id: str
    credential_id: str
    created_at: str
    filename: str
    file_type: str
    file_hash: str
    target_platform: str
    risk_level: str
    risk_score: float
    entity_counts: dict[str, int]
    routing_recommendation: str
    original_risk_level: str | None = None
    original_risk_score: float | None = None
    action_counts: dict[str, int] | None = None
    recommended_model: str | None = None
    upload_allowed: bool | None = None


def init_db(db_path: Path = DB_PATH) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                record_id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                target_platform TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                entity_counts_json TEXT NOT NULL,
                routing_recommendation TEXT NOT NULL,
                original_risk_level TEXT,
                original_risk_score REAL,
                action_counts_json TEXT,
                recommended_model TEXT,
                upload_allowed INTEGER
            )
            """
        )
        existing = {
            row[1]
            for row in conn.execute("PRAGMA table_info(audit_logs)").fetchall()
        }
        migrations = {
            "original_risk_level": "ALTER TABLE audit_logs ADD COLUMN original_risk_level TEXT",
            "original_risk_score": "ALTER TABLE audit_logs ADD COLUMN original_risk_score REAL",
            "action_counts_json": "ALTER TABLE audit_logs ADD COLUMN action_counts_json TEXT",
            "recommended_model": "ALTER TABLE audit_logs ADD COLUMN recommended_model TEXT",
            "upload_allowed": "ALTER TABLE audit_logs ADD COLUMN upload_allowed INTEGER",
        }
        for column, sql in migrations.items():
            if column not in existing:
                conn.execute(sql)


def record_scan(
    *,
    filename: str,
    file_type: str,
    content: str,
    result: ScanResult,
    original_result: ScanResult | None = None,
    action_counts: dict[str, int] | None = None,
    recommended_model: str | None = None,
    upload_allowed: bool | None = None,
    db_path: Path = DB_PATH,
) -> AuditRecord:
    init_db(db_path)
    record_id = uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    file_hash = sha256(content.encode("utf-8")).hexdigest()
    credential_id = f"SP-{created_at[:10].replace('-', '')}-{record_id[:8].upper()}"
    entity_counts = result.entity_counts
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                record_id, credential_id, created_at, filename, file_type, file_hash,
                target_platform, risk_level, risk_score, entity_counts_json,
                routing_recommendation, original_risk_level, original_risk_score,
                action_counts_json, recommended_model, upload_allowed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                credential_id,
                created_at,
                filename,
                file_type,
                file_hash,
                result.target_platform,
                result.risk_level.value,
                result.risk_score,
                json.dumps(entity_counts, ensure_ascii=False, sort_keys=True),
                result.routing_recommendation,
                original_result.risk_level.value if original_result else None,
                original_result.risk_score if original_result else None,
                json.dumps(action_counts or {}, ensure_ascii=False, sort_keys=True),
                recommended_model,
                None if upload_allowed is None else int(upload_allowed),
            ),
        )
    return AuditRecord(
        record_id=record_id,
        credential_id=credential_id,
        created_at=created_at,
        filename=filename,
        file_type=file_type,
        file_hash=file_hash,
        target_platform=result.target_platform,
        risk_level=result.risk_level.value,
        risk_score=result.risk_score,
        entity_counts=entity_counts,
        routing_recommendation=result.routing_recommendation,
        original_risk_level=original_result.risk_level.value if original_result else None,
        original_risk_score=original_result.risk_score if original_result else None,
        action_counts=action_counts or {},
        recommended_model=recommended_model,
        upload_allowed=upload_allowed,
    )


def list_recent_records(limit: int = 10, db_path: Path = DB_PATH) -> list[AuditRecord]:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT record_id, credential_id, created_at, filename, file_type, file_hash,
                   target_platform, risk_level, risk_score, entity_counts_json,
                   routing_recommendation, original_risk_level, original_risk_score,
                   action_counts_json, recommended_model, upload_allowed
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        AuditRecord(
            record_id=row[0],
            credential_id=row[1],
            created_at=row[2],
            filename=row[3],
            file_type=row[4],
            file_hash=row[5],
            target_platform=row[6],
            risk_level=row[7],
            risk_score=row[8],
            entity_counts=json.loads(row[9]),
            routing_recommendation=row[10],
            original_risk_level=row[11],
            original_risk_score=row[12],
            action_counts=json.loads(row[13] or "{}"),
            recommended_model=row[14],
            upload_allowed=None if row[15] is None else bool(row[15]),
        )
        for row in rows
    ]
