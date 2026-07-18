from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256

from app.services.agent import action_counts, is_upload_allowed, recommended_model, risk_reasons, upload_decision
from app.services.audit import AuditRecord
from app.services.parser import ParsedDocument
from app.services.scanner.models import ScanResult


def build_risk_report(
    document: ParsedDocument,
    original: ScanResult,
    after_redaction: ScanResult,
    actions: dict[str, str],
) -> dict:
    return {
        "filename": document.filename,
        "file_type": document.file_type,
        "file_hash": sha256(document.text.encode("utf-8")).hexdigest(),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "original_risk": original.to_report(),
        "after_redaction": after_redaction.to_report(),
        "risk_reasons": risk_reasons(original),
        "action_counts": action_counts(actions),
        "recommended_model": recommended_model(after_redaction),
        "upload_decision": upload_decision(after_redaction),
        "upload_allowed": is_upload_allowed(after_redaction),
        "notice": "报告不包含原始敏感正文。",
    }


def build_credential_text(
    *,
    record: AuditRecord,
    original: ScanResult,
    after_redaction: ScanResult,
    actions: dict[str, str],
) -> str:
    lines = [
        "欣盾AI（SunShield AI）使用安全凭证",
        "",
        f"凭证编号：{record.credential_id}",
        f"扫描时间：{record.created_at}",
        f"文件名：{record.filename}",
        f"文件类型：{record.file_type}",
        f"文件 Hash：{record.file_hash}",
        f"目标平台：{record.target_platform}",
        f"原始风险：{original.risk_level.value} / {original.risk_score}",
        f"脱敏后风险：{after_redaction.risk_level.value} / {after_redaction.risk_score}",
        f"敏感项统计：{json.dumps(original.entity_counts, ensure_ascii=False, sort_keys=True)}",
        f"已执行动作：{json.dumps(action_counts(actions), ensure_ascii=False, sort_keys=True)}",
        f"推荐模型：{recommended_model(after_redaction)}",
        f"上传结论：{upload_decision(after_redaction)}",
        f"是否允许上传：{'是' if is_upload_allowed(after_redaction) else '否'}",
        "",
        "风险原因：",
        *[f"- {reason}" for reason in risk_reasons(original)],
        "",
        "说明：本凭证不包含原始敏感正文，仅记录类型、数量、风险等级、处理结果和文件 hash。",
    ]
    return "\n".join(lines)


def audit_record_to_dict(record: AuditRecord) -> dict:
    return asdict(record)
