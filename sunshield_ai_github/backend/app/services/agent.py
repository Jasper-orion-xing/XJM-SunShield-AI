from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from app.services.parser import ParsedDocument
from app.services.scanner.models import ScanResult, SensitiveEntity


CONTACT_TYPES = {"phone_number", "email", "chinese_id", "bank_card"}
CREDENTIAL_TYPES = {
    "api_key",
    "token",
    "secret",
    "password",
    "private_key",
    "access_key",
    "database_connection",
    "high_entropy",
}
CUSTOMER_TYPES = {"customer_name", "project_code", "project_name"}
INTERNAL_TYPES = {"internal_domain", "internal_link", "ip_address", "server_address"}
AMOUNT_TYPES = {"quoted_amount", "payment_terms"}


@dataclass(frozen=True)
class AgentStep:
    step_no: int
    title: str
    status: str
    detail: str


def default_action_for_entity(entity: SensitiveEntity) -> str:
    if entity.entity_type in {"phone_number", "bank_card"}:
        return "mask"
    if entity.entity_type in {"email", "customer_name", "project_code", "internal_domain", "internal_link", "ip_address"}:
        return "consistent_label"
    if entity.entity_type in CREDENTIAL_TYPES:
        return "delete"
    if entity.entity_type in AMOUNT_TYPES:
        return "generalize"
    if entity.suggested_action == "review":
        return "consistent_label"
    return entity.suggested_action


def default_action_map(entities: list[SensitiveEntity]) -> dict[str, str]:
    return {entity.entity_id: default_action_for_entity(entity) for entity in entities}


def action_counts(actions: dict[str, str]) -> dict[str, int]:
    return dict(Counter(actions.values()))


def risk_reasons(result: ScanResult) -> list[str]:
    types = {entity.entity_type for entity in result.entities}
    reasons: list[str] = []
    if types & CREDENTIAL_TYPES:
        reasons.append("发现凭证、密钥、Token、数据库连接或高熵字符串。")
    if types & CUSTOMER_TYPES:
        reasons.append("发现客户名称、项目编号或项目相关商业信息。")
    if types & CONTACT_TYPES:
        reasons.append("发现手机号、邮箱、身份证或银行卡等个人信息。")
    if types & INTERNAL_TYPES:
        reasons.append("发现内部域名、内部链接、内网 IP 或服务器地址。")
    if types & AMOUNT_TYPES:
        reasons.append("发现报价、合同金额或付款条件。")
    if result.target_platform in {"public_ai", "unknown_site"}:
        reasons.append("目标平台为公共 AI 或未知网站，外发系数较高。")
    if not reasons:
        reasons.append("未发现明显高风险敏感类型，但仍建议人工复核重要文件。")
    return reasons


def recommended_model(result: ScanResult) -> str:
    if result.risk_level.value == "critical":
        return "仅允许本地模型或人工复核后使用内部模型"
    if result.risk_level.value == "high":
        return "优先内部模型；如需公共 AI，必须先脱敏"
    if result.target_platform == "public_ai":
        return "脱敏后可使用批准的公共 AI 或企业云模型"
    if result.target_platform in {"local_model", "internal_model"}:
        return "可使用当前目标平台，并保留审计记录"
    return "建议使用批准的企业云模型"


def upload_decision(result: ScanResult) -> str:
    has_credentials = any(entity.entity_type in CREDENTIAL_TYPES for entity in result.entities)
    if has_credentials and result.target_platform in {"public_ai", "unknown_site"}:
        return "禁止直接上传"
    if result.risk_level.value == "critical":
        return "禁止直接上传"
    if result.risk_level.value == "high" and result.target_platform in {"public_ai", "unknown_site"}:
        return "脱敏后才可上传"
    if result.risk_level.value in {"medium", "high"}:
        return "确认后可在受控平台使用"
    return "可确认后上传"


def is_upload_allowed(result: ScanResult) -> bool:
    return upload_decision(result) != "禁止直接上传"


def decision_explanation(original: ScanResult, after_redaction: ScanResult) -> str:
    reasons = "；".join(risk_reasons(original))
    return (
        f"Agent 判断：原始风险为{_risk_zh(original.risk_level.value)}，脱敏后风险为"
        f"{_risk_zh(after_redaction.risk_level.value)}。{reasons} "
        f"因此建议：{upload_decision(after_redaction)}，推荐模型：{recommended_model(after_redaction)}。"
    )


def build_agent_steps(
    document: ParsedDocument,
    original: ScanResult,
    after_redaction: ScanResult,
    actions: dict[str, str],
    *,
    credential_ready: bool = False,
) -> list[AgentStep]:
    has_entities = bool(original.entities)
    has_credentials = any(entity.entity_type in CREDENTIAL_TYPES for entity in original.entities)
    return [
        AgentStep(1, "解析文件", "已完成", f"已解析 {document.file_type.upper()}，抽取 {len(document.text)} 个字符。"),
        AgentStep(2, "本地扫描敏感信息", "已完成", f"识别 {len(original.entities)} 个风险项。"),
        AgentStep(3, "识别凭证和高风险内容", "已完成" if has_credentials else "已完成", "发现凭证类高风险内容。" if has_credentials else "未发现明显凭证类内容。"),
        AgentStep(4, "计算风险等级", "已完成", f"原始风险 {_risk_zh(original.risk_level.value)}，分数 {original.risk_score}。"),
        AgentStep(5, "生成脱敏建议", "已完成" if has_entities else "已完成", "已为每个敏感项生成默认处理建议。"),
        AgentStep(6, "用户人工确认", "需人工确认" if has_entities else "已完成", "可逐项调整，也可一键智能处理。"),
        AgentStep(7, "生成脱敏副本", "已完成", f"脱敏后风险 {_risk_zh(after_redaction.risk_level.value)}，分数 {after_redaction.risk_score}。"),
        AgentStep(8, "给出目标平台分流建议", "已完成", recommended_model(after_redaction)),
        AgentStep(9, "生成安全凭证和扫描历史", "已完成" if credential_ready else "待执行", "点击生成安全凭证后写入本地审计。"),
    ]


def _risk_zh(value: str) -> str:
    return {
        "low": "低",
        "medium": "中",
        "high": "高",
        "critical": "严重",
    }.get(value, value)
