from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(BACKEND))

from app.services.agent import (
    action_counts,
    build_agent_steps,
    decision_explanation,
    default_action_for_entity,
    default_action_map,
    is_upload_allowed,
    recommended_model,
    risk_reasons,
    upload_decision,
)
from app.services.audit import list_recent_records, record_scan
from app.services.exporter import build_action_preferences, export_redacted_original
from app.services.parser import ParsedDocument, parse_upload
from app.services.report import build_credential_text, build_risk_report
from app.services.scanner.dictionaries import EnterpriseDictionaries, load_enterprise_dictionaries
from app.services.scanner.engine import scan_text
from app.services.scanner.models import ScanResult, SensitiveEntity
from app.services.scanner.redactor import RedactionAction, redact_text


ACTION_LABELS = {
    RedactionAction.CONSISTENT_LABEL.value: "标签替换",
    RedactionAction.MASK.value: "遮盖",
    RedactionAction.DELETE.value: "删除",
    RedactionAction.GENERALIZE.value: "泛化",
    RedactionAction.HASH.value: "哈希",
    RedactionAction.KEEP.value: "保留",
    RedactionAction.REVIEW.value: "先按标签替换",
}

ENTITY_LABELS = {
    "phone_number": "手机号",
    "email": "邮箱",
    "chinese_id": "身份证",
    "bank_card": "银行卡",
    "quoted_amount": "金额",
    "project_code": "项目编号",
    "product_model": "产品型号",
    "internal_domain": "内部域名",
    "internal_link": "内部链接",
    "ip_address": "内网 IP",
    "database_connection": "数据库连接",
    "private_key": "私钥",
    "access_key": "Access Key",
    "api_key": "API Key",
    "token": "Token",
    "password": "密码",
    "secret": "Secret",
    "high_entropy": "高熵字符串",
    "customer_name": "客户名称",
    "confidentiality_label": "密级词",
    "denylist": "Deny List",
}

RISK_COLORS = {
    "low": "#18b26b",
    "medium": "#d89c00",
    "high": "#f97316",
    "critical": "#dc2626",
}

ENTITY_COLORS = {
    "phone_number": "#ffe08a",
    "email": "#c7e7ff",
    "customer_name": "#d8f7d0",
    "project_code": "#e9d5ff",
    "quoted_amount": "#ffd6a5",
    "api_key": "#ffc9c9",
    "token": "#ffc9c9",
    "secret": "#ffc9c9",
    "password": "#ffc9c9",
    "private_key": "#ffc9c9",
    "database_connection": "#ffdfdf",
    "internal_domain": "#d5f4e6",
    "internal_link": "#d5f4e6",
    "ip_address": "#d5f4e6",
    "product_model": "#e0e7ff",
}

TARGET_LABELS = {
    "public_ai": "公共 AI",
    "approved_enterprise_model": "批准的企业云模型",
    "internal_model": "公司内部模型",
    "local_model": "本地模型",
    "unknown_site": "未知网站",
}


def main() -> None:
    st.set_page_config(page_title="欣盾AI（SunShield AI）", page_icon="盾", layout="wide")
    _inject_style()
    st.title("欣盾AI（SunShield AI）")
    st.caption("把资料交给 AI 之前，先完成安全检查。")

    dictionaries = _load_dictionaries()
    document, target_platform, namespace_id = _input_panel(dictionaries)

    if not document.text.strip():
        _empty_state()
        return

    result = scan_text(
        document.text,
        target_platform=target_platform,
        dictionaries=dictionaries,
    )
    _results(document, result, namespace_id)


def _input_panel(dictionaries: EnterpriseDictionaries) -> tuple[ParsedDocument, str, str]:
    with st.sidebar:
        st.header("输入")
        target_platform = st.selectbox(
            "目标平台",
            options=list(TARGET_LABELS.keys()),
            format_func=lambda value: TARGET_LABELS[value],
            index=0,
        )
        namespace_id = st.text_input("一致性替换命名空间", value="demo")
        st.subheader("演示模式")
        demo_cols = st.columns(2)
        if demo_cols[0].button("加载 Word", width="stretch"):
            st.session_state["demo_file_path"] = str(
                ROOT / "sample_data" / "synthetic_demo_files" / "欣盾AI（SunShield AI）_客户报价测试样本.docx"
            )
        if demo_cols[1].button("加载 PDF", width="stretch"):
            st.session_state["demo_file_path"] = str(
                ROOT / "sample_data" / "synthetic_demo_files" / "欣盾AI（SunShield AI）_技术方案测试样本.pdf"
            )
        if st.session_state.get("demo_file_path"):
            demo_path = Path(st.session_state["demo_file_path"])
            st.caption(f"当前演示文件：{demo_path.name}")
            if st.button("清除演示文件", width="stretch"):
                st.session_state.pop("demo_file_path", None)
                st.rerun()

        input_mode = st.radio("输入方式", ["粘贴文本", "上传文件"], horizontal=True)

        pasted_text = ""
        uploaded = None
        if input_mode == "粘贴文本":
            if st.button("填入比赛演示样例", width="stretch"):
                st.session_state["pasted_demo"] = _demo_text()
            pasted_text = st.text_area(
                "待检查内容",
                value=st.session_state.get("pasted_demo", ""),
                height=260,
                placeholder="粘贴合同、报价、邮件、会议纪要或提示词...",
            )
        else:
            uploaded = st.file_uploader(
                "上传 TXT / PDF / XLSX / DOCX",
                type=["txt", "md", "csv", "pdf", "xlsx", "docx"],
            )

        st.divider()
        st.subheader("企业词库")
        st.caption(
            f"客户 {len(dictionaries.customers)}，项目 {len(dictionaries.project_codes)}，"
            f"产品 {len(dictionaries.product_models)}，内网域名 {len(dictionaries.internal_domains)}"
        )
        _dictionary_editor(dictionaries)
        st.info("自动识别无法保证发现全部敏感信息。高风险文件应由文件责任人或信息安全人员复核。")
        _history_panel()

    if st.session_state.get("demo_file_path"):
        demo_path = Path(st.session_state["demo_file_path"])
        if demo_path.exists():
            return parse_upload(demo_path.name, demo_path.read_bytes()), target_platform, namespace_id

    if uploaded is not None:
        try:
            return parse_upload(uploaded.name, uploaded.getvalue()), target_platform, namespace_id
        except Exception as exc:
            st.error(f"文件解析失败：{exc}")
            return ParsedDocument(uploaded.name, "unknown", "", [str(exc)], None), target_platform, namespace_id

    return ParsedDocument("pasted-text.txt", "text", pasted_text, [], None), target_platform, namespace_id


def _results(document: ParsedDocument, result: ScanResult, namespace_id: str) -> None:
    actions = _entity_actions(result.entities)
    if st.button("一键智能处理", width="stretch"):
        st.session_state["entity_actions"].update(default_action_map(result.entities))
        st.rerun()

    redacted_text = redact_text(
        document.text,
        result.entities,
        namespace_id=namespace_id,
        actions=actions,
    )
    adjusted_result = scan_text(redacted_text, target_platform=result.target_platform)

    _metric_row(result, adjusted_result, document)
    _agent_panel(document, result, adjusted_result, actions)
    _decision_panel(result, adjusted_result)
    _risk_report_panel(document, result, adjusted_result, actions)

    if document.warnings:
        for warning in document.warnings:
            st.warning(warning)
    if document.file_type == "pdf":
        st.warning("当前 PDF 支持文本型 PDF 扫描和脱敏文本导出；扫描件/OCR 和真正坐标级 PDF 红框脱敏属于后续能力。")

    left, middle, right = st.columns([0.95, 1.25, 1.25], gap="large")
    with left:
        _entity_list(document.text, result.entities, actions)
    with middle:
        st.subheader("原文预览")
        st.markdown(_highlight_html(document.text, result.entities), unsafe_allow_html=True)
    with right:
        st.subheader("脱敏结果")
        st.text_area("安全文本", redacted_text, height=420, label_visibility="collapsed")
        _downloads(document, result, adjusted_result, redacted_text, actions, namespace_id)


def _metric_row(result: ScanResult, adjusted_result: ScanResult, document: ParsedDocument) -> None:
    risk_label = _risk_label(result.risk_level.value)
    adjusted_label = _risk_label(adjusted_result.risk_level.value)
    count = len(result.entities)
    severe = sum(1 for entity in result.entities if entity.severity >= 5)
    route = _route_text(result.routing_recommendation)

    _cards(
        [
            ("综合风险", risk_label, str(result.risk_score), result.risk_level.value),
            ("识别项", str(count), "敏感/风险项", "neutral"),
            ("高严重度", str(severe), "severity >= 5", "neutral"),
            ("脱敏后风险", adjusted_label, str(adjusted_result.risk_score), adjusted_result.risk_level.value),
            ("输入类型", document.file_type.upper(), "文件解析完成", "neutral"),
        ]
    )
    st.info(route)


def _cards(cards: list[tuple[str, str, str, str]]) -> None:
    html_cards = []
    for title, value, sub, level in cards:
        color = RISK_COLORS.get(level, "#3b82f6")
        html_cards.append(
            f"""
            <div class="sp-card" style="border-left-color:{color}">
              <div class="sp-card-title">{html.escape(title)}</div>
              <div class="sp-card-value" style="color:{color}">{html.escape(value)}</div>
              <div class="sp-card-sub">{html.escape(sub)}</div>
            </div>
            """
        )
    st.markdown(f"<div class='sp-card-grid'>{''.join(html_cards)}</div>", unsafe_allow_html=True)


def _agent_panel(
    document: ParsedDocument,
    result: ScanResult,
    adjusted_result: ScanResult,
    actions: dict[str, str],
) -> None:
    with st.expander("Agent 智能处理流程", expanded=True):
        steps = build_agent_steps(document, result, adjusted_result, actions)
        for step in steps:
            badge = {
                "已完成": "done",
                "需人工确认": "review",
                "待执行": "todo",
                "执行中": "running",
            }.get(step.status, "todo")
            st.markdown(
                f"<div class='agent-step {badge}'><b>Step {step.step_no}：{html.escape(step.title)}</b>"
                f"<span>{html.escape(step.status)}</span><p>{html.escape(step.detail)}</p></div>",
                unsafe_allow_html=True,
            )


def _decision_panel(result: ScanResult, adjusted_result: ScanResult) -> None:
    with st.expander("Agent 决策说明", expanded=True):
        st.write(decision_explanation(result, adjusted_result))
        st.markdown("**风险原因**")
        for reason in risk_reasons(result):
            st.markdown(f"- {reason}")
        st.markdown(f"**推荐模型：** {recommended_model(adjusted_result)}")
        st.markdown(f"**上传结论：** {upload_decision(adjusted_result)}")


def _risk_report_panel(
    document: ParsedDocument,
    result: ScanResult,
    adjusted_result: ScanResult,
    actions: dict[str, str],
) -> None:
    with st.expander("风险报告", expanded=False):
        cols = st.columns(3)
        cols[0].metric("原始风险", _risk_label(result.risk_level.value), result.risk_score)
        cols[1].metric("脱敏后风险", _risk_label(adjusted_result.risk_level.value), adjusted_result.risk_score)
        cols[2].metric("上传结论", upload_decision(adjusted_result))
        st.markdown("**已执行动作统计**")
        st.json(action_counts(actions), expanded=False)


def _entity_actions(entities: list[SensitiveEntity]) -> dict[str, str]:
    actions: dict[str, str] = {}
    if "entity_actions" not in st.session_state:
        st.session_state["entity_actions"] = {}
    known = st.session_state["entity_actions"]

    for entity in entities:
        actions[entity.entity_id] = known.get(entity.entity_id, entity.suggested_action)
    return actions


def _entity_list(
    text: str,
    entities: list[SensitiveEntity],
    actions: dict[str, str],
) -> None:
    st.subheader("敏感项")
    if not entities:
        st.success("未发现明显敏感项。仍建议人工复核高价值文件。")
        return

    counts = Counter(entity.entity_type for entity in entities)
    st.caption("，".join(f"{_entity_label(kind)} {count}" for kind, count in counts.items()))

    type_options = ["全部"] + sorted(counts.keys(), key=lambda item: _entity_label(item))
    selected_type = st.selectbox(
        "按类型筛选",
        type_options,
        format_func=lambda value: "全部" if value == "全部" else _entity_label(value),
    )
    visible_entities = [
        entity for entity in entities if selected_type == "全部" or entity.entity_type == selected_type
    ]

    bulk_cols = st.columns(2)
    if bulk_cols[0].button("全部同类按建议处理", width="stretch"):
        for entity in visible_entities:
            st.session_state["entity_actions"][entity.entity_id] = default_action_for_entity(entity)
        st.rerun()
    if bulk_cols[1].button("全部同类保留", width="stretch"):
        for entity in visible_entities:
            st.session_state["entity_actions"][entity.entity_id] = RedactionAction.KEEP.value
        st.rerun()

    table = pd.DataFrame(
        [
            {
                "类型": _entity_label(entity.entity_type),
                "片段": _safe_excerpt(text, entity),
                "置信度": round(entity.confidence, 2),
                "严重度": entity.severity,
                "建议": ACTION_LABELS.get(entity.suggested_action, entity.suggested_action),
                "依据": entity.detector,
            }
            for entity in visible_entities
        ]
    )
    st.dataframe(table, hide_index=True, width="stretch", height=230)

    st.markdown("**人工处理**")
    options = [
        RedactionAction.CONSISTENT_LABEL.value,
        RedactionAction.MASK.value,
        RedactionAction.DELETE.value,
        RedactionAction.GENERALIZE.value,
        RedactionAction.HASH.value,
        RedactionAction.KEEP.value,
    ]
    for index, entity in enumerate(visible_entities, start=1):
        label = f"{index}. {_entity_label(entity.entity_type)} | {_safe_excerpt(text, entity)}"
        selected = st.selectbox(
            label,
            options=options,
            format_func=lambda value: ACTION_LABELS[value],
            index=options.index(actions.get(entity.entity_id, entity.suggested_action))
            if actions.get(entity.entity_id, entity.suggested_action) in options
            else 0,
            key=f"action_{entity.entity_id}",
        )
        st.session_state["entity_actions"][entity.entity_id] = selected


def _downloads(
    document: ParsedDocument,
    result: ScanResult,
    adjusted_result: ScanResult,
    redacted_text: str,
    actions: dict[str, str],
    namespace_id: str,
) -> None:
    report = build_risk_report(document, result, adjusted_result, actions)
    st.download_button(
        "下载脱敏文本",
        redacted_text.encode("utf-8"),
        file_name=f"{Path(document.filename).stem}_redacted.txt",
        mime="text/plain",
        width="stretch",
    )
    st.download_button(
        "下载风险报告 JSON",
        json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"),
        file_name=f"{Path(document.filename).stem}_risk_report.json",
        mime="application/json",
        width="stretch",
    )
    preferences = build_action_preferences(document.text, result.entities, actions)
    exported = export_redacted_original(
        document.filename,
        document.content,
        dictionaries=_load_dictionaries(),
        target_platform=result.target_platform,
        namespace_id=namespace_id,
        preferences=preferences,
    )
    if exported:
        st.download_button(
            f"下载脱敏原格式 {Path(exported.filename).suffix.upper()}",
            exported.content,
            file_name=exported.filename,
            mime=exported.mime_type,
            width="stretch",
        )

    if st.button("生成安全凭证并写入扫描历史", width="stretch"):
        record = record_scan(
            filename=document.filename,
            file_type=document.file_type,
            content=document.text,
            result=adjusted_result,
            original_result=result,
            action_counts=action_counts(actions),
            recommended_model=recommended_model(adjusted_result),
            upload_allowed=is_upload_allowed(adjusted_result),
        )
        credential_text = build_credential_text(
            record=record,
            original=result,
            after_redaction=adjusted_result,
            actions=actions,
        )
        st.session_state["latest_credential_text"] = credential_text
        st.session_state["latest_credential_id"] = record.credential_id
        st.success(f"安全凭证：{record.credential_id}")
        st.caption("扫描历史仅保存文件 hash、类型数量、风险等级和处理结果，不保存原文。")
    if st.session_state.get("latest_credential_text"):
        st.download_button(
            "下载安全凭证 TXT",
            st.session_state["latest_credential_text"].encode("utf-8"),
            file_name=f"{st.session_state.get('latest_credential_id', 'sunshield_ai')}_credential.txt",
            mime="text/plain",
            width="stretch",
        )


def _highlight_html(text: str, entities: list[SensitiveEntity]) -> str:
    if not entities:
        return f"<div class='preview'>{html.escape(text)}</div>"
    parts: list[str] = []
    cursor = 0
    for entity in sorted(entities, key=lambda item: item.start):
        parts.append(html.escape(text[cursor : entity.start]))
        label = _entity_label(entity.entity_type)
        value = html.escape(text[entity.start : entity.end])
        parts.append(
            f"<mark style='background:{ENTITY_COLORS.get(entity.entity_type, '#ffe08a')}' title='{label} | confidence {entity.confidence:.2f}'>"
            f"{value}<span>{label}</span></mark>"
        )
        cursor = entity.end
    parts.append(html.escape(text[cursor:]))
    return f"<div class='preview'>{''.join(parts)}</div>"


def _safe_excerpt(text: str, entity: SensitiveEntity) -> str:
    value = text[entity.start : entity.end]
    if len(value) <= 36:
        return value
    return value[:18] + "..." + value[-10:]


def _load_dictionaries() -> EnterpriseDictionaries:
    return load_enterprise_dictionaries(ROOT / "config")


def _history_panel() -> None:
    with st.expander("最近扫描历史", expanded=False):
        records = list_recent_records(limit=8)
        if not records:
            st.caption("暂无扫描历史。")
            return
        for record in records:
            st.markdown(
                f"**{record.credential_id}**  \n"
                f"{record.filename} | 风险 {_risk_label(record.risk_level)} | "
                f"{record.created_at[:19].replace('T', ' ')}"
            )


def _dictionary_editor(dictionaries: EnterpriseDictionaries) -> None:
    with st.expander("策略配置", expanded=False):
        st.caption("仅保存虚构样例词库；变更后会重新扫描。")
        fields = {
            "customers.example.yaml": ("客户词库", dictionaries.customers),
            "project_codes.example.yaml": ("项目代号", dictionaries.project_codes),
            "product_models.example.yaml": ("产品型号", dictionaries.product_models),
            "internal_domains.example.yaml": ("内部域名", dictionaries.internal_domains),
            "confidential_terms.example.yaml": ("密级关键词", dictionaries.confidential_terms),
            "allowlist.example.yaml": ("Allow List", dictionaries.allowlist),
            "denylist.example.yaml": ("Deny List", dictionaries.denylist),
        }
        updated: dict[str, str] = {}
        for filename, (label, values) in fields.items():
            updated[filename] = st.text_area(
                label,
                value="\n".join(values),
                height=72,
                key=f"dict_{filename}",
            )
        if st.button("保存策略配置", width="stretch"):
            for filename, raw in updated.items():
                items = [line.strip() for line in raw.splitlines() if line.strip()]
                content = "items:\n" + "".join(f"  - {item}\n" for item in items)
                (ROOT / "config" / filename).write_text(content, encoding="utf-8")
            st.success("策略配置已保存。")
            st.rerun()


def _empty_state() -> None:
    st.info("请在左侧粘贴文本或上传文件。")
    st.markdown(
        """
        **当前可用能力**

        - 本地扫描手机号、邮箱、身份证、银行卡、金额、项目编号、产品型号、内网地址和凭证类信息
        - 读取企业词库样例
        - 解释每个风险项的类型、置信度、严重度和识别依据
        - 支持人工选择保留、遮盖、删除、标签替换、哈希或泛化
        - 下载脱敏文本和不含敏感正文的 JSON 风险报告
        """
    )


def _risk_label(value: str) -> str:
    return {
        "low": "低",
        "medium": "中",
        "high": "高",
        "critical": "严重",
    }.get(value, value)


def _route_text(value: str) -> str:
    return {
        "block_or_manual_review": "建议：禁止直接上传，先交由文件责任人或信息安全人员复核。",
        "redact_before_public_ai_or_use_internal_model": "建议：不得直接发往公共 AI；请脱敏后使用批准企业模型，或改用内部/本地模型。",
        "redact_before_public_ai": "建议：脱敏后再发往公共 AI，并保留扫描记录。",
        "allowed_with_audit": "建议：可在内部或本地模型中使用，并保留审计摘要。",
        "allowed_after_user_confirmation": "建议：用户确认后可使用。",
    }.get(value, value)


def _entity_label(entity_type: str) -> str:
    return ENTITY_LABELS.get(entity_type, entity_type)


def _demo_text() -> str:
    return (
        "请帮我整理一封发给公共 AI 的客户报价摘要。\n\n"
        "客户：ABC Data Center\n"
        "联系人：James Wang，手机号 13812345678，邮箱 james.wang@example.com\n"
        "项目编号：SWD-TH-2026-018\n"
        "报价金额：2,350,000 元，付款条件：30% 预付款，70% 验收后支付。\n"
        "产品型号：SunEdge-X2，未发布型号 SPX-9000。\n"
        "内部域名：corp.example.local，内网地址：http://intranet.local/project/swd\n"
        "API Token: token=abcDEF1234567890abcDEF1234567890\n"
        "数据库：postgresql://demo_user:DemoPass2026@10.10.2.8:5432/quote\n"
        "文件等级：严格机密。"
    )


def _inject_style() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.5rem; }
        .preview {
            border: 1px solid #d7dde8;
            background: #fbfcfe;
            color: #1b2430;
            border-radius: 8px;
            padding: 16px;
            min-height: 420px;
            white-space: pre-wrap;
            line-height: 1.65;
            font-size: 14px;
        }
        mark {
            background: #ffe08a;
            color: #121212;
            padding: 2px 4px;
            border-radius: 4px;
        }
        mark span {
            margin-left: 4px;
            color: #704b00;
            font-size: 11px;
            font-weight: 700;
        }
        [data-testid="stMetric"] {
            border: 1px solid #273446;
            background: #141b24;
            color: #eef4ff;
            border-radius: 8px;
            padding: 10px 12px;
        }
        [data-testid="stMetricLabel"],
        [data-testid="stMetricValue"] {
            color: #eef4ff;
        }
        [data-testid="stMetricDelta"] {
            color: #6ee7a8;
        }
        .sp-card-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 12px;
            margin: 12px 0 16px 0;
        }
        .sp-card {
            background: #111827;
            border: 1px solid #273446;
            border-left: 5px solid #3b82f6;
            border-radius: 8px;
            padding: 12px 14px;
            min-height: 96px;
        }
        .sp-card-title {
            color: #aab6c7;
            font-size: 13px;
            margin-bottom: 6px;
        }
        .sp-card-value {
            font-size: 28px;
            font-weight: 800;
            line-height: 1.1;
        }
        .sp-card-sub {
            color: #7f8da3;
            font-size: 12px;
            margin-top: 8px;
        }
        .agent-step {
            border: 1px solid #263445;
            border-radius: 8px;
            padding: 10px 12px;
            margin: 8px 0;
            background: #0f1722;
        }
        .agent-step span {
            float: right;
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 999px;
            background: #263445;
            color: #d7e2f0;
        }
        .agent-step.done span { background: #14532d; color: #bbf7d0; }
        .agent-step.review span { background: #7c2d12; color: #fed7aa; }
        .agent-step.todo span { background: #334155; color: #dbeafe; }
        .agent-step p {
            color: #aab6c7;
            margin: 6px 0 0 0;
            font-size: 13px;
        }
        @media (max-width: 1100px) {
            .sp-card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
