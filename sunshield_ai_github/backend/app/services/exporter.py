from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from app.services.scanner.dictionaries import EnterpriseDictionaries
from app.services.scanner.engine import scan_text
from app.services.scanner.models import SensitiveEntity
from app.services.scanner.redactor import redact_text


ActionPreference = dict[tuple[str, str], str]


@dataclass(frozen=True)
class ExportedFile:
    filename: str
    content: bytes
    mime_type: str


def build_action_preferences(
    text: str,
    entities: list[SensitiveEntity],
    actions: dict[str, str],
) -> ActionPreference:
    preferences: ActionPreference = {}
    for entity in entities:
        original = text[entity.start : entity.end]
        preferences[(entity.entity_type, original)] = actions.get(
            entity.entity_id,
            entity.suggested_action,
        )
    return preferences


def export_redacted_original(
    filename: str,
    content: bytes | None,
    *,
    dictionaries: EnterpriseDictionaries,
    target_platform: str,
    namespace_id: str,
    preferences: ActionPreference,
) -> ExportedFile | None:
    if not content:
        return None
    suffix = Path(filename).suffix.lower()
    stem = Path(filename).stem
    if suffix == ".xlsx":
        return ExportedFile(
            filename=f"{stem}_redacted.xlsx",
            content=redact_xlsx_bytes(
                content,
                dictionaries=dictionaries,
                target_platform=target_platform,
                namespace_id=namespace_id,
                preferences=preferences,
            ),
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    if suffix == ".docx":
        return ExportedFile(
            filename=f"{stem}_redacted.docx",
            content=redact_docx_bytes(
                content,
                dictionaries=dictionaries,
                target_platform=target_platform,
                namespace_id=namespace_id,
                preferences=preferences,
            ),
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    return None


def redact_xlsx_bytes(
    content: bytes,
    *,
    dictionaries: EnterpriseDictionaries,
    target_platform: str,
    namespace_id: str,
    preferences: ActionPreference | None = None,
) -> bytes:
    import openpyxl

    workbook = openpyxl.load_workbook(io.BytesIO(content))
    active_preferences = preferences or {}
    for sheet in workbook.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if cell.value is None or not isinstance(cell.value, str):
                    continue
                cell.value = _redact_fragment(
                    cell.value,
                    dictionaries=dictionaries,
                    target_platform=target_platform,
                    namespace_id=namespace_id,
                    preferences=active_preferences,
                )
    out = io.BytesIO()
    workbook.save(out)
    workbook.close()
    return out.getvalue()


def redact_docx_bytes(
    content: bytes,
    *,
    dictionaries: EnterpriseDictionaries,
    target_platform: str,
    namespace_id: str,
    preferences: ActionPreference | None = None,
) -> bytes:
    active_preferences = preferences or {}
    source = io.BytesIO(content)
    out = io.BytesIO()
    with zipfile.ZipFile(source, "r") as in_zip:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as out_zip:
            for info in in_zip.infolist():
                data = in_zip.read(info.filename)
                if _is_docx_text_xml(info.filename):
                    data = _redact_docx_xml(
                        data,
                        dictionaries=dictionaries,
                        target_platform=target_platform,
                        namespace_id=namespace_id,
                        preferences=active_preferences,
                    )
                out_zip.writestr(info, data)
    return out.getvalue()


def _redact_docx_xml(
    data: bytes,
    *,
    dictionaries: EnterpriseDictionaries,
    target_platform: str,
    namespace_id: str,
    preferences: ActionPreference,
) -> bytes:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return data

    namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    changed = False
    for node in root.findall(".//w:t", namespace):
        if not node.text:
            continue
        redacted = _redact_fragment(
            node.text,
            dictionaries=dictionaries,
            target_platform=target_platform,
            namespace_id=namespace_id,
            preferences=preferences,
        )
        if redacted != node.text:
            node.text = redacted
            changed = True
    if not changed:
        return data
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)


def _redact_fragment(
    value: str,
    *,
    dictionaries: EnterpriseDictionaries,
    target_platform: str,
    namespace_id: str,
    preferences: ActionPreference,
) -> str:
    result = scan_text(value, dictionaries=dictionaries, target_platform=target_platform)
    overrides = {
        entity.entity_id: preferences.get(
            (entity.entity_type, value[entity.start : entity.end]),
            entity.suggested_action,
        )
        for entity in result.entities
    }
    return redact_text(value, result.entities, namespace_id=namespace_id, actions=overrides)


def _is_docx_text_xml(name: str) -> bool:
    return (
        name == "word/document.xml"
        or name.startswith("word/header")
        or name.startswith("word/footer")
        or name.startswith("word/footnotes")
        or name.startswith("word/endnotes")
        or name.startswith("word/comments")
    ) and name.endswith(".xml")

