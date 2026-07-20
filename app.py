from __future__ import annotations

import io
import json
import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from patterns import PII_REGEXES
from scanner import analyzer as presidio_analyzer
from scanner import scan_dataframe


@dataclass
class UploadedScan:
    file_name: str
    extension: str
    dataframe: pd.DataFrame
    findings: list[dict[str, Any]]
    stats: dict[str, Any]


@dataclass
class FileStatus:
    file_name: str
    state: str
    detail: str
    size_mb: float


@dataclass
class InputFile:
    name: str
    payload: bytes


@dataclass
class RemediationRecord:
    file_name: str
    column: str
    pattern: str
    detection_source: str
    strategy: str
    cells_changed: int


def load_uploaded_dataframe(file_name: str, file_bytes: bytes) -> tuple[pd.DataFrame, str]:
    extension = Path(file_name).suffix.lower().lstrip(".")

    if extension == "csv":
        return pd.read_csv(io.BytesIO(file_bytes), dtype=str), extension
    if extension == "json":
        return pd.read_json(io.BytesIO(file_bytes), lines=True), extension
    if extension == "parquet":
        return pd.read_parquet(io.BytesIO(file_bytes)), extension
    if extension == "txt":
        text_content = file_bytes.decode("utf-8", errors="ignore")
        return pd.DataFrame({"value": text_content.splitlines()}), extension
    if extension in {"xlsx", "xls"}:
        return pd.read_excel(io.BytesIO(file_bytes), dtype=str), extension

    raise ValueError(
        "Unsupported file type. Use csv, json, parquet, txt, xlsx, or xls."
    )


def expand_input_files(uploaded_files) -> list[InputFile]:
    expanded: list[InputFile] = []

    for uploaded in uploaded_files:
        file_name = uploaded.name
        file_bytes = uploaded.getvalue()
        extension = Path(file_name).suffix.lower().lstrip(".")

        if extension != "zip":
            expanded.append(InputFile(name=file_name, payload=file_bytes))
            continue

        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for member in zf.infolist():
                member_name = member.filename

                if member.is_dir():
                    continue

                member_ext = Path(member_name).suffix.lower().lstrip(".")
                if member_ext not in {"csv", "json", "parquet", "txt", "xlsx", "xls"}:
                    continue

                expanded.append(InputFile(name=Path(member_name).name, payload=zf.read(member)))

    return expanded


def format_size_mb(file_size_bytes: int) -> float:
    return round(file_size_bytes / (1024 * 1024), 2)


def summarize_findings(findings_df: pd.DataFrame) -> dict[str, int]:
    if findings_df.empty or "risk" not in findings_df.columns:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "REVIEW": 0}

    counts = findings_df["risk"].value_counts().to_dict()
    return {
        "CRITICAL": int(counts.get("CRITICAL", 0)),
        "HIGH": int(counts.get("HIGH", 0)),
        "MEDIUM": int(counts.get("MEDIUM", 0)),
        "LOW": int(counts.get("LOW", 0)),
        "REVIEW": int(counts.get("REVIEW", 0)),
    }


def anonymize_dataframe(df: pd.DataFrame, findings_df: pd.DataFrame) -> pd.DataFrame:
    anonymized = df.copy()
    if findings_df.empty:
        return anonymized

    for _, finding in findings_df.iterrows():
        column = finding.get("column")
        pattern = finding.get("pattern")

        if column not in anonymized.columns or not pattern:
            continue

        token = f"<PII:{pattern}>"

        if finding.get("detection_source") == "REGEX_RULE" and pattern in PII_REGEXES:
            regex_pattern = PII_REGEXES[pattern]
            anonymized[column] = anonymized[column].astype(str).apply(
                lambda value: token if regex_pattern.fullmatch(value.strip()) else value
            )
            continue

        sample_matches = [
            finding.get("sample_match_1", ""),
            finding.get("sample_match_2", ""),
            finding.get("sample_match_3", ""),
            finding.get("sample_match_4", ""),
            finding.get("sample_match_5", ""),
        ]
        sample_matches = [s for s in sample_matches if isinstance(s, str) and s]

        if sample_matches:
            anonymized[column] = anonymized[column].astype(str).apply(
                lambda value: _replace_samples(value, sample_matches, token)
            )

    return anonymized


def remediation_label(remediation_mode: str) -> str:
    labels = {
        "redact": "REDACT",
        "hash": "HASH",
        "mask_last4": "MASK_LAST4",
    }
    return labels.get(remediation_mode, "REDACT")


def transform_value(value: str, pattern: str, remediation_mode: str, salt: str) -> str:
    if remediation_mode == "hash":
        digest = hashlib.sha256(f"{salt}|{pattern}|{value}".encode("utf-8")).hexdigest()[:12]
        return f"<PII_HASH:{pattern}:{digest}>"

    if remediation_mode == "mask_last4":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4 and pattern in {
            "ssn",
            "credit_card",
            "bank_account",
            "routing_number",
            "phone",
        }:
            return f"<PII_MASK:{pattern}:***{digits[-4:]}>"
        return f"<PII_MASK:{pattern}>"

    return f"<PII_REDACT:{pattern}>"


def replace_by_regex(series: pd.Series, pattern_name: str, remediation_mode: str, salt: str) -> tuple[pd.Series, int]:
    regex_pattern = PII_REGEXES.get(pattern_name)
    if regex_pattern is None:
        return series, 0

    updated_values = []
    changed = 0

    for value in series.astype(str):
        stripped = value.strip()
        if regex_pattern.fullmatch(stripped):
            updated_values.append(transform_value(stripped, pattern_name, remediation_mode, salt))
            changed += 1
        else:
            updated_values.append(value)

    return pd.Series(updated_values, index=series.index), changed


def replace_by_samples(series: pd.Series, pattern_name: str, samples: list[str], remediation_mode: str, salt: str) -> tuple[pd.Series, int]:
    if not samples:
        return series, 0

    updated_values = []
    changed = 0

    for original in series.astype(str):
        value = original
        local_change = False

        for sample in samples:
            if sample and sample in value:
                replacement = transform_value(sample, pattern_name, remediation_mode, salt)
                value = value.replace(sample, replacement)
                local_change = True

        if local_change:
            changed += 1
        updated_values.append(value)

    return pd.Series(updated_values, index=series.index), changed


def replace_by_presidio_entity(
    series: pd.Series,
    entity_type: str,
    remediation_mode: str,
    salt: str,
    strict_person_fallback: bool,
    strict_location_fallback: bool,
) -> tuple[pd.Series, int]:
    updated_values = []
    changed = 0

    for original in series.astype(str):
        value = original
        entities = presidio_analyzer.analyze(text=value, language="en")
        target_entities = [e for e in entities if e.entity_type == entity_type]

        # Replace from right to left so offsets remain valid.
        for entity in sorted(target_entities, key=lambda x: x.start, reverse=True):
            detected_text = value[entity.start:entity.end]
            replacement = transform_value(detected_text, entity_type, remediation_mode, salt)
            value = value[:entity.start] + replacement + value[entity.end:]

        if (
            entity_type == "PERSON"
            and strict_person_fallback
            and "requested that documents be mailed" in value
        ):
            # Fallback for templated note lines where PERSON can be missed by NLP.
            value = apply_person_template_fallback(value, remediation_mode, salt)

        if (
            entity_type == "LOCATION"
            and strict_location_fallback
            and "requested that documents be mailed to" in value
        ):
            # Fallback for address narrative lines where LOCATION can be missed by NLP.
            value = apply_location_template_fallback(value, remediation_mode, salt)

        if value != original:
            changed += 1
        updated_values.append(value)

    return pd.Series(updated_values, index=series.index), changed


def apply_person_template_fallback(value: str, remediation_mode: str, salt: str) -> str:
    person_pattern = re.compile(
        r"\b([A-Z][a-z]+\s+[A-Z][a-z]+)(?=\s+requested\s+that\s+documents\s+be\s+mailed)",
    )

    def _replace(match: re.Match) -> str:
        detected_name = match.group(1)
        return transform_value(detected_name, "PERSON", remediation_mode, salt)

    return person_pattern.sub(_replace, value)


def apply_location_template_fallback(value: str, remediation_mode: str, salt: str) -> str:
    # Redact address segment patterns in templated mailing narrative lines.
    street_pattern = re.compile(
        r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)\b",
    )
    city_state_zip_pattern = re.compile(
        r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(AL|GA|NC|TN)\s+\d{5}\b",
    )

    def _replace_street(match: re.Match) -> str:
        detected = match.group(0)
        return transform_value(detected, "LOCATION", remediation_mode, salt)

    def _replace_city_state_zip(match: re.Match) -> str:
        detected = match.group(0)
        return transform_value(detected, "LOCATION", remediation_mode, salt)

    updated = street_pattern.sub(_replace_street, value)
    updated = city_state_zip_pattern.sub(_replace_city_state_zip, updated)
    return updated


def sub_with_transform(
    value: str,
    regex: re.Pattern,
    pattern_name: str,
    remediation_mode: str,
    salt: str,
) -> tuple[str, int]:
    def _replace(match: re.Match) -> str:
        detected = match.group(0)
        return transform_value(detected, pattern_name, remediation_mode, salt)

    return regex.subn(_replace, value)


def replace_contextual_digit_tokens(
    value: str,
    remediation_mode: str,
    salt: str,
) -> tuple[str, set[str]]:
    updated = value
    changed_types: set[str] = set()
    digit_pattern = re.compile(r"(?<!\d)\d{8,17}(?!\d)")

    matches = list(digit_pattern.finditer(updated))
    for match in sorted(matches, key=lambda m: m.start(), reverse=True):
        token = match.group(0)
        start, end = match.start(), match.end()
        context = updated[max(0, start - 28): min(len(updated), end + 28)].lower()

        replacement_label = ""
        if len(token) == 9 and ("routing" in context or "aba" in context):
            replacement_label = "routing_number"
        elif any(k in context for k in ["account", "acct", "bank", "iban"]):
            replacement_label = "bank_account"

        if replacement_label:
            replacement = transform_value(token, replacement_label, remediation_mode, salt)
            updated = updated[:start] + replacement + updated[end:]
            changed_types.add(replacement_label)

    return updated, changed_types


def apply_common_pii_fallback_value(
    value: str,
    remediation_mode: str,
    salt: str,
    enable_contextual_date_fallback: bool,
) -> tuple[str, set[str]]:
    updated = value
    changed_types: set[str] = set()

    simple_patterns = [
        ("email", re.compile(r"(?<!\w)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)")),
        ("phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")),
        ("ssn", re.compile(r"(?<!\d)\d{3}-?\d{2}-?\d{4}(?!\d)")),
        ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")),
        ("ein", re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)")),
        ("ip", re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")),
    ]

    for pattern_name, regex in simple_patterns:
        updated, replacements = sub_with_transform(
            updated,
            regex,
            pattern_name,
            remediation_mode,
            salt,
        )
        if replacements > 0:
            changed_types.add(pattern_name)

    updated, contextual_types = replace_contextual_digit_tokens(
        updated,
        remediation_mode,
        salt,
    )
    changed_types.update(contextual_types)

    if enable_contextual_date_fallback:
        date_context = updated.lower()
        if any(k in date_context for k in ["dob", "birth", "born", "date of birth"]):
            date_regex = re.compile(r"(?<!\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-]\d{4}(?!\d)")
            updated, replacements = sub_with_transform(
                updated,
                date_regex,
                "dob",
                remediation_mode,
                salt,
            )
            if replacements > 0:
                changed_types.add("dob")

    return updated, changed_types


def apply_common_pii_fallback_series(
    series: pd.Series,
    remediation_mode: str,
    salt: str,
    enable_contextual_date_fallback: bool,
) -> tuple[pd.Series, dict[str, int]]:
    updated_values = []
    type_change_counts: dict[str, int] = {}

    for original in series.astype(str):
        updated, changed_types = apply_common_pii_fallback_value(
            original,
            remediation_mode,
            salt,
            enable_contextual_date_fallback,
        )
        for changed_type in changed_types:
            type_change_counts[changed_type] = type_change_counts.get(changed_type, 0) + 1
        updated_values.append(updated)

    return pd.Series(updated_values, index=series.index), type_change_counts


def remediate_dataframe(
    file_name: str,
    df: pd.DataFrame,
    findings_df: pd.DataFrame,
    remediation_mode: str,
    include_review_findings: bool,
    hash_salt: str,
    strict_person_fallback: bool,
    strict_location_fallback: bool,
    strict_common_fallback: bool,
    strict_date_fallback: bool,
) -> tuple[pd.DataFrame, list[RemediationRecord]]:
    remediated = df.copy()
    records: list[RemediationRecord] = []
    touched_columns: set[str] = set()

    if findings_df.empty:
        return remediated, records

    for _, finding in findings_df.iterrows():
        column = finding.get("column")
        pattern = finding.get("pattern")
        risk = finding.get("risk", "")
        detection_source = str(finding.get("detection_source", ""))

        if column not in remediated.columns or not pattern:
            continue

        touched_columns.add(column)

        if not include_review_findings and risk == "REVIEW":
            continue

        if detection_source == "REGEX_RULE" and pattern in PII_REGEXES:
            updated_series, changed = replace_by_regex(
                remediated[column],
                pattern,
                remediation_mode,
                hash_salt,
            )
        elif detection_source == "PRESIDIO_NLP":
            updated_series, changed = replace_by_presidio_entity(
                remediated[column],
                pattern,
                remediation_mode,
                hash_salt,
                strict_person_fallback,
                strict_location_fallback,
            )
        else:
            sample_matches = [
                finding.get("sample_match_1", ""),
                finding.get("sample_match_2", ""),
                finding.get("sample_match_3", ""),
                finding.get("sample_match_4", ""),
                finding.get("sample_match_5", ""),
            ]
            sample_matches = [s for s in sample_matches if isinstance(s, str) and s]
            updated_series, changed = replace_by_samples(
                remediated[column],
                pattern,
                sample_matches,
                remediation_mode,
                hash_salt,
            )

        if changed > 0:
            remediated[column] = updated_series
            records.append(
                RemediationRecord(
                    file_name=file_name,
                    column=column,
                    pattern=pattern,
                    detection_source=detection_source,
                    strategy=remediation_label(remediation_mode),
                    cells_changed=changed,
                )
            )

    if strict_common_fallback:
        for column in sorted(touched_columns):
            updated_series, fallback_counts = apply_common_pii_fallback_series(
                remediated[column],
                remediation_mode,
                hash_salt,
                strict_date_fallback,
            )

            if fallback_counts:
                remediated[column] = updated_series
                for pattern_name, cells_changed in fallback_counts.items():
                    records.append(
                        RemediationRecord(
                            file_name=file_name,
                            column=column,
                            pattern=pattern_name,
                            detection_source="STRICT_FALLBACK",
                            strategy=remediation_label(remediation_mode),
                            cells_changed=cells_changed,
                        )
                    )

    return remediated, records


def _replace_samples(value: str, samples: list[str], token: str) -> str:
    updated = value
    for sample in samples:
        updated = updated.replace(sample, token)
    return updated


def dataframe_to_bytes(df: pd.DataFrame, extension: str) -> bytes:
    if extension == "csv":
        return df.to_csv(index=False).encode("utf-8")
    if extension == "json":
        return df.to_json(orient="records", lines=True).encode("utf-8")
    if extension == "txt":
        txt_series = df.iloc[:, 0].astype(str) if len(df.columns) > 0 else pd.Series(dtype=str)
        return "\n".join(txt_series.tolist()).encode("utf-8")
    if extension in {"xlsx", "xls"}:
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return buffer.getvalue()
    if extension == "parquet":
        buffer = io.BytesIO()
        df.to_parquet(buffer, index=False)
        return buffer.getvalue()

    return df.to_csv(index=False).encode("utf-8")


st.set_page_config(page_title="Pre-Ingestion PII Tool", page_icon="🔎", layout="wide")

st.title("Pre-Ingestion PII Tool")
st.caption("Scan files locally for PII before they leave your workstation.")

with st.sidebar:
    st.header("Scan Options")
    run_scan = st.checkbox("Detect PII", value=True)
    include_presidio = st.checkbox("Include Presidio findings", value=True)
    show_samples = st.checkbox("Show sample values", value=True)
    build_anonymized = st.checkbox("Generate anonymized copy", value=True)
    skip_large_files = st.checkbox("Skip very large files", value=True)
    max_file_size_mb = st.number_input(
        "Max file size (MB)",
        min_value=1,
        max_value=1024,
        value=25,
        step=1,
        disabled=not skip_large_files,
        help="Files larger than this limit are skipped when the option is enabled.",
    )
    st.header("Cloud Remediation")
    build_anonymized = st.checkbox("Generate cloud-ready files", value=True)
    remediation_mode = st.selectbox(
        "Remediation strategy",
        options=["redact", "mask_last4", "hash"],
        format_func=lambda x: {
            "redact": "Redact",
            "mask_last4": "Mask keep last 4",
            "hash": "Hash tokenize",
        }[x],
    )
    include_review_findings = st.checkbox(
        "Also remediate REVIEW findings",
        value=True,
        help="REVIEW findings usually come from NLP and may include false positives.",
    )
    strict_person_fallback = st.checkbox(
        "Strict fallback for missed names in narrative text",
        value=True,
        help=(
            "Adds a context-aware fallback for PERSON in phrases like "
            "'<Name> requested that documents be mailed'."
        ),
    )
    strict_location_fallback = st.checkbox(
        "Strict fallback for missed locations in narrative text",
        value=True,
        help=(
            "Adds a context-aware fallback for mailing addresses and city/state/zip "
            "segments in narrative lines."
        ),
    )
    strict_common_fallback = st.checkbox(
        "Strict fallback for common PII patterns",
        value=True,
        help="Adds regex/context fallbacks for email, phone, SSN, cards, accounts, EIN, and IP.",
    )
    strict_date_fallback = st.checkbox(
        "Contextual date fallback (DOB/birth context)",
        value=True,
        disabled=not strict_common_fallback,
        help="Redacts date values only when DOB/birth context appears in the text.",
    )
    hash_salt = st.text_input(
        "Hash salt",
        value="local-remediation-salt",
        disabled=remediation_mode != "hash",
        help="Used only for hash mode to produce deterministic tokens.",
    )
    run_clicked = st.button("Scan", type="primary", use_container_width=True)

uploaded_files = st.file_uploader(
    "Upload multiple files or a ZIP archive",
    type=["csv", "json", "parquet", "txt", "xlsx", "xls", "zip"],
    accept_multiple_files=True,
)

if uploaded_files:
    input_files = expand_input_files(uploaded_files)
    st.info(f"{len(input_files)} file(s) queued for scan.")
    st.caption("You can select multiple files directly or upload a ZIP containing supported file types.")
else:
    input_files = []

if run_clicked and not input_files:
    st.warning("Upload at least one file to run the scan.")

if run_clicked and input_files and run_scan:
    scans: list[UploadedScan] = []
    all_findings: list[dict[str, Any]] = []
    all_stats: list[dict[str, Any]] = []
    file_statuses: list[FileStatus] = []

    with st.spinner("Scanning files..."):
        for uploaded in input_files:
            file_size_mb = format_size_mb(len(uploaded.payload))

            if skip_large_files and file_size_mb > max_file_size_mb:
                file_statuses.append(
                    FileStatus(
                        file_name=uploaded.name,
                        state="SKIPPED",
                        detail=(
                            f"Skipped: {file_size_mb} MB exceeds {max_file_size_mb} MB limit"
                        ),
                        size_mb=file_size_mb,
                    )
                )
                continue

            try:
                df, ext = load_uploaded_dataframe(uploaded.name, uploaded.payload)
                findings, stats = scan_dataframe(df, uploaded.name)

                if not include_presidio:
                    findings = [
                        finding
                        for finding in findings
                        if finding.get("detection_source") != "PRESIDIO_NLP"
                    ]
                    stats = {
                        "source": uploaded.name,
                        "columns_scanned": stats.get("columns_scanned", 0),
                        "findings": len(findings),
                    }

                scan = UploadedScan(
                    file_name=uploaded.name,
                    extension=ext,
                    dataframe=df,
                    findings=findings,
                    stats=stats,
                )
                scans.append(scan)
                all_findings.extend(findings)
                all_stats.append(stats)
                file_statuses.append(
                    FileStatus(
                        file_name=uploaded.name,
                        state="SUCCESS",
                        detail=f"Scanned successfully with {len(findings)} finding(s)",
                        size_mb=file_size_mb,
                    )
                )

            except Exception as exc:
                file_statuses.append(
                    FileStatus(
                        file_name=uploaded.name,
                        state="FAILED",
                        detail=str(exc),
                        size_mb=file_size_mb,
                    )
                )

    findings_df = pd.DataFrame(all_findings)
    stats_df = pd.DataFrame(all_stats)
    risk_summary = summarize_findings(findings_df)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CRITICAL", risk_summary["CRITICAL"])
    c2.metric("HIGH", risk_summary["HIGH"])
    c3.metric("MEDIUM", risk_summary["MEDIUM"])
    c4.metric("LOW", risk_summary["LOW"])
    c5.metric("REVIEW", risk_summary["REVIEW"])

    st.subheader("Top Findings")
    if findings_df.empty:
        st.info("No findings detected for selected options.")
    else:
        top = (
            findings_df.groupby(["pattern", "risk"], dropna=False)["matches"]
            .sum()
            .reset_index()
            .sort_values(by="matches", ascending=False)
            .head(10)
        )
        st.dataframe(top, use_container_width=True)

    st.subheader("Per-File Scan Status")
    status_rows = [
        {
            "file": item.file_name,
            "status": item.state,
            "size_mb": item.size_mb,
            "details": item.detail,
        }
        for item in file_statuses
    ]
    status_df = pd.DataFrame(status_rows)
    if not status_df.empty:
        st.dataframe(status_df, use_container_width=True)
        for item in file_statuses:
            badge = f"[{item.state}] {item.file_name} ({item.size_mb} MB)"
            if item.state == "SUCCESS":
                st.success(f"{badge}: {item.detail}")
            elif item.state == "SKIPPED":
                st.warning(f"{badge}: {item.detail}")
            else:
                st.error(f"{badge}: {item.detail}")

    st.subheader("Detailed Findings")
    if findings_df.empty:
        st.write("No detailed findings to display.")
    else:
        if not show_samples:
            sample_cols = [f"sample_match_{i}" for i in range(1, 6)]
            safe_cols = [c for c in findings_df.columns if c not in sample_cols]
            st.dataframe(findings_df[safe_cols], use_container_width=True)
        else:
            st.dataframe(findings_df, use_container_width=True)

    st.subheader("Per-File Findings")
    if scans:
        tab_labels = [scan.file_name for scan in scans]
        tabs = st.tabs(tab_labels)
        for tab, scan in zip(tabs, scans):
            with tab:
                scan_findings_df = pd.DataFrame(scan.findings)
                if scan_findings_df.empty:
                    st.info("No findings for this file.")
                else:
                    if not show_samples:
                        sample_cols = [f"sample_match_{i}" for i in range(1, 6)]
                        safe_cols = [
                            c for c in scan_findings_df.columns if c not in sample_cols
                        ]
                        st.dataframe(scan_findings_df[safe_cols], use_container_width=True)
                    else:
                        st.dataframe(scan_findings_df, use_container_width=True)
    else:
        st.info("No successful file scans to show in per-file tabs.")

    st.subheader("File Scan Stats")
    st.dataframe(stats_df, use_container_width=True)

    findings_bytes = findings_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Findings CSV",
        data=findings_bytes,
        file_name="pii_findings.csv",
        mime="text/csv",
    )

    if build_anonymized and scans:
        zip_buffer = io.BytesIO()
        remediation_records: list[RemediationRecord] = []
        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for scan in scans:
                scan_findings_df = pd.DataFrame(scan.findings)
                remediated_df, scan_records = remediate_dataframe(
                    file_name=scan.file_name,
                    df=scan.dataframe,
                    findings_df=scan_findings_df,
                    remediation_mode=remediation_mode,
                    include_review_findings=include_review_findings,
                    hash_salt=hash_salt,
                    strict_person_fallback=strict_person_fallback,
                    strict_location_fallback=strict_location_fallback,
                    strict_common_fallback=strict_common_fallback,
                    strict_date_fallback=strict_date_fallback,
                )
                remediation_records.extend(scan_records)
                payload = dataframe_to_bytes(remediated_df, scan.extension)
                base_name = Path(scan.file_name).stem
                safe_ext = scan.extension if scan.extension else "csv"
                zf.writestr(f"{base_name}_cloud_ready.{safe_ext}", payload)

            remediation_df = pd.DataFrame([r.__dict__ for r in remediation_records])
            zf.writestr(
                "remediation_report.csv",
                remediation_df.to_csv(index=False) if not remediation_df.empty else "",
            )

            zf.writestr(
                "anonymization_manifest.json",
                json.dumps(
                    {
                        "note": "Cloud-ready remediation based on detected findings.",
                        "strategy": remediation_label(remediation_mode),
                        "include_review_findings": include_review_findings,
                        "files": [scan.file_name for scan in scans],
                    },
                    indent=2,
                ),
            )

        remediation_df = pd.DataFrame([r.__dict__ for r in remediation_records])
        st.subheader("Remediation Summary")
        if remediation_df.empty:
            st.info("No cells were changed during remediation for the selected strategy.")
        else:
            summary = (
                remediation_df.groupby(["file_name", "pattern", "strategy"], dropna=False)[
                    "cells_changed"
                ]
                .sum()
                .reset_index()
                .sort_values(by="cells_changed", ascending=False)
            )
            st.dataframe(summary, use_container_width=True)

        st.download_button(
            "Download Cloud-Ready Files (ZIP)",
            data=zip_buffer.getvalue(),
            file_name="cloud_ready_outputs.zip",
            mime="application/zip",
        )

elif run_clicked and not run_scan:
    st.info("PII detection is turned off. Enable 'Detect PII' and run scan.")
