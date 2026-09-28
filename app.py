from __future__ import annotations

import io
import json
import hashlib
import os
import random
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Hashable, cast

import pandas as pd
import requests
from fastavro import reader, writer as avro_writer
import streamlit as st

if os.name == "nt":
    import truststore

    truststore.inject_into_ssl()

from data_quality import (
    validate_output,
    DQFailure,
    DQReport,
    AnomalyResult,
    SemanticRisk,
    RegulatoryFlag,
    QuasiIdentifierGroup,
    FormatAnomaly,
    PlausibilityIssue,
    ConsistencyIssue,
    CompletenessIssue,
    AutoExpectationRun,
    AutoExpectationSpec,
)
from patterns import PII_REGEXES
from scanner import scan_dataframe
from remediate import (
    NAME_LIKE_COLUMN_HINTS,
    FULL_NAME_PATTERN,
    PERSON_CONTEXT_PATTERN,
    LOCATION_FULL_ADDRESS_PATTERN,
    LOCATION_STREET_PATTERN,
    LOCATION_CITY_STATE_ZIP_PATTERN,
    LOCATION_CITY_STATE_PATTERN,
    REMEDIATION_PATTERN_PRIORITY,
    REMEDIATION_PATTERN_OPTIONS,
    RemediationRecord,
    coerce_text,
    is_name_like_column,
    remediation_label,
    transform_value,
    replace_by_regex,
    replace_by_samples,
    replace_by_presidio_entity,
    apply_person_context_fallback,
    apply_location_context_fallback,
    remediation_priority,
    sub_with_transform,
    replace_contextual_digit_tokens,
    apply_common_pii_fallback_value,
    apply_common_pii_fallback_series,
    remediate_dataframe,
)


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


LARGE_FILE_BYTES = 100 * 1024 * 1024


def _load_json_dataframe_from_bytes(payload: bytes) -> pd.DataFrame:
    # First try standard JSON (object/array), then fall back to JSONL.
    text_content = payload.decode("utf-8-sig")

    try:
        parsed = json.loads(text_content)
    except json.JSONDecodeError:
        return pd.read_json(io.BytesIO(payload), lines=True)

    if isinstance(parsed, list):
        return pd.json_normalize(parsed)

    if isinstance(parsed, dict):
        for list_key in ("records", "items", "data", "teas"):
            candidate = parsed.get(list_key)
            if isinstance(candidate, list):
                return pd.json_normalize(candidate)
        return pd.json_normalize([parsed])

    raise ValueError("Unsupported JSON structure. Expected object, array, or JSON lines.")


def _load_avro_dataframe_from_bytes(payload: bytes) -> pd.DataFrame:
    return pd.DataFrame(list(reader(io.BytesIO(payload))))


def load_uploaded_dataframe(file_name: str, file_bytes: bytes) -> tuple[pd.DataFrame, str]:
    extension = Path(file_name).suffix.lower().lstrip(".")

    if extension == "csv":
        return pd.read_csv(io.BytesIO(file_bytes), dtype=str), extension
    if extension == "avro":
        return _load_avro_dataframe_from_bytes(file_bytes), extension
    if extension == "json":
        return _load_json_dataframe_from_bytes(file_bytes), extension
    if extension == "parquet":
        return pd.read_parquet(io.BytesIO(file_bytes)), extension
    if extension == "txt":
        text_content = file_bytes.decode("utf-8", errors="ignore")
        return pd.DataFrame({"value": text_content.splitlines()}), extension
    if extension in {"xlsx", "xls"}:
        return pd.read_excel(io.BytesIO(file_bytes), dtype=str), extension

    raise ValueError(
        "Unsupported file type. Use avro, csv, json, parquet, txt, xlsx, or xls."
    )


def _sample_uploaded_avro_for_analysis(
    file_name: str,
    uploaded_file,
    max_rows: int,
) -> tuple[str, bytes, int]:
    """Stream a bounded deterministic sample from an uploaded Avro file."""
    uploaded_file.seek(0)
    reservoir: list[dict[str, Any]] = []
    seen = 0
    rng = random.Random(42)
    for record in reader(uploaded_file):
        seen += 1
        record_dict = cast(dict[str, Any], record)
        if len(reservoir) < max_rows:
            reservoir.append(record_dict)
            continue
        replacement = rng.randrange(seen)
        if replacement < max_rows:
            reservoir[replacement] = record_dict

    sample_name = f"{Path(file_name).stem}.sample.csv"
    sample_bytes = pd.DataFrame(reservoir).to_csv(index=False).encode("utf-8")
    return sample_name, sample_bytes, seen


def expand_input_files(
    uploaded_files,
    sample_large_files: bool = False,
    sample_row_limit: int = 1000,
) -> list[InputFile]:
    expanded: list[InputFile] = []

    for uploaded in uploaded_files:
        file_name = uploaded.name
        extension = Path(file_name).suffix.lower().lstrip(".")

        if (
            sample_large_files
            and extension == "avro"
            and uploaded.size >= LARGE_FILE_BYTES
        ):
            sample_name, sample_bytes, _ = _sample_uploaded_avro_for_analysis(
                file_name,
                uploaded,
                sample_row_limit,
            )
            expanded.append(InputFile(name=sample_name, payload=sample_bytes))
            continue

        file_bytes = uploaded.getvalue()
        if extension != "zip":
            expanded.append(InputFile(name=file_name, payload=file_bytes))
            continue

        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for member in zf.infolist():
                member_name = member.filename

                if member.is_dir():
                    continue

                member_ext = Path(member_name).suffix.lower().lstrip(".")
                if member_ext not in {"avro", "csv", "json", "parquet", "txt", "xlsx", "xls"}:
                    continue

                expanded.append(InputFile(name=Path(member_name).name, payload=zf.read(member)))

    return expanded


def format_size_mb(file_size_bytes: int) -> float:
    return round(file_size_bytes / (1024 * 1024), 2)


def _post_quality_file(
    api_base: str,
    endpoint: str,
    file_name: str,
    payload: bytes,
    api_key: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {"X-API-Key": api_key} if api_key else {}
    try:
        response = requests.post(
            f"{api_base.rstrip('/')}{endpoint}",
            files={"file": (file_name, io.BytesIO(payload))},
            params=params or {},
            headers=headers,
            timeout=330,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not reach the DQ API at {api_base}: {exc}") from exc

    try:
        result = response.json()
    except ValueError:
        result = {"detail": response.text}

    if response.status_code >= 300:
        detail = result.get("detail", result) if isinstance(result, dict) else result
        raise RuntimeError(f"DQ API returned HTTP {response.status_code}: {detail}")
    if not isinstance(result, dict):
        raise RuntimeError("DQ API returned an unexpected response format.")
    return result


def _dq_report_from_payload(payload: dict[str, Any]) -> DQReport:
    return DQReport(
        passed=bool(payload.get("passed", False)),
        evaluated=int(payload.get("evaluated", 0)),
        successful=int(payload.get("successful", 0)),
        failed=int(payload.get("failed", 0)),
        failures=[
            DQFailure(
                expectation=str(item.get("expectation", "")),
                column=item.get("column"),
                details=item.get("details", {}),
            )
            for item in payload.get("failures", [])
        ],
    )


def _auto_expectation_from_payload(payload: dict[str, Any]) -> AutoExpectationRun:
    passed = int(payload.get("passed", 0))
    failed = int(payload.get("failed", 0))
    executed = int(payload.get("executed_count", 0))
    report = None
    if executed:
        report = DQReport(
            passed=failed == 0,
            evaluated=executed,
            successful=passed,
            failed=failed,
            failures=[
                DQFailure(
                    expectation=str(item.get("expectation", "")),
                    column=item.get("column"),
                    details=item.get("details", {}),
                )
                for item in payload.get("failures", [])
            ],
        )

    return AutoExpectationRun(
        specs=[
            AutoExpectationSpec(
                expectation_type=str(item.get("expectation_type", "")),
                column=str(item.get("column", "")),
                kwargs={},
                rationale=str(item.get("rationale", "")),
                confidence=str(item.get("confidence", "")),
                generation_source=str(item.get("generation_source", "LLM")),
            )
            for item in payload.get("specs", [])
        ],
        outcomes=payload.get("outcomes", []),
        report=report,
        error=payload.get("error"),
        diagnostic=payload.get("diagnostic"),
    )


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


PATTERN_DISPLAY_ALIASES = {
    "PHONE_NUMBER": "Phone",
    "EMAIL_ADDRESS": "Email",
    "US_SSN": "SSN",
    "CREDIT_CARD": "Credit Card",
    "IP_ADDRESS": "IP",
    "PERSON": "Person",
    "LOCATION": "Location",
}

def format_pattern_label(pattern: Any, detection_source: Any) -> str:
    raw_pattern = str(pattern or "").strip()
    raw_source = str(detection_source or "").strip()

    if not raw_pattern:
        return ""

    display_name = PATTERN_DISPLAY_ALIASES.get(raw_pattern)
    if display_name is None:
        normalized = raw_pattern.replace("_", " ").strip()
        display_name = normalized.title() if normalized else raw_pattern

    source_suffix = {
        "REGEX_RULE": "Regex",
        "PRESIDIO_NLP": "NLP",
        "STRICT_FALLBACK": "Fallback",
    }.get(raw_source)

    return f"{display_name}({source_suffix})" if source_suffix else display_name


def with_display_pattern(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "pattern" not in df.columns:
        return df

    display_df = df.copy()
    display_df["pattern"] = display_df.apply(
        lambda row: format_pattern_label(
            row.get("pattern"),
            row.get("detection_source"),
        ),
        axis=1,
    )
    return display_df


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


def _replace_samples(value: str, samples: list[str], token: str) -> str:
    updated = value
    for sample in samples:
        updated = updated.replace(sample, token)
    return updated


def dataframe_to_bytes(df: pd.DataFrame, extension: str) -> bytes:
    if extension == "avro":
        buffer = io.BytesIO()
        fields = [{"name": str(column), "type": ["null", "string"]} for column in df.columns]
        schema = {"type": "record", "name": "RemediatedRecord", "fields": fields}
        records = [
            {str(column): None if pd.isna(value) else str(value) for column, value in row.items()}
            for row in df.to_dict(orient="records")
        ]
        avro_writer(buffer, schema, records)
        return buffer.getvalue()
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


def _initialize_option_group(master_key: str, defaults: dict[str, Any]) -> None:
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)
    st.session_state.setdefault(
        master_key,
        all(bool(st.session_state[key]) for key in defaults),
    )


def _set_option_group(master_key: str, selected_values: dict[str, Any]) -> None:
    selected = bool(st.session_state[master_key])
    for key, value in selected_values.items():
        st.session_state[key] = value if selected else ([] if isinstance(value, list) else False)


def _sync_option_group(master_key: str, option_keys: list[str]) -> None:
    st.session_state[master_key] = all(
        bool(st.session_state.get(key)) for key in option_keys
    )


def _option_checkbox(
    label: str,
    key: str,
    master_key: str,
    option_keys: list[str],
    **kwargs: Any,
) -> bool:
    return st.checkbox(
        label,
        key=key,
        on_change=_sync_option_group,
        args=(master_key, option_keys),
        **kwargs,
    )


_SCAN_OPTIONS = {
    "run_scan": True,
    "include_presidio": True,
    "show_samples": True,
    "skip_large_files": True,
}
_DQ_OPTIONS = {
    "run_dq": True,
    "run_narrative": False,
    "run_anomaly": False,
    "run_plausibility": False,
    "run_consistency": False,
    "run_completeness": False,
    "run_auto_dq_expectations": True,
}
_AI_PII_OPTIONS = {
    "run_semantic": False,
    "run_regulatory": False,
    "run_quasi": False,
    "run_format": False,
}
_CLOUD_REMEDIATION_OPTIONS = {
    "build_anonymized": True,
    "include_review_findings": True,
    "selected_remediation_patterns": list(REMEDIATION_PATTERN_OPTIONS),
    "strict_person_fallback": True,
    "strict_location_fallback": True,
    "strict_common_fallback": True,
    "strict_date_fallback": True,
}
_ALL_SCAN_OPTIONS = {key: True for key in _SCAN_OPTIONS}
_ALL_DQ_OPTIONS = {key: True for key in _DQ_OPTIONS}
_ALL_AI_PII_OPTIONS = {key: True for key in _AI_PII_OPTIONS}
_ALL_CLOUD_REMEDIATION_OPTIONS = dict(_CLOUD_REMEDIATION_OPTIONS)
for _master_key, _defaults in [
    ("scan_options_select_all", _SCAN_OPTIONS),
    ("dq_select_all", _DQ_OPTIONS),
    ("ai_pii_select_all", _AI_PII_OPTIONS),
    ("cloud_remediation_select_all", _CLOUD_REMEDIATION_OPTIONS),
]:
    _initialize_option_group(_master_key, _defaults)


st.set_page_config(page_title="Pre-Ingestion PII Tool", page_icon="🔎", layout="wide")

st.title("Pre-Ingestion PII Tool")
run_clicked = st.button("Scan", type="primary", key="main_scan_button")
st.caption("Scan files for PII and data quality issues before ingestion.")

with st.sidebar:
    st.header("DQ API Backend")
    api_base = st.text_input(
        "FastAPI base URL",
        value=os.getenv("PII_SCANNER_API_BASE", "http://localhost:8000"),
        help="Start the backend with: uvicorn api:app --reload",
    )
    configured_api_key = os.getenv("PII_SCANNER_API_KEY", "")
    if configured_api_key:
        api_key = configured_api_key
        st.success("API authentication configured")
    else:
        api_key = st.text_input("API key (if required)", value="", type="password")

    st.header("Scan Options")
    st.checkbox(
        "Select all",
        key="scan_options_select_all",
        help="Select or clear every option in Scan Options.",
        on_change=_set_option_group,
        args=("scan_options_select_all", _ALL_SCAN_OPTIONS),
    )
    run_scan = _option_checkbox("Detect PII", "run_scan", "scan_options_select_all", list(_SCAN_OPTIONS))
    include_presidio = _option_checkbox("Include Presidio findings", "include_presidio", "scan_options_select_all", list(_SCAN_OPTIONS))
    show_samples = _option_checkbox("Show sample values", "show_samples", "scan_options_select_all", list(_SCAN_OPTIONS))
    skip_large_files = _option_checkbox("Skip very large files", "skip_large_files", "scan_options_select_all", list(_SCAN_OPTIONS))
    max_file_size_mb = st.number_input(
        "Max file size (MB)",
        min_value=1,
        max_value=1024,
        value=1024,
        step=1,
        disabled=not skip_large_files,
        help="Files larger than this limit are skipped when the option is enabled.",
    )

    st.header("Data Quality")
    st.checkbox(
        "Select all",
        key="dq_select_all",
        help="Select or clear every Data Quality check.",
        on_change=_set_option_group,
        args=("dq_select_all", _ALL_DQ_OPTIONS),
    )
    run_dq = _option_checkbox("Run data quality checks", "run_dq", "dq_select_all", list(_DQ_OPTIONS))
    run_narrative = _option_checkbox("DQ failure narrative (Azure OpenAI)", "run_narrative", "dq_select_all", list(_DQ_OPTIONS), disabled=not run_dq, help="GPT explains what is wrong and what to do when a check fails.")
    run_anomaly = _option_checkbox("Anomaly detection (AI)", "run_anomaly", "dq_select_all", list(_DQ_OPTIONS), disabled=not run_dq, help="Isolation Forest flags statistically unusual values per column.")
    run_plausibility = _option_checkbox("Value plausibility (Azure OpenAI)", "run_plausibility", "dq_select_all", list(_DQ_OPTIONS), disabled=not run_dq, help="GPT checks whether individual values make sense for their column.")
    run_consistency = _option_checkbox("Cross-column consistency (Azure OpenAI)", "run_consistency", "dq_select_all", list(_DQ_OPTIONS), disabled=not run_dq, help="GPT checks for contradictions between columns (e.g. end date before start date).")
    run_completeness = _option_checkbox("Completeness assessment (Azure OpenAI)", "run_completeness", "dq_select_all", list(_DQ_OPTIONS), disabled=not run_dq, help="GPT identifies columns that appear incomplete or companion columns that are missing.")
    run_auto_dq_expectations = _option_checkbox(
        "Generate and run LLM Great Expectations (Azure OpenAI)",
        key="run_auto_dq_expectations",
        master_key="dq_select_all",
        option_keys=list(_DQ_OPTIONS),
        disabled=not run_dq,
        help="Azure OpenAI proposes additional Great Expectations checks from data profiling; the API runs and reports them.",
    )

    st.header("AI — PII & Compliance")
    st.checkbox(
        "Select all",
        key="ai_pii_select_all",
        help="Select or clear every AI PII and compliance check.",
        on_change=_set_option_group,
        args=("ai_pii_select_all", _ALL_AI_PII_OPTIONS),
    )
    run_semantic = _option_checkbox("Semantic PII risk (Azure OpenAI)", "run_semantic", "ai_pii_select_all", list(_AI_PII_OPTIONS), help="GPT flags columns that look like PII but weren't caught by the scanner.")
    run_regulatory = _option_checkbox("Regulatory risk — HIPAA/GDPR/CCPA (Azure OpenAI)", "run_regulatory", "ai_pii_select_all", list(_AI_PII_OPTIONS), help="GPT identifies columns that may trigger regulatory obligations.")
    run_quasi = _option_checkbox("Quasi-identifier detection (Azure OpenAI)", "run_quasi", "ai_pii_select_all", list(_AI_PII_OPTIONS), help="GPT identifies column combinations that together could re-identify individuals.")
    run_format = _option_checkbox("Format anomaly check (Azure OpenAI)", "run_format", "ai_pii_select_all", list(_AI_PII_OPTIONS), help="GPT checks whether values match the format implied by the column name.")

    st.header("Cloud Remediation")
    st.checkbox(
        "Select all",
        key="cloud_remediation_select_all",
        help="Select or clear every Cloud Remediation option.",
        on_change=_set_option_group,
        args=("cloud_remediation_select_all", _ALL_CLOUD_REMEDIATION_OPTIONS),
    )
    build_anonymized = _option_checkbox("Generate cloud-ready files", "build_anonymized", "cloud_remediation_select_all", list(_CLOUD_REMEDIATION_OPTIONS))
    remediation_mode = st.selectbox(
        "Remediation strategy",
        options=["redact", "mask_last4", "hash"],
        format_func=lambda x: {
            "redact": "Redact",
            "mask_last4": "Mask keep last 4",
            "hash": "Hash tokenize",
        }[x],
    )
    include_review_findings = _option_checkbox(
        "Also remediate REVIEW findings",
        key="include_review_findings",
        master_key="cloud_remediation_select_all",
        option_keys=list(_CLOUD_REMEDIATION_OPTIONS),
        help="REVIEW findings usually come from NLP and may include false positives.",
    )
    selected_remediation_patterns = st.multiselect(
        "PII types to remediate",
        options=REMEDIATION_PATTERN_OPTIONS,
        key="selected_remediation_patterns",
        on_change=_sync_option_group,
        args=("cloud_remediation_select_all", list(_CLOUD_REMEDIATION_OPTIONS)),
        format_func=lambda p: f"{format_pattern_label(p, '')} ({p})",
        help="Only selected types will be redacted/masked/hashed in cloud-ready outputs.",
    )
    strict_person_fallback = _option_checkbox(
        "Strict fallback for missed names in narrative text",
        key="strict_person_fallback",
        master_key="cloud_remediation_select_all",
        option_keys=list(_CLOUD_REMEDIATION_OPTIONS),
        help=(
            "Adds a context-aware fallback for PERSON in phrases like "
            "'<Name> requested that documents be mailed'."
        ),
    )
    strict_location_fallback = _option_checkbox(
        "Strict fallback for missed locations in narrative text",
        key="strict_location_fallback",
        master_key="cloud_remediation_select_all",
        option_keys=list(_CLOUD_REMEDIATION_OPTIONS),
        help=(
            "Adds a context-aware fallback for mailing addresses and city/state/zip "
            "segments in narrative lines."
        ),
    )
    strict_common_fallback = _option_checkbox(
        "Strict fallback for common PII patterns",
        key="strict_common_fallback",
        master_key="cloud_remediation_select_all",
        option_keys=list(_CLOUD_REMEDIATION_OPTIONS),
        help="Adds regex/context fallbacks for email, phone, SSN, cards, accounts, EIN, and IP.",
    )
    strict_date_fallback = _option_checkbox(
        "Contextual date fallback (DOB/birth context)",
        key="strict_date_fallback",
        master_key="cloud_remediation_select_all",
        option_keys=list(_CLOUD_REMEDIATION_OPTIONS),
        disabled=not strict_common_fallback,
        help="Redacts date values only when DOB/birth context appears in the text.",
    )
    hash_salt = st.text_input(
        "Hash salt",
        value="local-remediation-salt",
        disabled=remediation_mode != "hash",
        help="Used only for hash mode to produce deterministic tokens.",
    )

run_ai_dq = any(
    [
        run_narrative,
        run_anomaly,
        run_semantic,
        run_regulatory,
        run_quasi,
        run_format,
        run_plausibility,
        run_consistency,
        run_completeness,
        run_auto_dq_expectations,
    ]
)

uploaded_files = st.file_uploader(
    "Upload multiple files or a ZIP archive",
    type=["avro", "csv", "json", "parquet", "txt", "xlsx", "xls", "zip"],
    accept_multiple_files=True,
)

sample_large_files = st.checkbox(
    "Use a representative sample for large Avro files",
    value=True,
    help="Streams Avro files of 100 MB or larger and uses a deterministic reservoir sample for PII, DQ, and remediation analysis.",
)
sample_row_limit = st.number_input(
    "Maximum sampled rows",
    min_value=100,
    max_value=10000,
    value=1000,
    step=100,
    disabled=not sample_large_files,
)

if uploaded_files:
    input_files = expand_input_files(
        uploaded_files,
        sample_large_files=sample_large_files,
        sample_row_limit=int(sample_row_limit),
    )
    st.info(f"{len(input_files)} file(s) queued for scan.")
    st.caption("You can select multiple files directly or upload a ZIP containing supported file types.")
else:
    input_files = []

if run_clicked and not input_files:
    st.warning("Upload at least one file to run the scan.")
if run_clicked and input_files and not (run_scan or run_dq or run_ai_dq):
    st.warning("Select PII detection or at least one data quality check.")

if run_clicked and input_files and (run_scan or run_dq or run_ai_dq):
    scans: list[UploadedScan] = []
    all_findings: list[dict[str, Any]] = []
    all_stats: list[dict[str, Any]] = []
    file_statuses: list[FileStatus] = []
    dq_input_reports: dict[str, DQReport] = {}
    dq_output_report: DQReport | None = None
    anomaly_results: dict[str, list[AnomalyResult]] = {}
    dq_narratives: dict[str, str] = {}
    semantic_risks: dict[str, list[SemanticRisk]] = {}
    regulatory_flags: dict[str, list[RegulatoryFlag]] = {}
    quasi_groups: dict[str, list[QuasiIdentifierGroup]] = {}
    format_anomalies: dict[str, list[FormatAnomaly]] = {}
    plausibility_issues: dict[str, list[PlausibilityIssue]] = {}
    consistency_issues: dict[str, list[ConsistencyIssue]] = {}
    completeness_issues: dict[str, list[CompletenessIssue]] = {}
    auto_expectation_runs: dict[str, AutoExpectationRun] = {}
    dq_api_errors: dict[str, dict[str, str]] = {}

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

                if run_scan:
                    findings, stats = scan_dataframe(df, uploaded.name)
                else:
                    findings = []
                    stats = {
                        "source": uploaded.name,
                        "columns_scanned": 0,
                        "findings": 0,
                    }

                known_cols = {
                    str(finding.get("column"))
                    for finding in findings
                    if finding.get("column")
                }

                if run_dq:
                    try:
                        report_payload = _post_quality_file(
                            api_base,
                            "/quality/validate/file",
                            uploaded.name,
                            uploaded.payload,
                            api_key,
                        )
                        dq_input_reports[uploaded.name] = _dq_report_from_payload(report_payload)
                    except Exception as exc:
                        dq_api_errors.setdefault(uploaded.name, {})["validation"] = str(exc)

                if run_ai_dq:
                    ai_params: dict[str, Any] = {
                        "narrative": run_narrative,
                        "anomaly": run_anomaly,
                        "semantic_pii": run_semantic,
                        "regulatory": run_regulatory,
                        "quasi_id": run_quasi,
                        "format_check": run_format,
                        "plausibility": run_plausibility,
                        "consistency": run_consistency,
                        "completeness": run_completeness,
                        "auto_expectations": run_auto_dq_expectations,
                    }
                    if run_semantic and known_cols:
                        ai_params["known_pii_columns"] = sorted(known_cols)

                    try:
                        ai_result = _post_quality_file(
                            api_base,
                            "/quality/ai-analysis/file",
                            uploaded.name,
                            uploaded.payload,
                            api_key,
                            params=ai_params,
                        )
                        if run_narrative and ai_result.get("narrative"):
                            dq_narratives[uploaded.name] = ai_result["narrative"]
                        if run_anomaly:
                            anomaly_results[uploaded.name] = [
                                AnomalyResult(
                                    column=item.get("column", ""),
                                    anomalous_row_count=item.get("anomalous_row_count", 0),
                                    total_rows=item.get("total_rows", 0),
                                    anomaly_pct=item.get("anomaly_pct", 0),
                                    explanation=item.get("explanation", ""),
                                    sample_anomalous_values=item.get("sample_anomalous_values", []),
                                )
                                for item in ai_result.get("anomalies", [])
                            ]
                        if run_semantic:
                            semantic_risks[uploaded.name] = [
                                SemanticRisk(**item)
                                for item in ai_result.get("semantic_pii_risks", [])
                            ]
                        if run_regulatory:
                            regulatory_flags[uploaded.name] = [
                                RegulatoryFlag(**item)
                                for item in ai_result.get("regulatory_flags", [])
                            ]
                        if run_quasi:
                            quasi_groups[uploaded.name] = [
                                QuasiIdentifierGroup(**item)
                                for item in ai_result.get("quasi_identifiers", [])
                            ]
                        if run_format:
                            format_anomalies[uploaded.name] = [
                                FormatAnomaly(**item)
                                for item in ai_result.get("format_anomalies", [])
                            ]
                        if run_plausibility:
                            plausibility_issues[uploaded.name] = [
                                PlausibilityIssue(**item)
                                for item in ai_result.get("plausibility_issues", [])
                            ]
                        if run_consistency:
                            consistency_issues[uploaded.name] = [
                                ConsistencyIssue(**item)
                                for item in ai_result.get("consistency_issues", [])
                            ]
                        if run_completeness:
                            completeness_issues[uploaded.name] = [
                                CompletenessIssue(**item)
                                for item in ai_result.get("completeness_issues", [])
                            ]
                        if run_auto_dq_expectations:
                            auto_expectation_runs[uploaded.name] = _auto_expectation_from_payload(
                                ai_result.get("auto_expectations", {})
                            )
                        if ai_result.get("errors"):
                            dq_api_errors.setdefault(uploaded.name, {}).update(
                                {key: str(value) for key, value in ai_result["errors"].items()}
                            )
                    except Exception as exc:
                        dq_api_errors.setdefault(uploaded.name, {})["AI analysis"] = str(exc)

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
                        detail=(
                            f"Scanned successfully with {len(findings)} finding(s)"
                            if run_scan
                            else "Processed for data quality; PII scan was not selected"
                        ),
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
    findings_display_df = with_display_pattern(findings_df)
    stats_df = pd.DataFrame(all_stats)
    risk_summary = summarize_findings(findings_df)

    if run_scan and run_dq and not findings_df.empty:
        dq_output_report = validate_output(findings_df)

    if run_scan:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("CRITICAL", risk_summary["CRITICAL"])
        c2.metric("HIGH", risk_summary["HIGH"])
        c3.metric("MEDIUM", risk_summary["MEDIUM"])
        c4.metric("LOW", risk_summary["LOW"])
        c5.metric("REVIEW", risk_summary["REVIEW"])
    else:
        st.info("PII detection was not selected.")

    st.subheader("Top Findings")
    if not run_scan:
        st.info("Enable Detect PII to generate findings.")
    elif findings_df.empty:
        st.info("No findings detected for selected options.")
    else:
        top = (
            findings_display_df.groupby(["pattern", "risk"], dropna=False)["matches"]
            .sum()
            .reset_index()
            .sort_values(by="matches", ascending=False)
            .head(10)
        )
        st.dataframe(top, width="stretch")

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
        st.dataframe(status_df, width="stretch")
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
            safe_cols = [c for c in findings_display_df.columns if c not in sample_cols]
            st.dataframe(findings_display_df[safe_cols], width="stretch")
        else:
            st.dataframe(findings_display_df, width="stretch")

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
                    scan_findings_display_df = with_display_pattern(scan_findings_df)
                    if not show_samples:
                        sample_cols = [f"sample_match_{i}" for i in range(1, 6)]
                        safe_cols = [
                            c for c in scan_findings_display_df.columns if c not in sample_cols
                        ]
                        st.dataframe(scan_findings_display_df[safe_cols], width="stretch")
                    else:
                        st.dataframe(scan_findings_display_df, width="stretch")
    else:
        st.info("No successful file scans to show in per-file tabs.")

    st.subheader("File Scan Stats")
    st.dataframe(stats_df, width="stretch")

    findings_bytes = findings_df.to_csv(index=False).encode("utf-8")

    if (run_dq or run_ai_dq) and (
        dq_input_reports
        or dq_output_report
        or anomaly_results
        or dq_narratives
        or semantic_risks
        or regulatory_flags
        or quasi_groups
        or format_anomalies
        or plausibility_issues
        or consistency_issues
        or completeness_issues
        or auto_expectation_runs
        or dq_api_errors
    ):
        st.subheader("Data Quality")
        if dq_input_reports:
            with st.expander("File quality checks", expanded=True):
                for fname, report in dq_input_reports.items():
                    status = "✅ passed" if report.passed else "❌ failed"
                    st.markdown(f"**{fname}** — {status} ({report.successful}/{report.evaluated} checks)")
                    score = round(report.successful / report.evaluated * 100) if report.evaluated else 0
                    score_cols = st.columns(4)
                    score_cols[0].metric("Quality Score", f"{score}%")
                    score_cols[1].metric("Checks Run", report.evaluated)
                    score_cols[2].metric("Passed", report.successful)
                    score_cols[3].metric("Failed", report.failed)
                    if report.evaluated == 0:
                        st.info("No Great Expectations checks were run for this file.")
                    elif score >= 90:
                        st.success(f"Data quality is **{score}%** — meets threshold.")
                    elif score >= 70:
                        st.warning(f"Data quality is **{score}%** — review failures below.")
                    else:
                        st.error(f"Data quality is **{score}%** — significant issues detected.")
                    if report.failures:
                        rows = [
                            {"issue": f.expectation, "column": f.column or "", **f.details}
                            for f in report.failures
                        ]
                        st.dataframe(pd.DataFrame(rows), width="stretch")
                    narrative = dq_narratives.get(fname, "")
                    if narrative:
                        st.info(f"**AI summary:** {narrative}")
        if run_dq:
            st.markdown("#### LLM-Generated Great Expectations")
            if not run_auto_dq_expectations:
                st.info("LLM-generated expectations are disabled in the Data Quality options.")
            elif not auto_expectation_runs:
                st.info("No LLM expectation results were returned. Check the DQ API errors below.")
            else:
                for fname, auto_run in auto_expectation_runs.items():
                    st.markdown(f"**{fname}**")
                    if auto_run.error:
                        st.warning(f"Could not generate expectations: {auto_run.error}")
                        if auto_run.diagnostic and auto_run.diagnostic.get("hint"):
                            st.caption(auto_run.diagnostic["hint"])
                        continue

                    report = auto_run.report
                    if report is None:
                        st.info("No generated expectations were available to execute.")
                        if auto_run.diagnostic and auto_run.diagnostic.get("hint"):
                            st.caption(auto_run.diagnostic["hint"])
                        continue

                    score = round(report.success_rate * 100)
                    score_cols = st.columns(4)
                    score_cols[0].metric("LLM Quality Score", f"{score}%")
                    score_cols[1].metric("Expectations Run", report.evaluated)
                    score_cols[2].metric("Passed", report.successful)
                    score_cols[3].metric("Failed", report.failed)
                    if score >= 90:
                        st.success(f"LLM expectations pass at **{score}%**.")
                    elif score >= 70:
                        st.warning(f"LLM expectations pass at **{score}%** — review failures.")
                    else:
                        st.error(f"LLM expectations pass at **{score}%** — significant issues.")

                    outcome_rows = [
                        {
                            "status": outcome["status_icon"],
                            "expectation": outcome["expectation_label"],
                            "column": outcome["column"],
                            "source": outcome.get("generation_source", "LLM"),
                            "confidence": outcome["confidence"],
                            "why this expectation was created": outcome["rationale"],
                            "params": json.dumps(outcome["params"], ensure_ascii=False),
                        }
                        for outcome in auto_run.outcomes
                    ]
                    if outcome_rows:
                        st.dataframe(pd.DataFrame(outcome_rows), width="stretch")

                    failed_rows = [
                        {
                            "expectation": outcome["expectation_label"],
                            "column": outcome["column"],
                            "why failed": outcome["failure_details"].get("why_failed", ""),
                            **{
                                key: value
                                for key, value in outcome["failure_details"].items()
                                if key != "why_failed"
                            },
                        }
                        for outcome in auto_run.outcomes
                        if outcome.get("passed") is False
                    ]
                    if failed_rows:
                        st.caption("Failed expectations and reasons")
                        st.dataframe(pd.DataFrame(failed_rows), width="stretch")
        if anomaly_results:
            flagged = {f: [a for a in anoms if a.flagged] for f, anoms in anomaly_results.items()}
            any_flagged = any(flagged.values())
            with st.expander("Anomaly detection (AI)", expanded=any_flagged):
                for fname, anoms in flagged.items():
                    if not anoms:
                        st.markdown(f"**{fname}** — ✅ no anomalies detected")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(anoms)} column(s) with anomalous values")
                    rows = [
                        {
                            "column": a.column,
                            "anomalous rows": a.anomalous_row_count,
                            "anomaly %": f"{a.anomaly_pct}%",
                            "why flagged": getattr(a, "explanation", ""),
                            "sample values": ", ".join(a.sample_anomalous_values),
                        }
                        for a in anoms
                    ]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if semantic_risks:
            any_risks = any(semantic_risks.values())
            with st.expander("Semantic PII risk (AI)", expanded=any_risks):
                for fname, risks in semantic_risks.items():
                    if not risks:
                        st.markdown(f"**{fname}** — ✅ no additional PII columns identified")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(risks)} column(s) flagged by AI")
                    rows = [{"column": r.column, "risk": r.risk, "reason": r.reason} for r in risks]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if regulatory_flags:
            any_flags = any(regulatory_flags.values())
            with st.expander("Regulatory risk — HIPAA / GDPR / CCPA (AI)", expanded=any_flags):
                for fname, flags in regulatory_flags.items():
                    if not flags:
                        st.markdown(f"**{fname}** — ✅ no regulatory obligations identified")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(flags)} regulatory flag(s)")
                    rows = [{"column": f.column, "regulation": f.regulation, "category": f.category, "severity": f.severity, "obligation": f.obligation} for f in flags]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if quasi_groups:
            any_quasi = any(quasi_groups.values())
            with st.expander("Quasi-identifier detection (AI)", expanded=any_quasi):
                for fname, groups in quasi_groups.items():
                    if not groups:
                        st.markdown(f"**{fname}** — ✅ no quasi-identifier combinations found")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(groups)} re-identification risk group(s)")
                    rows = [{"columns": ", ".join(g.columns), "risk": g.risk, "reason": g.reason} for g in groups]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if format_anomalies:
            any_fmt = any(format_anomalies.values())
            with st.expander("Format anomaly check (AI)", expanded=any_fmt):
                for fname, anomalies in format_anomalies.items():
                    if not anomalies:
                        st.markdown(f"**{fname}** — ✅ all column values match expected formats")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(anomalies)} format mismatch(es)")
                    rows = [{"column": a.column, "expected": a.expected_format, "issue": a.observed_issue, "severity": a.severity} for a in anomalies]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if plausibility_issues:
            any_p = any(plausibility_issues.values())
            with st.expander("Value plausibility (AI)", expanded=any_p):
                for fname, issues in plausibility_issues.items():
                    if not issues:
                        st.markdown(f"**{fname}** — ✅ all values appear plausible")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(issues)} plausibility issue(s)")
                    rows = [{"column": i.column, "severity": i.severity, "issue": i.issue, "example": i.example} for i in issues]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if consistency_issues:
            any_c = any(consistency_issues.values())
            with st.expander("Cross-column consistency (AI)", expanded=any_c):
                for fname, issues in consistency_issues.items():
                    if not issues:
                        st.markdown(f"**{fname}** — ✅ no cross-column inconsistencies found")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(issues)} consistency issue(s)")
                    rows = [{"columns": i.columns, "severity": i.severity, "issue": i.issue} for i in issues]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if completeness_issues:
            any_co = any(completeness_issues.values())
            with st.expander("Completeness assessment (AI)", expanded=any_co):
                for fname, issues in completeness_issues.items():
                    if not issues:
                        st.markdown(f"**{fname}** — ✅ dataset appears complete")
                        continue
                    st.markdown(f"**{fname}** — ⚠️ {len(issues)} completeness gap(s)")
                    rows = [{"column": i.column, "severity": i.severity, "issue": i.issue} for i in issues]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if dq_output_report:
            with st.expander("Scanner diagnostics (advanced)", expanded=not dq_output_report.passed):
                status = "✅ passed" if dq_output_report.passed else "❌ failed"
                st.markdown(f"Scan output schema — {status} ({dq_output_report.successful}/{dq_output_report.evaluated} checks)")
                if dq_output_report.failures:
                    rows = [
                        {"issue": f.expectation, "column": f.column or "", **f.details}
                        for f in dq_output_report.failures
                    ]
                    st.dataframe(pd.DataFrame(rows), width="stretch")
        if dq_api_errors:
            with st.expander("DQ API errors", expanded=True):
                for fname, errors in dq_api_errors.items():
                    st.markdown(f"**{fname}**")
                    for check, message in errors.items():
                        st.error(f"{check}: {message}")

    if run_scan:
        st.download_button(
            "Download Findings CSV",
            data=findings_bytes,
            file_name="pii_findings.csv",
            mime="text/csv",
        )

    if run_scan and build_anonymized and scans:
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
                    selected_patterns=set(selected_remediation_patterns),
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
            st.dataframe(summary, width="stretch")

        st.download_button(
            "Download Cloud-Ready Files (ZIP)",
            data=zip_buffer.getvalue(),
            file_name="cloud_ready_outputs.zip",
            mime="application/zip",
        )

elif run_clicked and not run_scan:
    st.info("PII detection is turned off. Enable 'Detect PII' and run scan.")
