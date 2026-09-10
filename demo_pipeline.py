"""
demo_pipeline.py — Simulated Ingestion Pipeline Demo
Demonstrates PII Detection, DQ Analysis, and PII Remediation via the local FastAPI.
Run the API first:  uvicorn api:app --reload
Then launch this app:  streamlit run demo_pipeline.py
"""
from __future__ import annotations

import io
import json
import random
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import os

if os.name == "nt":
    import truststore

    truststore.inject_into_ssl()

import pandas as pd
import requests
import streamlit as st
from fastavro import reader as avro_reader

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_API_BASE = os.getenv("PII_SCANNER_API_BASE", "http://localhost:8000")
PUBLIC_API_BASE = os.getenv("PII_SCANNER_PUBLIC_API_URL", "").strip().rstrip("/")
SUPPORTED_TYPES = ["avro", "csv", "json", "parquet", "txt", "xlsx", "xls", "zip"]
LARGE_FILE_BYTES = 100 * 1024 * 1024
RISK_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#388e3c",
    "REVIEW": "#7b1fa2",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class APICallLog:
    seq: int
    label: str
    method: str
    url: str
    file_name: str
    file_size_kb: float
    status_code: int
    elapsed_ms: float
    request_summary: str
    response_preview: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


@dataclass
class PipelineResult:
    file_name: str
    pii_result: dict[str, Any] | None = None
    dq_result: dict[str, Any] | None = None
    ai_dq_result: dict[str, Any] | None = None
    remediation_result: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_json_preview(data: Any, max_chars: int = 1800) -> str:
    try:
        text = json.dumps(data, indent=2, default=str)
    except Exception:
        text = str(data)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n  ... [{len(text) - max_chars} chars truncated]"
    return text


def _call_api(
    seq: int,
    label: str,
    method: str,
    url: str,
    file_name: str,
    file_bytes: bytes,
    params: dict | None = None,
    api_key: str = "",
) -> tuple[APICallLog, dict | None]:
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    size_kb = round(len(file_bytes) / 1024, 1)
    mime = _mime_for(file_name)
    files = {"file": (file_name, io.BytesIO(file_bytes), mime)}
    request_summary = (
        f"{method} {url}\n"
        f"  file : {file_name} ({size_kb} KB, {mime})\n"
        f"  params: {json.dumps(params or {})}"
    )

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method,
            url,
            files=files,
            params=params or {},
            headers=headers,
            timeout=330,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

        log = APICallLog(
            seq=seq,
            label=label,
            method=method,
            url=url,
            file_name=file_name,
            file_size_kb=size_kb,
            status_code=resp.status_code,
            elapsed_ms=elapsed_ms,
            request_summary=request_summary,
            response_preview=_fmt_json_preview(body)
            + ("\n\n  HINT: Enter your API key in the sidebar (PII_SCANNER_API_KEY)." if resp.status_code == 401 else ""),
            success=resp.status_code < 300,
        )
        return log, body if resp.status_code < 300 else None

    except requests.ConnectionError:
        elapsed_ms = round((time.perf_counter() - t0) * 1000)
        log = APICallLog(
            seq=seq,
            label=label,
            method=method,
            url=url,
            file_name=file_name,
            file_size_kb=size_kb,
            status_code=0,
            elapsed_ms=elapsed_ms,
            request_summary=request_summary,
            response_preview="CONNECTION REFUSED — is the FastAPI server running?",
            success=False,
        )
        return log, None
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000)
        log = APICallLog(
            seq=seq,
            label=label,
            method=method,
            url=url,
            file_name=file_name,
            file_size_kb=size_kb,
            status_code=0,
            elapsed_ms=elapsed_ms,
            request_summary=request_summary,
            response_preview=f"ERROR: {exc}",
            success=False,
        )
        return log, None


def _mime_for(file_name: str) -> str:
    ext = Path(file_name).suffix.lower()
    return {
        ".csv": "text/csv",
        ".avro": "application/avro",
        ".json": "application/json",
        ".parquet": "application/octet-stream",
        ".txt": "text/plain",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xls": "application/vnd.ms-excel",
    }.get(ext, "application/octet-stream")


def _expand_uploads(uploaded_files) -> list[tuple[str, bytes]]:
    """Flatten uploaded files; unzip ZIP archives."""
    result: list[tuple[str, bytes]] = []
    for f in uploaded_files:
        name = f.name
        data = f.getvalue()
        if Path(name).suffix.lower() == ".zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    ext = Path(member.filename).suffix.lower().lstrip(".")
                    if ext in {"avro", "csv", "json", "parquet", "txt", "xlsx", "xls"}:
                        result.append((Path(member.filename).name, zf.read(member)))
        else:
            result.append((name, data))
    return result


def _sample_avro_for_analysis(
    file_name: str,
    file_bytes: bytes,
    max_rows: int,
) -> tuple[str, bytes, int]:
    """Create a bounded CSV payload from an Avro stream using deterministic reservoir sampling."""
    reservoir: list[dict[str, Any]] = []
    seen = 0
    rng = random.Random(42)
    records = avro_reader(io.BytesIO(file_bytes))
    for record in records:
        seen += 1
        if len(reservoir) < max_rows:
            reservoir.append(record)
            continue
        replacement = rng.randrange(seen)
        if replacement < max_rows:
            reservoir[replacement] = record

    sample_name = f"{Path(file_name).stem}.sample.csv"
    sample_bytes = pd.DataFrame(reservoir).to_csv(index=False).encode("utf-8")
    return sample_name, sample_bytes, seen


def _sample_uploaded_avro_for_analysis(
    file_name: str,
    uploaded_file,
    max_rows: int,
) -> tuple[str, bytes, int]:
    """Sample a Streamlit upload in place, avoiding a second full-file bytes copy."""
    uploaded_file.seek(0)
    reservoir: list[dict[str, Any]] = []
    seen = 0
    rng = random.Random(42)
    for record in avro_reader(uploaded_file):
        seen += 1
        if len(reservoir) < max_rows:
            reservoir.append(record)
            continue
        replacement = rng.randrange(seen)
        if replacement < max_rows:
            reservoir[replacement] = record

    sample_name = f"{Path(file_name).stem}.sample.csv"
    sample_bytes = pd.DataFrame(reservoir).to_csv(index=False).encode("utf-8")
    return sample_name, sample_bytes, seen


def _prepare_uploaded_files(uploaded_files, sample_large_files: bool, sample_row_limit: int) -> list[tuple[str, bytes]]:
    """Prepare API payloads while avoiding a full-file copy for large direct Avro uploads."""
    result: list[tuple[str, bytes]] = []
    for uploaded in uploaded_files:
        file_name = uploaded.name
        if (
            sample_large_files
            and Path(file_name).suffix.lower() == ".avro"
            and uploaded.size >= LARGE_FILE_BYTES
        ):
            result.append(_sample_uploaded_avro_for_analysis(file_name, uploaded, sample_row_limit)[:2])
            continue
        result.extend(_expand_uploads([uploaded]))
    return result

# ---------------------------------------------------------------------------
# Log rendering
# ---------------------------------------------------------------------------

def _render_log(calls: list[APICallLog]) -> str:
    divider = "─" * 72
    lines: list[str] = [
        f"{'='*72}",
        f"  PIPELINE API ACTIVITY LOG  —  {datetime.now().strftime('%Y-%m-%d')}",
        f"  {len(calls)} API call(s)",
        f"{'='*72}",
        "",
    ]
    for c in calls:
        status_str = f"{c.status_code} OK" if c.success else f"{c.status_code} ERROR"
        lines += [
            divider,
            f"  #{c.seq:02d}  [{c.timestamp}]  {c.label}",
            divider,
            "",
            "  REQUEST",
            f"  ───────",
            *[f"  {line}" for line in c.request_summary.splitlines()],
            "",
            f"  RESPONSE  —  {status_str}  ({c.elapsed_ms} ms)",
            f"  ────────",
            *[f"  {line}" for line in c.response_preview.splitlines()],
            "",
        ]
    lines += [f"{'='*72}", "  END OF LOG", f"{'='*72}"]
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Result rendering
# ---------------------------------------------------------------------------

def _risk_badge(risk: str) -> str:
    return f":{risk.lower()}" if risk in {"critical", "high", "medium", "low"} else ""


def _render_pii_result(result: dict[str, Any], file_name: str) -> None:
    stats = result.get("stats", {})
    findings = result.get("findings", [])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Columns Scanned", stats.get("columns_scanned", "—"))
    col2.metric("PII Findings", len(findings))
    pii_cols = stats.get("columns_with_pii_count", stats.get("pii_columns", "—"))
    col3.metric("PII Columns", pii_cols)
    col4.metric("Rows", stats.get("rows", "—"))

    if not findings:
        st.success("No PII detected.")
        return

    findings_df = pd.DataFrame(findings)

    # Risk summary
    if "risk" in findings_df.columns:
        risk_counts = findings_df["risk"].value_counts()
        st.markdown("**Risk breakdown:**")
        rcols = st.columns(len(risk_counts))
        for i, (risk, count) in enumerate(risk_counts.items()):
            color = RISK_COLORS.get(risk, "#555")
            rcols[i].markdown(
                f"<span style='color:{color};font-weight:bold;font-size:1.1em'>"
                f"{risk}</span><br><span style='font-size:1.4em'>{count}</span>",
                unsafe_allow_html=True,
            )

    # Findings table (truncated columns for readability)
    display_cols = [c for c in ["column", "pattern", "risk", "detection_source"] if c in findings_df.columns]
    if display_cols:
        st.dataframe(findings_df[display_cols].drop_duplicates(), use_container_width=True)


def _render_dq_result(result: dict[str, Any], file_name: str) -> None:
    # API returns: evaluated, successful, failed, success_rate, failures[]
    evaluated = result.get("evaluated", 0)
    successful = result.get("successful", 0)
    failed = result.get("failed", 0)
    score = round((successful / evaluated) * 100) if evaluated else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Quality Score", f"{score}%")
    c2.metric("Checks Run", evaluated)
    c3.metric("Passed", successful)
    c4.metric("Failed", failed)

    if evaluated == 0:
        st.info("No Great Expectations checks were run for this file type.")
    elif score >= 90:
        st.success(f"Data quality is **{score}%** — meets threshold.")
    elif score >= 70:
        st.warning(f"Data quality is **{score}%** — review failures below.")
    else:
        st.error(f"Data quality is **{score}%** — significant issues detected.")

    failures = result.get("failures", [])
    if failures:
        st.markdown("**Failed checks:**")
        for f in failures[:15]:
            # API serialises DQFailure with key "expectation" (human label)
            exp = f.get("expectation", f.get("expectation_type", "check"))
            col = f.get("column", "")
            details = f.get("details", {})
            detail_str = ", ".join(f"{k}: {v}" for k, v in details.items() if v) if details else ""
            msg = f"• **{exp}**" + (f" — `{col}`" if col else "") + (f"  ({detail_str})" if detail_str else "")
            st.markdown(msg)
        if len(failures) > 15:
            st.caption(f"… and {len(failures) - 15} more failures")


_SEV_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def _render_ai_dq_result(result: dict[str, Any]) -> None:
    checks_run = result.get("checks_run", [])
    if not checks_run:
        st.info("No AI checks were run.")
        return

    narrative = result.get("narrative", "")
    if narrative:
        st.markdown("**📝 DQ Narrative**")
        st.info(narrative)

    anomalies = result.get("anomalies", [])
    if "anomaly" in checks_run:
        st.markdown(f"**🤖 Anomaly Detection** — {len(anomalies)} flagged column(s)")
        if anomalies:
            for a in anomalies:
                pct = a.get("anomaly_pct", 0)
                col = a.get("column", "")
                explanation = a.get("explanation", "")
                samples = a.get("sample_anomalous_values", [])[:3]
                st.markdown(
                    f"• `{col}` — **{pct:.1f}%** anomalous rows  \n"
                    + (f"  {explanation}  \n" if explanation else "")
                    + (f"  Samples: `{'`, `'.join(samples)}`" if samples else "")
                )
        else:
            st.success("No anomalies detected.")

    # severity field name varies by check type: semantic uses "risk", others use "severity"
    _SEV_FIELD: dict[str, str] = {
        "semantic_pii_risks": "risk",
        "regulatory_flags": "severity",
        "format_anomalies": "severity",
        "plausibility_issues": "severity",
        "consistency_issues": "severity",
        "completeness_issues": "severity",
    }

    for key, label, icon in [
        ("semantic_pii_risks", "Semantic PII Risks", "🔍"),
        ("regulatory_flags", "Regulatory Flags", "⚖️"),
        ("format_anomalies", "Format Anomalies", "📐"),
        ("plausibility_issues", "Plausibility Issues", "🤔"),
        ("consistency_issues", "Cross-Column Consistency Issues", "🔗"),
        ("completeness_issues", "Completeness Issues", "📋"),
    ]:
        if key not in result:
            continue
        items = result[key]
        sev_field = _SEV_FIELD.get(key, "severity")
        st.markdown(f"**{icon} {label}** — {len(items)} item(s)")
        if items:
            rows = []
            for item in items:
                sev = item.get(sev_field, "")
                icon_sev = _SEV_ICON.get(sev, "⚪")
                col = item.get("column", item.get("columns", ""))
                if isinstance(col, list):
                    col = ", ".join(col)
                issue = item.get(
                    "issue", item.get("obligation", item.get("reason", item.get("observed_issue", "")))
                )
                rows.append({"Severity": f"{icon_sev} {sev}", "Column(s)": col, "Finding": issue})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.success("No issues found.")

    quasi = result.get("quasi_identifiers", [])
    if "quasi_id" in checks_run:
        st.markdown(f"**🔗 Quasi-Identifier Groups** — {len(quasi)} group(s)")
        for g in quasi:
            cols = g.get("columns", [])
            risk = g.get("risk", "")
            reason = g.get("reason", "")
            st.markdown(f"• {_SEV_ICON.get(risk, '⚪')} **{risk}** — `{'`, `'.join(cols)}` — {reason}")

    # Surface any per-check errors returned by the API
    api_errors = {k: v for k, v in result.get("errors", {}).items() if k != "auto_expectations"}
    if api_errors:
        st.markdown("**⚠️ Check errors:**")
        for check, msg in api_errors.items():
            st.error(f"`{check}`: {msg}")


def _render_auto_expectations(auto_exp: dict[str, Any]) -> None:
    """Renders LLM-generated expectations inline with the same style as the GE section."""
    proposed = auto_exp.get("proposed_count", 0)
    executed = auto_exp.get("executed_count", 0)
    ae_error = auto_exp.get("error")
    ae_diag = auto_exp.get("diagnostic") or {}

    passed = auto_exp.get("passed", 0)
    failed = auto_exp.get("failed", 0)
    rate = auto_exp.get("success_rate", 0)
    score = round(rate * 100)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("LLM Quality Score", f"{score}%" if executed else "—")
    c2.metric("Expectations Run", executed)
    c3.metric("Passed", passed)
    c4.metric("Failed", failed)

    if ae_error:
        st.warning(f"Could not generate expectations: {ae_error}")
    elif executed == 0:
        pass  # diagnostic expander below will explain
    elif score >= 90:
        st.success(f"LLM expectations pass at **{score}%**.")
    elif score >= 70:
        st.warning(f"LLM expectations pass at **{score}%** — review failures.")
    else:
        st.error(f"LLM expectations pass at **{score}%** — significant issues.")

    # Failed expectations
    failures = auto_exp.get("failures", [])
    if failures:
        st.markdown("**Failed LLM expectations:**")
        for f in failures:
            exp = f.get("expectation", "")
            col = f.get("column", "")
            details = f.get("details", {})
            detail_str = ", ".join(f"{k}: {v}" for k, v in details.items() if v) if details else ""
            st.markdown(
                f"• **{exp}**" + (f" — `{col}`" if col else "")
                + (f"  ({detail_str})" if detail_str else "")
            )

    # Full expectations table
    outcomes = auto_exp.get("outcomes", [])
    specs = auto_exp.get("specs", [])
    display_items = outcomes or specs
    if display_items:
        with st.expander(f"📋 All {proposed} LLM-generated expectations", expanded=False):
            if outcomes:
                rows = [
                    {
                        "Status": o.get("status_icon", ""),
                        "Expectation": o.get("expectation_label", o.get("expectation", "")),
                        "Column": o.get("column", ""),
                        "Source": o.get("generation_source", "LLM"),
                        "Confidence": o.get("confidence", ""),
                        "Rationale": o.get("rationale", ""),
                    }
                    for o in outcomes
                ]
            else:
                rows = [
                    {
                        "Expectation": s.get("expectation_type", "").replace("expect_", "").replace("_", " ").title(),
                        "Column": s.get("column", ""),
                        "Source": s.get("generation_source", "LLM"),
                        "Confidence": s.get("confidence", ""),
                        "Rationale": s.get("rationale", ""),
                    }
                    for s in specs
                ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # Diagnostic details (collapsed by default when things worked)
    if ae_diag:
        hint = ae_diag.get("hint", "")
        llm_chars = ae_diag.get("llm_response_chars", 0)
        llm_items = ae_diag.get("llm_items_parsed", 0)
        accepted = ae_diag.get("specs_accepted", 0)
        llm_accepted = ae_diag.get("llm_specs_accepted", accepted)
        fallback_count = ae_diag.get("profile_fallback_specs", 0)
        rej_type = ae_diag.get("rejected_unknown_type", 0)
        rej_col = ae_diag.get("rejected_bad_column", 0)
        raw_preview = ae_diag.get("raw_llm_preview", "")
        with st.expander("🔍 LLM diagnostic", expanded=bool(ae_error or not accepted)):
            batches = ae_diag.get("batches", 1)
            finish = ae_diag.get("llm_finish_reasons", ae_diag.get("llm_finish_reason", ""))
            if isinstance(finish, list):
                finish_str = ", ".join(f"`{r}`" for r in finish)
            else:
                finish_str = f"`{finish}`"
            st.markdown(
                f"- **{batches}** LLM batch call(s), **{llm_chars}** total chars, "
                f"finish reasons: {finish_str}\n"
                f"- **{llm_items}** item(s) parsed → LLM accepted: **{llm_accepted}** / "
                f"rejected (unknown type): **{rej_type}** / "
                f"rejected (unrecognised column): **{rej_col}**\n"
                f"- Profile fallbacks added: **{fallback_count}** / total executed: **{accepted}**"
            )
            if hint:
                st.info(hint)
            if raw_preview:
                st.code(raw_preview, language="text")


def _render_remediation_result(result: dict[str, Any], file_name: str) -> None:
    total_changed = result.get("total_cells_changed", 0)
    pii_count = result.get("pii_findings_count", 0)
    mode = result.get("mode", "redact")
    summary = result.get("remediation_summary", [])

    c1, c2, c3 = st.columns(3)
    c1.metric("Strategy", mode.upper())
    c2.metric("PII Findings Remediated", pii_count)
    c3.metric("Cells Changed", total_changed)

    if total_changed == 0:
        st.info("No cells were modified (no PII found or all findings below threshold).")
    else:
        st.success(f"Remediation complete — **{total_changed}** cell(s) transformed using `{mode}`.")

    if summary:
        st.markdown("**Remediation log:**")
        st.dataframe(pd.DataFrame(summary), use_container_width=True)

    remediated_csv = result.get("remediated_csv", "")
    if remediated_csv:
        st.download_button(
            label=f"Download remediated CSV — {file_name}",
            data=remediated_csv.encode("utf-8"),
            file_name=f"remediated_{Path(file_name).stem}.csv",
            mime="text/csv",
        )


def _render_pipeline_result(result: PipelineResult) -> None:
    st.caption(f"Results for `{result.file_name}`")

    if result.errors:
        for error in result.errors:
            st.error(error)

    if result.pii_result:
        st.markdown("#### 🔍 PII Detection")
        _render_pii_result(result.pii_result, result.file_name)

    if result.dq_result:
        st.markdown("#### 📊 Data Quality — Great Expectations")
        _render_dq_result(result.dq_result, result.file_name)

    if result.ai_dq_result and result.ai_dq_result.get("auto_expectations"):
        st.markdown(f"#### ⚙️ LLM-Generated Expectations — `{result.file_name}`")
        _render_auto_expectations(result.ai_dq_result["auto_expectations"])

    if result.ai_dq_result:
        ai_without_auto = {
            key: value
            for key, value in result.ai_dq_result.items()
            if key != "auto_expectations"
        }
        if any(key in ai_without_auto for key in [
            "narrative", "anomalies", "semantic_pii_risks", "regulatory_flags",
            "quasi_identifiers", "format_anomalies", "plausibility_issues",
            "consistency_issues", "completeness_issues",
        ]):
            st.markdown("#### 🤖 AI-Powered DQ Analysis")
            _render_ai_dq_result(ai_without_auto)

    if result.remediation_result:
        st.markdown("#### 🛡️ PII Remediation")
        _render_remediation_result(result.remediation_result, result.file_name)

# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Pipeline API Demo",
    page_icon="🔬",
    layout="wide",
)

# Sidebar — connection settings
with st.sidebar:
    st.header("API Connection")
    managed_api_base = bool(os.getenv("PII_SCANNER_API_BASE", "").strip())
    api_base = st.text_input(
        "API target (server-side)" if managed_api_base else "FastAPI base URL",
        value=DEFAULT_API_BASE,
        disabled=managed_api_base,
        help=(
            "Managed by the OpenShift deployment and resolved inside the demo container."
            if managed_api_base
            else "Start the server with: uvicorn api:app --reload"
        ),
    )
    configured_api_key = os.getenv("PII_SCANNER_API_KEY", "")
    if configured_api_key:
        api_key = configured_api_key
        st.success("API authentication configured")
    else:
        api_key = st.text_input(
            "API Key (leave blank if none)",
            value="",
            type="password",
        )
    if PUBLIC_API_BASE:
        st.info(
            f"External applications can call [{PUBLIC_API_BASE}]({PUBLIC_API_BASE}).  \n"
            f"[Open API documentation]({PUBLIC_API_BASE}/docs)  \n"
            "Protected endpoints require the `X-API-Key` request header."
        )
    st.divider()
    st.header("Remediation Options")
    remediation_mode = st.selectbox(
        "Strategy",
        options=["redact", "mask_last4", "hash"],
        format_func=lambda x: {
            "redact": "Redact  — replace with <PII_REDACT:…>",
            "mask_last4": "Mask  — keep last 4 digits",
            "hash": "Hash  — deterministic token",
        }[x],
    )
    include_review = st.checkbox("Include REVIEW-risk findings", value=True)
    st.divider()
    st.header("DQ — AI Options")
    st.caption("Requires Azure OpenAI env vars to be set on the server.")
    dq_narrative = st.checkbox("DQ failure narrative", value=False)
    dq_anomaly = st.checkbox("Anomaly detection (Isolation Forest)", value=False)
    dq_semantic_pii = st.checkbox("Semantic PII risk", value=False)
    dq_regulatory = st.checkbox("Regulatory risk — HIPAA/GDPR/CCPA", value=False)
    dq_quasi_id = st.checkbox("Quasi-identifier detection", value=False)
    dq_format_check = st.checkbox("Format anomaly check", value=False)
    dq_plausibility = st.checkbox("Value plausibility", value=False)
    dq_consistency = st.checkbox("Cross-column consistency", value=False)
    dq_completeness = st.checkbox("Completeness assessment", value=False)
    dq_auto_expectations = st.checkbox("Auto-generate expectations", value=False)
    st.divider()
    st.caption("Start the API server:")
    st.code("uvicorn api:app --reload", language="bash")

# Main area
st.title("🔬 Ingestion Pipeline API Demo")
st.caption(
    "Simulates a data ingestion pipeline that calls the local PII Scanner API "
    "for detection, quality validation, and remediation before data is loaded."
)

st.divider()

# --- Operation selector ---
st.subheader("Pipeline Operations")
st.markdown("Select one or more checks to run against each uploaded file:")

op_col1, op_col2, op_col3 = st.columns(3)
with op_col1:
    do_pii = st.toggle(
        "🔍 PII Detection",
        value=True,
        help="POST /scan/file — scans for PII using regex and Presidio NLP",
    )
    if do_pii:
        st.caption("Endpoint: `POST /scan/file`")
with op_col2:
    do_dq = st.toggle(
        "📊 DQ Analysis",
        value=True,
        help="POST /quality/validate/file — Great Expectations quality checks",
    )
    if do_dq:
        st.caption("Endpoint: `POST /quality/validate/file`")
        st.caption("+ `POST /quality/ai-analysis/file` when AI options are on")
with op_col3:
    do_remediation = st.toggle(
        "🛡️ PII Remediation",
        value=False,
        help="POST /remediate/file — scans and produces a redacted output file",
    )
    if do_remediation:
        st.caption("Endpoint: `POST /remediate/file`")

if not do_pii and not do_dq and not do_remediation:
    st.warning("Select at least one pipeline operation above.")

st.divider()

# --- File upload ---
st.subheader("Input Files")
uploaded_files = st.file_uploader(
    "Upload one or more files (or a ZIP archive containing supported files)",
    type=SUPPORTED_TYPES,
    accept_multiple_files=True,
)

sample_large_files = st.checkbox(
    "Use representative sample for large Avro files",
    value=True,
    help="Streams the Avro file and sends at most the selected number of sampled rows to each API operation.",
)
sample_row_limit = st.number_input(
    "Maximum sampled rows",
    min_value=100,
    max_value=10000,
    value=1000,
    step=100,
    disabled=not sample_large_files,
)

input_files: list[tuple[str, bytes]] = []
if uploaded_files:
    st.info(f"{len(uploaded_files)} upload(s) queued  •  Operations: "
            + ", ".join(filter(None, [
                "PII Detection" if do_pii else "",
                "DQ Analysis" if do_dq else "",
                "PII Remediation" if do_remediation else "",
            ])))

st.divider()

# --- Run button ---
run_clicked = st.button(
    "▶  Run Pipeline",
    type="primary",
    disabled=not uploaded_files or not (do_pii or do_dq or do_remediation),
)

if run_clicked and not uploaded_files:
    st.warning("Upload at least one file to run the pipeline.")

# ---------------------------------------------------------------------------
# Pipeline execution
# ---------------------------------------------------------------------------

if run_clicked and uploaded_files and (do_pii or do_dq or do_remediation):
    api_logs: list[APICallLog] = []
    results: list[PipelineResult] = []
    call_seq = 0

    health_url = f"{api_base.rstrip('/')}/health"
    try:
        health_resp = requests.get(health_url, timeout=5)
        if health_resp.status_code != 200:
            st.error(f"API health check failed ({health_resp.status_code}). Is the server running?")
            st.stop()
    except requests.ConnectionError:
        st.error(
            f"Cannot connect to API at `{api_base}`.  \n"
            "Start the server with: `uvicorn api:app --reload`"
        )
        st.stop()

    # Map each AI check to its API param name and human label
    _ai_checks: list[tuple[str, str, bool]] = [
        ("narrative",         "DQ Narrative",              dq_narrative),
        ("anomaly",           "Anomaly Detection",         dq_anomaly),
        ("semantic_pii",      "Semantic PII Risk",         dq_semantic_pii),
        ("regulatory",        "Regulatory Risk",           dq_regulatory),
        ("quasi_id",          "Quasi-Identifier Detection",dq_quasi_id),
        ("format_check",      "Format Anomaly Check",      dq_format_check),
        ("plausibility",      "Value Plausibility",        dq_plausibility),
        ("consistency",       "Cross-Column Consistency",  dq_consistency),
        ("completeness",      "Completeness Assessment",   dq_completeness),
        ("auto_expectations", "Auto-Generate Expectations",dq_auto_expectations),
    ]
    _selected_ai_checks = [(p, lbl) for p, lbl, on in _ai_checks if on]
    _any_ai_dq = bool(_selected_ai_checks)

    # Live log placeholder — updated after every API call
    st.divider()
    st.subheader("📋 API Activity Log")
    st.caption("Updates after each API call.")
    log_placeholder = st.empty()

    input_files = _prepare_uploaded_files(
        uploaded_files,
        sample_large_files=sample_large_files,
        sample_row_limit=int(sample_row_limit),
    )

    _op_count = sum([do_pii, do_dq, bool(_selected_ai_checks) if do_dq else 0, do_remediation])
    total_ops = len(input_files) * max(_op_count, 1)
    completed = 0
    progress = st.progress(0, text="Starting pipeline…")

    for file_name, file_bytes in input_files:
        pr = PipelineResult(file_name=file_name)

        # --- PII Detection ---
        if do_pii:
            call_seq += 1
            progress.progress(completed / total_ops, text=f"PII Detection → {file_name}")
            log, body = _call_api(
                seq=call_seq,
                label=f"PII Detection  |  {file_name}",
                method="POST",
                url=f"{api_base.rstrip('/')}/scan/file",
                file_name=file_name,
                file_bytes=file_bytes,
                api_key=api_key,
            )
            api_logs.append(log)
            log_placeholder.code(_render_log(api_logs), language="text")
            if body:
                pr.pii_result = body
            else:
                pr.errors.append(f"PII scan failed: {log.response_preview[:120]}")
            completed += 1

        # --- DQ Analysis (GE checks) ---
        if do_dq:
            call_seq += 1
            progress.progress(completed / total_ops, text=f"DQ Analysis → {file_name}")
            log, body = _call_api(
                seq=call_seq,
                label=f"DQ Analysis  |  {file_name}",
                method="POST",
                url=f"{api_base.rstrip('/')}/quality/validate/file",
                file_name=file_name,
                file_bytes=file_bytes,
                api_key=api_key,
            )
            api_logs.append(log)
            log_placeholder.code(_render_log(api_logs), language="text")
            if body:
                pr.dq_result = body
            else:
                pr.errors.append(f"DQ validation failed: {log.response_preview[:120]}")
            completed += 1

            # --- AI DQ checks — one upload/request for all selected checks ---
            merged_ai: dict[str, Any] = {"checks_run": []}
            if _selected_ai_checks:
                call_seq += 1
                check_labels = ", ".join(label for _, label in _selected_ai_checks)
                progress.progress(completed / total_ops, text=f"AI DQ checks → {file_name}")
                log, body = _call_api(
                    seq=call_seq,
                    label=f"AI DQ checks ({check_labels})  |  {file_name}",
                    method="POST",
                    url=f"{api_base.rstrip('/')}/quality/ai-analysis/file",
                    file_name=file_name,
                    file_bytes=file_bytes,
                    params={param: "true" for param, _ in _selected_ai_checks},
                    api_key=api_key,
                )
                api_logs.append(log)
                log_placeholder.code(_render_log(api_logs), language="text")
                if body:
                    merged_ai["checks_run"].extend(body.get("checks_run", []))
                    for k, v in body.items():
                        if k != "checks_run":
                            merged_ai[k] = v
                else:
                    pr.errors.append(f"AI DQ checks failed: {log.response_preview[:120]}")
                completed += 1

            if merged_ai["checks_run"]:
                pr.ai_dq_result = merged_ai

        # --- Remediation ---
        if do_remediation:
            call_seq += 1
            progress.progress(completed / total_ops, text=f"Remediation → {file_name}")
            log, body = _call_api(
                seq=call_seq,
                label=f"PII Remediation  |  {file_name}",
                method="POST",
                url=f"{api_base.rstrip('/')}/remediate/file",
                file_name=file_name,
                file_bytes=file_bytes,
                params={"mode": remediation_mode, "include_review": str(include_review).lower()},
                api_key=api_key,
            )
            api_logs.append(log)
            log_placeholder.code(_render_log(api_logs), language="text")
            if body:
                pr.remediation_result = body
            else:
                pr.errors.append(f"Remediation failed: {log.response_preview[:120]}")
            completed += 1

        results.append(pr)

    progress.progress(1.0, text="Pipeline complete.")
    # Final log render (replaces the last incremental update)
    log_placeholder.code(_render_log(api_logs), language="text")

    failed_calls = [c for c in api_logs if not c.success]
    if failed_calls:
        st.error(f"{len(failed_calls)} of {len(api_logs)} API call(s) failed.")
    else:
        total_ms = sum(c.elapsed_ms for c in api_logs)
        st.success(
            f"All {len(api_logs)} API call(s) succeeded  •  "
            f"Total API time: {total_ms:,.0f} ms"
        )

    # -----------------------------------------------------------------------
    # Human-readable results
    # -----------------------------------------------------------------------
    st.divider()
    st.subheader("📈 Pipeline Results")

    if len(results) > 1:
        result_tabs = st.tabs([result.file_name for result in results])
        for result_tab, result in zip(result_tabs, results):
            with result_tab:
                _render_pipeline_result(result)
    else:
        _render_pipeline_result(results[0])

    # Summary table
    if len(results) > 1:
        st.divider()
        st.markdown("#### Summary across all files")
        summary_rows = []
        for pr in results:
            row: dict[str, Any] = {"File": pr.file_name}
            if pr.pii_result:
                findings = pr.pii_result.get("findings", [])
                row["PII Findings"] = len(findings)
            if pr.dq_result:
                evaluated = pr.dq_result.get("evaluated", 0)
                successful = pr.dq_result.get("successful", 0)
                row["DQ Score"] = f"{round(successful/evaluated*100) if evaluated else 0}%"
            if pr.remediation_result:
                row["Cells Remediated"] = pr.remediation_result.get("total_cells_changed", 0)
            row["Errors"] = len(pr.errors)
            summary_rows.append(row)
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)
