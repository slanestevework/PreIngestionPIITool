from __future__ import annotations

import os
import json
from io import BytesIO
from pathlib import Path
from typing import Any

import pandas as pd
from fastavro import reader
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from scanner import scan_dataframe
from data_quality import (
    DQReport,
    validate_input,
    detect_anomalies,
    generate_narrative,
    assess_semantic_pii_risk,
    assess_regulatory_risk,
    detect_quasi_identifiers,
    detect_format_anomalies,
    assess_value_plausibility,
    detect_consistency_violations,
    assess_completeness,
    run_auto_expectations,
)
from remediate import remediate_dataframe, RemediationRecord


class ScanRecordsRequest(BaseModel):
    records: list[dict[str, Any]] = Field(
        ..., description="Array of JSON records to scan for PII."
    )
    source_name: str = Field(
        default="inline_records.json",
        description="Logical source name used in findings.",
    )


class ScanTextRequest(BaseModel):
    text: str = Field(..., description="Raw text to scan.")
    source_name: str = Field(
        default="inline_text.txt",
        description="Logical source name used in findings.",
    )
    column_name: str = Field(
        default="value",
        description="Column name used to hold text content during scanning.",
    )


app = FastAPI(
    title="PII Scanner API",
    description="On-prem API wrapper for regex + Presidio PII scanning.",
    version="1.0.0",
)

SUPPORTED_EXTENSIONS = {"avro", "csv", "json", "parquet", "txt", "xlsx", "xls"}


def _require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected_key = os.getenv("PII_SCANNER_API_KEY", "").strip()
    if not expected_key:
        return

    if x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _scan_dataframe(df: pd.DataFrame, source_name: str) -> dict[str, Any]:
    findings, stats = scan_dataframe(df=df, source_name=source_name)
    return {
        "source": source_name,
        "stats": stats,
        "findings": findings,
    }


def _load_json_dataframe_from_bytes(payload: bytes) -> pd.DataFrame:
    # Accept both JSONL and conventional JSON payloads.
    text_content = payload.decode("utf-8-sig")

    try:
        parsed = json.loads(text_content)
    except json.JSONDecodeError:
        return pd.read_json(BytesIO(payload), lines=True)

    if isinstance(parsed, list):
        return pd.json_normalize(parsed)

    if isinstance(parsed, dict):
        for list_key in ("records", "items", "data", "teas"):
            candidate = parsed.get(list_key)
            if isinstance(candidate, list):
                return pd.json_normalize(candidate)
        return pd.json_normalize([parsed])

    raise HTTPException(
        status_code=400,
        detail="Unsupported JSON structure. Expected object, array, or JSON lines.",
    )


def _load_avro_dataframe_from_bytes(payload: bytes) -> pd.DataFrame:
    return pd.DataFrame(list(reader(BytesIO(payload))))


def _load_dataframe_from_upload(upload_file: UploadFile, payload: bytes) -> pd.DataFrame:
    extension = Path(upload_file.filename or "").suffix.lower().lstrip(".")

    if extension == "csv":
        return pd.read_csv(BytesIO(payload), dtype=str)
    if extension == "avro":
        return _load_avro_dataframe_from_bytes(payload)
    if extension == "json":
        return _load_json_dataframe_from_bytes(payload)
    if extension == "parquet":
        return pd.read_parquet(BytesIO(payload))
    if extension == "txt":
        text_content = payload.decode("utf-8", errors="ignore")
        return pd.DataFrame({"value": text_content.splitlines()})
    if extension in {"xlsx", "xls"}:
        return pd.read_excel(BytesIO(payload), dtype=str)

    raise HTTPException(
        status_code=400,
        detail="Unsupported file type. Use avro, csv, json, parquet, txt, xlsx, or xls.",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan/records", dependencies=[Depends(_require_api_key)])
def scan_records(request: ScanRecordsRequest) -> dict[str, Any]:
    if not request.records:
        raise HTTPException(status_code=400, detail="records must not be empty")

    df = pd.DataFrame(request.records)
    return _scan_dataframe(df=df, source_name=request.source_name)


@app.post("/scan/text", dependencies=[Depends(_require_api_key)])
def scan_text(request: ScanTextRequest) -> dict[str, Any]:
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")

    lines = [line for line in request.text.splitlines() if line.strip()]
    if not lines:
        lines = [request.text]

    df = pd.DataFrame({request.column_name: lines})
    return _scan_dataframe(df=df, source_name=request.source_name)


@app.post("/scan/file", dependencies=[Depends(_require_api_key)])
async def scan_file(file: UploadFile = File(...)) -> dict[str, Any]:
    extension = Path(file.filename or "").suffix.lower().lstrip(".")
    if extension not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Use avro, csv, json, parquet, txt, xlsx, or xls.",
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        df = _load_dataframe_from_upload(file, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    source_name = file.filename or "uploaded_file"
    return _scan_dataframe(df=df, source_name=source_name)


@app.post("/quality/validate", dependencies=[Depends(_require_api_key)])
def quality_validate_records(request: ScanRecordsRequest) -> dict:
    """Run Great Expectations data quality checks on a JSON record payload."""
    if not request.records:
        raise HTTPException(status_code=400, detail="records must not be empty")

    df = pd.DataFrame(request.records)
    report: DQReport = validate_input(df)
    return report.to_dict()


@app.post("/quality/validate/file", dependencies=[Depends(_require_api_key)])
async def quality_validate_file(file: UploadFile = File(...)) -> dict:
    """Run Great Expectations data quality checks on an uploaded file."""
    extension = Path(file.filename or "").suffix.lower().lstrip(".")
    if extension not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Use avro, csv, json, parquet, txt, xlsx, or xls.",
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        df = _load_dataframe_from_upload(file, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    report: DQReport = validate_input(df)
    return report.to_dict()


@app.post("/quality/ai-analysis/file", dependencies=[Depends(_require_api_key)])
async def quality_ai_analysis_file(
    file: UploadFile = File(...),
    narrative: bool = False,
    anomaly: bool = False,
    semantic_pii: bool = False,
    regulatory: bool = False,
    quasi_id: bool = False,
    format_check: bool = False,
    plausibility: bool = False,
    consistency: bool = False,
    completeness: bool = False,
    auto_expectations: bool = False,
) -> dict[str, Any]:
    """Run AI-powered DQ checks (Azure OpenAI + Isolation Forest) on an uploaded file."""
    extension = Path(file.filename or "").suffix.lower().lstrip(".")
    if extension not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type.")

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        df = _load_dataframe_from_upload(file, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    source_name = file.filename or "uploaded_file"
    result: dict[str, Any] = {"source": source_name, "checks_run": [], "errors": {}}

    # Narrative requires a DQ report first
    dq_report: DQReport | None = None
    if narrative:
        try:
            dq_report = validate_input(df)
            result["narrative"] = generate_narrative(dq_report, file_name=source_name)
            result["checks_run"].append("narrative")
        except Exception as exc:
            result["errors"]["narrative"] = str(exc)

    if anomaly:
        try:
            anomaly_results = detect_anomalies(df)
            result["anomalies"] = [
                {
                    "column": a.column,
                    "anomalous_row_count": a.anomalous_row_count,
                    "total_rows": a.total_rows,
                    "anomaly_pct": a.anomaly_pct,
                    "explanation": a.explanation,
                    "sample_anomalous_values": a.sample_anomalous_values,
                }
                for a in anomaly_results if a.flagged
            ]
            result["checks_run"].append("anomaly")
        except Exception as exc:
            result["errors"]["anomaly"] = str(exc)

    if semantic_pii:
        try:
            risks = assess_semantic_pii_risk(df)
            result["semantic_pii_risks"] = [
                {"column": r.column, "risk": r.risk, "reason": r.reason} for r in risks
            ]
            result["checks_run"].append("semantic_pii")
        except Exception as exc:
            result["errors"]["semantic_pii"] = str(exc)

    if regulatory:
        try:
            flags = assess_regulatory_risk(df)
            result["regulatory_flags"] = [
                {
                    "column": f.column,
                    "regulation": f.regulation,
                    "category": f.category,
                    "obligation": f.obligation,
                    "severity": f.severity,
                }
                for f in flags
            ]
            result["checks_run"].append("regulatory")
        except Exception as exc:
            result["errors"]["regulatory"] = str(exc)

    if quasi_id:
        try:
            groups = detect_quasi_identifiers(df)
            result["quasi_identifiers"] = [
                {"columns": g.columns, "risk": g.risk, "reason": g.reason} for g in groups
            ]
            result["checks_run"].append("quasi_id")
        except Exception as exc:
            result["errors"]["quasi_id"] = str(exc)

    if format_check:
        try:
            anomalies = detect_format_anomalies(df)
            result["format_anomalies"] = [
                {
                    "column": a.column,
                    "expected_format": a.expected_format,
                    "observed_issue": a.observed_issue,
                    "severity": a.severity,
                }
                for a in anomalies
            ]
            result["checks_run"].append("format_check")
        except Exception as exc:
            result["errors"]["format_check"] = str(exc)

    if plausibility:
        try:
            issues = assess_value_plausibility(df)
            result["plausibility_issues"] = [
                {"column": i.column, "issue": i.issue, "example": i.example, "severity": i.severity}
                for i in issues
            ]
            result["checks_run"].append("plausibility")
        except Exception as exc:
            result["errors"]["plausibility"] = str(exc)

    if consistency:
        try:
            issues = detect_consistency_violations(df)
            result["consistency_issues"] = [
                {"columns": i.columns, "issue": i.issue, "severity": i.severity} for i in issues
            ]
            result["checks_run"].append("consistency")
        except Exception as exc:
            result["errors"]["consistency"] = str(exc)

    if completeness:
        try:
            issues = assess_completeness(df)
            result["completeness_issues"] = [
                {"column": i.column, "issue": i.issue, "severity": i.severity} for i in issues
            ]
            result["checks_run"].append("completeness")
        except Exception as exc:
            result["errors"]["completeness"] = str(exc)

    if auto_expectations:
        # run_auto_expectations catches its own exceptions internally
        auto_run = run_auto_expectations(df)
        result["auto_expectations"] = {
            "proposed_count": len(auto_run.specs),
            "executed_count": len(auto_run.outcomes),   # distinct from passed — means "run"
            "error": auto_run.error,
            "diagnostic": auto_run.diagnostic,
            "passed": auto_run.report.successful if auto_run.report else 0,
            "failed": auto_run.report.failed if auto_run.report else 0,
            "success_rate": auto_run.report.success_rate if auto_run.report else 0.0,
            "failures": (
                [
                    {"expectation": f.expectation, "column": f.column, "details": f.details}
                    for f in auto_run.report.failures
                ]
                if auto_run.report else []
            ),
            "specs": [
                {
                    "expectation_type": s.expectation_type,
                    "column": s.column,
                    "confidence": s.confidence,
                    "rationale": s.rationale,
                    "generation_source": s.generation_source,
                }
                for s in auto_run.specs
            ],
            "outcomes": auto_run.outcomes,
        }
        result["checks_run"].append("auto_expectations")

    return result


@app.post("/remediate/file", dependencies=[Depends(_require_api_key)])
async def remediate_file(
    file: UploadFile = File(...),
    mode: str = "redact",
    salt: str = "api-remediation-salt",
    include_review: bool = True,
) -> dict[str, Any]:
    """Scan a file for PII and return a remediated CSV plus a remediation summary."""
    extension = Path(file.filename or "").suffix.lower().lstrip(".")
    if extension not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Use avro, csv, json, parquet, txt, xlsx, or xls.",
        )
    if mode not in {"redact", "mask_last4", "hash"}:
        raise HTTPException(status_code=400, detail="mode must be redact, mask_last4, or hash")

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        df = _load_dataframe_from_upload(file, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    source_name = file.filename or "uploaded_file"
    findings, stats = scan_dataframe(df=df, source_name=source_name)
    findings_df = pd.DataFrame(findings) if findings else pd.DataFrame()

    remediated_df, records = remediate_dataframe(
        file_name=source_name,
        df=df,
        findings_df=findings_df,
        remediation_mode=mode,
        include_review_findings=include_review,
        hash_salt=salt,
        strict_person_fallback=True,
        strict_location_fallback=True,
        strict_common_fallback=True,
        strict_date_fallback=True,
        selected_patterns=None,
    )

    return {
        "source": source_name,
        "mode": mode,
        "scan_stats": stats,
        "pii_findings_count": len(findings),
        "remediation_summary": [
            {
                "column": r.column,
                "pattern": r.pattern,
                "detection_source": r.detection_source,
                "strategy": r.strategy,
                "cells_changed": r.cells_changed,
            }
            for r in records
        ],
        "total_cells_changed": sum(r.cells_changed for r in records),
        "remediated_csv": remediated_df.to_csv(index=False),
    }
