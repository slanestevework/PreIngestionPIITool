from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from scanner import scan_dataframe
from data_quality import DQReport, validate_input


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

SUPPORTED_EXTENSIONS = {"csv", "json", "parquet", "txt", "xlsx", "xls"}


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


def _load_dataframe_from_upload(upload_file: UploadFile, payload: bytes) -> pd.DataFrame:
    extension = Path(upload_file.filename or "").suffix.lower().lstrip(".")

    if extension == "csv":
        return pd.read_csv(BytesIO(payload), dtype=str)
    if extension == "json":
        return pd.read_json(BytesIO(payload), lines=True)
    if extension == "parquet":
        return pd.read_parquet(BytesIO(payload))
    if extension == "txt":
        text_content = payload.decode("utf-8", errors="ignore")
        return pd.DataFrame({"value": text_content.splitlines()})
    if extension in {"xlsx", "xls"}:
        return pd.read_excel(BytesIO(payload), dtype=str)

    raise HTTPException(
        status_code=400,
        detail="Unsupported file type. Use csv, json, parquet, txt, xlsx, or xls.",
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
            detail="Unsupported file type. Use csv, json, parquet, txt, xlsx, or xls.",
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
            detail="Unsupported file type. Use csv, json, parquet, txt, xlsx, or xls.",
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
