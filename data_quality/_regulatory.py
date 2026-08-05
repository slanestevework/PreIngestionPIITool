from __future__ import annotations

import json
from dataclasses import dataclass, field

import pandas as pd

from ._llm import chat

_REGULATORY_SYSTEM = (
    "You are a data privacy and compliance expert specialising in HIPAA, GDPR, and CCPA. "
    "Given a list of column names and sample values from a dataset, identify columns or "
    "combinations of columns that may trigger obligations under these regulations. "
    "Return a JSON array of objects with keys: "
    "\"column\" (column name or comma-separated list for combinations), "
    "\"regulation\" (HIPAA | GDPR | CCPA | MULTIPLE), "
    "\"category\" (e.g. PHI, PII, Sensitive Personal Data), "
    "\"obligation\" (one sentence on the specific obligation triggered), "
    "\"severity\" (HIGH | MEDIUM | LOW). "
    "Return only the JSON array, no prose."
)

_QUASI_SYSTEM = (
    "You are a data privacy expert specialising in re-identification risk. "
    "Given a list of column names and sample values, identify groups of columns that "
    "together form quasi-identifiers — combinations that could allow re-identification "
    "of individuals even though no single column is uniquely identifying on its own. "
    "Return a JSON array of objects with keys: "
    "\"columns\" (array of column names in the group), "
    "\"risk\" (HIGH | MEDIUM | LOW), "
    "\"reason\" (one sentence explaining the re-identification risk). "
    "Return only the JSON array, no prose."
)

_FORMAT_SYSTEM = (
    "You are a data quality analyst. "
    "Given column names and sample values, identify columns where the values do not match "
    "the format implied by the column name (e.g. a 'phone' column containing text strings, "
    "an 'email' column with no @ signs, a 'zip' column with values that are not 5-digit codes). "
    "Return a JSON array of objects with keys: "
    "\"column\", \"expected_format\" (brief description), "
    "\"observed_issue\" (what you actually saw), \"severity\" (HIGH | MEDIUM | LOW). "
    "Only include columns with genuine mismatches. Return only the JSON array, no prose."
)

_MAX_SAMPLE_ROWS = 5
_MAX_COLUMNS = 30


@dataclass
class RegulatoryFlag:
    column: str
    regulation: str
    category: str
    obligation: str
    severity: str


@dataclass
class QuasiIdentifierGroup:
    columns: list[str]
    risk: str
    reason: str


@dataclass
class FormatAnomaly:
    column: str
    expected_format: str
    observed_issue: str
    severity: str


def _sample_payload(df: pd.DataFrame, skip: set[str] | None = None) -> dict:
    skip = skip or set()
    cols = [c for c in df.columns if c not in skip][:_MAX_COLUMNS]
    return {
        col: df[col].dropna().astype(str).head(_MAX_SAMPLE_ROWS).tolist()
        for col in cols
    }


def _parse_json(raw: str) -> list:
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        result = json.loads(cleaned)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def assess_regulatory_risk(df: pd.DataFrame) -> list[RegulatoryFlag]:
    """Flags columns that may trigger HIPAA, GDPR, or CCPA obligations."""
    if df.empty:
        return []
    payload = json.dumps(_sample_payload(df), ensure_ascii=False)
    items = _parse_json(chat(_REGULATORY_SYSTEM, payload, max_tokens=768))
    return [
        RegulatoryFlag(
            column=str(item.get("column", "")),
            regulation=str(item.get("regulation", "")),
            category=str(item.get("category", "")),
            obligation=str(item.get("obligation", "")),
            severity=str(item.get("severity", "MEDIUM")).upper(),
        )
        for item in items
        if item.get("column")
    ]


def detect_quasi_identifiers(df: pd.DataFrame) -> list[QuasiIdentifierGroup]:
    """Identifies column combinations that together could re-identify individuals."""
    if df.empty or len(df.columns) < 2:
        return []
    payload = json.dumps(_sample_payload(df), ensure_ascii=False)
    items = _parse_json(chat(_QUASI_SYSTEM, payload, max_tokens=512))
    return [
        QuasiIdentifierGroup(
            columns=item.get("columns", []),
            risk=str(item.get("risk", "MEDIUM")).upper(),
            reason=str(item.get("reason", "")),
        )
        for item in items
        if item.get("columns")
    ]


def detect_format_anomalies(df: pd.DataFrame) -> list[FormatAnomaly]:
    """Flags columns where values don't match the format implied by the column name."""
    if df.empty:
        return []
    payload = json.dumps(_sample_payload(df), ensure_ascii=False)
    items = _parse_json(chat(_FORMAT_SYSTEM, payload, max_tokens=512))
    return [
        FormatAnomaly(
            column=str(item.get("column", "")),
            expected_format=str(item.get("expected_format", "")),
            observed_issue=str(item.get("observed_issue", "")),
            severity=str(item.get("severity", "MEDIUM")).upper(),
        )
        for item in items
        if item.get("column") and item.get("column") in df.columns
    ]
