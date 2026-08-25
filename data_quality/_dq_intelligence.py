from __future__ import annotations

import json
from dataclasses import dataclass

import pandas as pd

from ._llm import chat

_PLAUSIBILITY_SYSTEM = (
    "You are a data quality analyst. "
    "Given column names and sample values from a dataset, identify values that are "
    "implausible or suspicious for their column — for example: an age of 999, a negative "
    "salary, a date set 50 years in the future, a zip code with letters, a status column "
    "with a mix of Y/N and True/False and 1/0, or a percentage above 100. "
    "Return a JSON array of objects with keys: "
    "\"column\", \"issue\" (one sentence describing the implausible value or pattern), "
    "\"example\" (the specific value or values that look wrong), "
    "\"severity\" (HIGH | MEDIUM | LOW). "
    "Only flag genuine problems. Return only the JSON array, no prose."
)

_CONSISTENCY_SYSTEM = (
    "You are a data quality analyst. "
    "Given column names and sample values from a dataset, identify cross-column "
    "inconsistencies — for example: a zip code that doesn't match the state, an end_date "
    "before the start_date, a city/state combination that doesn't exist, a gender field "
    "inconsistent with a title field, or a total that doesn't match its component columns. "
    "Return a JSON array of objects with keys: "
    "\"columns\" (comma-separated column names involved), "
    "\"issue\" (one sentence describing the inconsistency), "
    "\"severity\" (HIGH | MEDIUM | LOW). "
    "Only flag genuine cross-column problems. Return only the JSON array, no prose."
)

_COMPLETENESS_SYSTEM = (
    "You are a data quality analyst. "
    "Given column names and sample values from a dataset, assess whether the dataset "
    "appears complete for its evident purpose. Look for: columns that seem like they "
    "should always have a value but are often blank, columns that appear to be "
    "intentionally left as placeholders, or important companion columns that appear to "
    "be missing entirely (e.g. an address without a zip, a name without an ID). "
    "Return a JSON array of objects with keys: "
    "\"column\" (affected column or 'dataset-level' for missing columns), "
    "\"issue\" (one sentence), "
    "\"severity\" (HIGH | MEDIUM | LOW). "
    "Only flag meaningful completeness gaps. Return only the JSON array, no prose."
)

_MAX_SAMPLE_ROWS = 8
_MAX_COLUMNS = 30


@dataclass
class PlausibilityIssue:
    column: str
    issue: str
    example: str
    severity: str


@dataclass
class ConsistencyIssue:
    columns: str
    issue: str
    severity: str


@dataclass
class CompletenessIssue:
    column: str
    issue: str
    severity: str


def _sample_payload(df: pd.DataFrame) -> dict:
    cols = list(df.columns)[:_MAX_COLUMNS]
    return {
        col: df[col].dropna().astype(str).head(_MAX_SAMPLE_ROWS).tolist()
        for col in cols
    }


def _parse(raw: str) -> list:
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        result = json.loads(cleaned)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def assess_value_plausibility(df: pd.DataFrame) -> list[PlausibilityIssue]:
    """LLM checks whether individual values are plausible for their column."""
    if df.empty:
        return []
    raw, _ = chat(_PLAUSIBILITY_SYSTEM, json.dumps(_sample_payload(df), ensure_ascii=False), max_tokens=512)
    return [
        PlausibilityIssue(
            column=str(item.get("column", "")),
            issue=str(item.get("issue", "")),
            example=str(item.get("example", "")),
            severity=str(item.get("severity", "MEDIUM")).upper(),
        )
        for item in _parse(raw)
        if item.get("column") and item.get("issue")
    ]


def detect_consistency_violations(df: pd.DataFrame) -> list[ConsistencyIssue]:
    """LLM checks for cross-column inconsistencies (date order, zip/state, totals, etc.)."""
    if df.empty or len(df.columns) < 2:
        return []
    raw, _ = chat(_CONSISTENCY_SYSTEM, json.dumps(_sample_payload(df), ensure_ascii=False), max_tokens=512)
    return [
        ConsistencyIssue(
            columns=str(item.get("columns", "")),
            issue=str(item.get("issue", "")),
            severity=str(item.get("severity", "MEDIUM")).upper(),
        )
        for item in _parse(raw)
        if item.get("columns") and item.get("issue")
    ]


def assess_completeness(df: pd.DataFrame) -> list[CompletenessIssue]:
    """LLM identifies columns that look incomplete or companion columns that appear missing."""
    if df.empty:
        return []
    raw, _ = chat(_COMPLETENESS_SYSTEM, json.dumps(_sample_payload(df), ensure_ascii=False), max_tokens=512)
    return [
        CompletenessIssue(
            column=str(item.get("column", "")),
            issue=str(item.get("issue", "")),
            severity=str(item.get("severity", "MEDIUM")).upper(),
        )
        for item in _parse(raw)
        if item.get("column") and item.get("issue")
    ]
