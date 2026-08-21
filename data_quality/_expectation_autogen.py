from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import great_expectations as gx
import pandas as pd

from ._llm import chat
from ._report import DQReport, build_report
from ._runner import run_expectations

_EXPECTATION_SYSTEM = (
    "You are a Great Expectations assistant for tabular data quality. "
    "Given a compact profile of a dataset, propose practical expectations as JSON only. "
    "Return a JSON array where each item has keys: "
    "expectation_type, column, kwargs, rationale, confidence. "
    "Allowed expectation_type values: "
    "expect_column_values_to_not_be_null, "
    "expect_column_values_to_be_unique, "
    "expect_column_values_to_be_between, "
    "expect_column_values_to_be_in_set, "
    "expect_column_values_to_match_regex, "
    "expect_column_value_lengths_to_be_between. "
    "Rules: "
    "1) Use only columns present in the profile. "
    "2) Keep kwargs small and valid for Great Expectations. "
    "3) Prefer robust ranges and mostly thresholds over brittle exact checks. "
    "4) For in_set, keep value_set <= 25 values. "
    "5) confidence must be HIGH, MEDIUM, or LOW. "
    "6) Return at most 25 expectations. "
    "Return only JSON with no markdown."
)

_ALLOWED_TYPES = {
    "expect_column_values_to_not_be_null",
    "expect_column_values_to_be_unique",
    "expect_column_values_to_be_between",
    "expect_column_values_to_be_in_set",
    "expect_column_values_to_match_regex",
    "expect_column_value_lengths_to_be_between",
}

_EXPECTATION_BUILDERS = {
    "expect_column_values_to_not_be_null": gx.expectations.ExpectColumnValuesToNotBeNull,
    "expect_column_values_to_be_unique": gx.expectations.ExpectColumnValuesToBeUnique,
    "expect_column_values_to_be_between": gx.expectations.ExpectColumnValuesToBeBetween,
    "expect_column_values_to_be_in_set": gx.expectations.ExpectColumnValuesToBeInSet,
    "expect_column_values_to_match_regex": gx.expectations.ExpectColumnValuesToMatchRegex,
    "expect_column_value_lengths_to_be_between": gx.expectations.ExpectColumnValueLengthsToBeBetween,
}


@dataclass
class AutoExpectationSpec:
    expectation_type: str
    column: str
    kwargs: dict[str, Any]
    rationale: str
    confidence: str


@dataclass
class AutoExpectationRun:
    specs: list[AutoExpectationSpec]
    report: DQReport | None
    error: str | None = None


def _to_json_clean(raw: str) -> list[dict[str, Any]]:
    text = raw.strip()
    text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _col_profile(series: pd.Series) -> dict[str, Any]:
    non_null = series.dropna()
    non_null_count = int(non_null.shape[0])

    profile: dict[str, Any] = {
        "dtype": str(series.dtype),
        "rows": int(series.shape[0]),
        "non_null": non_null_count,
        "null_pct": round(float(series.isna().mean() * 100), 2) if len(series) else 0.0,
        "distinct": int(non_null.nunique(dropna=True)) if non_null_count else 0,
        "distinct_pct": round(float(non_null.nunique(dropna=True) / non_null_count * 100), 2)
        if non_null_count
        else 0.0,
        "sample_values": non_null.astype(str).head(8).tolist(),
    }

    if non_null_count and pd.api.types.is_numeric_dtype(series):
        numeric = pd.to_numeric(non_null, errors="coerce").dropna()
        if not numeric.empty:
            profile.update(
                {
                    "numeric_min": float(numeric.min()),
                    "numeric_max": float(numeric.max()),
                    "p01": float(numeric.quantile(0.01)),
                    "p99": float(numeric.quantile(0.99)),
                }
            )

    if non_null_count and pd.api.types.is_object_dtype(series):
        as_text = non_null.astype(str)
        lengths = as_text.str.len()
        profile.update(
            {
                "len_min": int(lengths.min()),
                "len_max": int(lengths.max()),
                "len_p95": float(lengths.quantile(0.95)),
            }
        )
        top = as_text.value_counts(dropna=True).head(12)
        if not top.empty:
            profile["top_values"] = {str(k): int(v) for k, v in top.items()}

    return profile


def _dataset_profile(df: pd.DataFrame, max_columns: int = 40) -> dict[str, Any]:
    selected_columns = list(df.columns)[:max_columns]
    return {
        "row_count": int(df.shape[0]),
        "column_count": int(df.shape[1]),
        "columns": {
            str(col): _col_profile(df[col])
            for col in selected_columns
        },
    }


def _sanitize_spec(raw: dict[str, Any], allowed_columns: set[str]) -> AutoExpectationSpec | None:
    expectation_type = str(raw.get("expectation_type", "")).strip().lower()
    column = str(raw.get("column", "")).strip()
    kwargs = raw.get("kwargs", {})

    if expectation_type not in _ALLOWED_TYPES:
        return None
    if column not in allowed_columns:
        return None
    if not isinstance(kwargs, dict):
        return None

    cleaned_kwargs = dict(kwargs)
    cleaned_kwargs["column"] = column

    if expectation_type == "expect_column_values_to_not_be_null":
        mostly = cleaned_kwargs.get("mostly", 1.0)
        try:
            mostly_value = float(mostly)
        except (TypeError, ValueError):
            mostly_value = 1.0
        cleaned_kwargs["mostly"] = min(1.0, max(0.0, mostly_value))

    if expectation_type == "expect_column_values_to_be_in_set":
        value_set = cleaned_kwargs.get("value_set", [])
        if not isinstance(value_set, list):
            return None
        cleaned_kwargs["value_set"] = [str(v) for v in value_set[:25]]
        if not cleaned_kwargs["value_set"]:
            return None

    if expectation_type == "expect_column_values_to_match_regex":
        regex = cleaned_kwargs.get("regex", "")
        if not isinstance(regex, str) or not regex.strip():
            return None
        cleaned_kwargs["regex"] = regex

    if expectation_type in {
        "expect_column_values_to_be_between",
        "expect_column_value_lengths_to_be_between",
    }:
        min_value = cleaned_kwargs.get("min_value")
        max_value = cleaned_kwargs.get("max_value")
        if min_value is None and max_value is None:
            return None

    return AutoExpectationSpec(
        expectation_type=expectation_type,
        column=column,
        kwargs=cleaned_kwargs,
        rationale=str(raw.get("rationale", "")).strip(),
        confidence=str(raw.get("confidence", "MEDIUM")).strip().upper(),
    )


def propose_auto_expectation_specs(df: pd.DataFrame) -> list[AutoExpectationSpec]:
    if df.empty:
        return []

    profile = _dataset_profile(df)
    raw = chat(
        _EXPECTATION_SYSTEM,
        json.dumps(profile, ensure_ascii=False),
        max_tokens=1200,
    )
    parsed = _to_json_clean(raw)

    allowed_columns = {str(c) for c in df.columns}
    specs: list[AutoExpectationSpec] = []
    seen: set[tuple[str, str, str]] = set()

    for item in parsed:
        spec = _sanitize_spec(item, allowed_columns)
        if spec is None:
            continue
        dedupe_key = (
            spec.expectation_type,
            spec.column,
            json.dumps(spec.kwargs, sort_keys=True, default=str),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        specs.append(spec)
        if len(specs) >= 25:
            break

    return specs


def _build_gx_expectations(specs: list[AutoExpectationSpec]) -> list:
    expectations = []
    for spec in specs:
        builder = _EXPECTATION_BUILDERS.get(spec.expectation_type)
        if builder is None:
            continue
        try:
            expectations.append(builder(**spec.kwargs))
        except Exception:
            continue
    return expectations


def run_auto_expectations(df: pd.DataFrame, suite_name: str | None = None) -> AutoExpectationRun:
    try:
        specs = propose_auto_expectation_specs(df)
        gx_expectations = _build_gx_expectations(specs)
        if not gx_expectations:
            return AutoExpectationRun(specs=specs, report=None, error="No valid expectations were generated.")

        result = run_expectations(df, gx_expectations, suite_name=suite_name)
        report = build_report(result)
        return AutoExpectationRun(specs=specs, report=report)
    except Exception as exc:
        return AutoExpectationRun(specs=[], report=None, error=str(exc))
