from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import great_expectations as gx
import pandas as pd

from ._llm import chat
from ._report import DQReport, build_report
from ._runner import run_expectations


def _human_expectation_label(expectation_type: str) -> str:
    labels = {
        "expect_column_values_to_not_be_null": "Column has too many nulls",
        "expect_column_values_to_be_unique": "Column values must be unique",
        "expect_column_values_to_be_between": "Column values out of allowed range",
        "expect_column_values_to_be_in_set": "Column contains unexpected values",
        "expect_column_values_to_match_regex": "Column value format mismatch",
        "expect_column_value_lengths_to_be_between": "Column value length out of range",
    }
    key = expectation_type.lower().strip()
    return labels.get(key, key.removeprefix("expect_").replace("_", " ").title())


def _format_failure_details(expectation_type: str, raw: dict[str, Any]) -> dict[str, str]:
    key = expectation_type.lower()
    out: dict[str, str] = {}

    if "not_be_null" in key:
        out["why_failed"] = "Too many null or blank values were found."
        out["null_count"] = str(raw.get("unexpected_count", ""))
        pct = raw.get("unexpected_percent")
        if pct is not None:
            out["null_pct"] = f"{float(pct):.1f}%"
    elif "to_be_in_set" in key:
        out["why_failed"] = "Values outside the approved set were found."
        out["bad_values"] = str(raw.get("partial_unexpected_list", ""))
        out["bad_count"] = str(raw.get("unexpected_count", ""))
    elif "to_be_between" in key:
        out["why_failed"] = "Values outside the configured numeric range were found."
        out["observed"] = str(raw.get("observed_value", ""))
        out["bad_count"] = str(raw.get("unexpected_count", ""))
    elif "to_match_regex" in key:
        out["why_failed"] = "Values did not match the expected text format pattern."
        out["bad_values"] = str(raw.get("partial_unexpected_list", ""))
        out["bad_count"] = str(raw.get("unexpected_count", ""))
    elif "lengths_to_be_between" in key:
        out["why_failed"] = "Value lengths fell outside the expected range."
        out["bad_values"] = str(raw.get("partial_unexpected_list", ""))
        out["bad_count"] = str(raw.get("unexpected_count", ""))
    elif "to_be_unique" in key:
        out["why_failed"] = "Duplicate values were found where uniqueness was expected."
        out["duplicate_count"] = str(raw.get("unexpected_count", ""))
        out["sample_duplicates"] = str(raw.get("partial_unexpected_list", ""))
    else:
        out["why_failed"] = "Expectation did not pass validation."

    return {k: v for k, v in out.items() if v not in {"", "None"}}

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
    "Completeness checks must use mostly >= 0.95; do not copy the observed null rate. "
    "Expectations should express reasonable quality standards and may fail the profiled data. "
    "4) For in_set, keep value_set <= 25 values. "
    "5) confidence must be HIGH, MEDIUM, or LOW. "
    "6) Propose at least 2 distinct expectation types for every profiled column. "
    "7) Return at most 25 expectations. "
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

_IDENTIFIER_COLUMN_PATTERN = re.compile(r"\b(id|uuid|key|identifier|reference)\b", re.IGNORECASE)
_DATE_COLUMN_PATTERN = re.compile(r"\b(date|dated|restocked|timestamp|time)\b", re.IGNORECASE)
_NUMERIC_VALUE_PATTERN = r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$"
_DATE_VALUE_PATTERN = r"^(?:\d{4}-\d{2}-\d{2}|\d{2}[/-]\d{2}[/-]\d{4})$"
_TRIMMED_TEXT_PATTERN = r"^\S(?:.*\S)?$"


@dataclass
class AutoExpectationSpec:
    expectation_type: str
    column: str
    kwargs: dict[str, Any]
    rationale: str
    confidence: str
    generation_source: str = "LLM"


@dataclass
class AutoExpectationRun:
    specs: list[AutoExpectationSpec]
    outcomes: list[dict[str, Any]]
    report: DQReport | None
    error: str | None = None
    diagnostic: dict[str, Any] | None = None


def _to_json_clean(raw: str) -> list[dict[str, Any]]:
    text = raw.strip()
    # Strip any markdown code fence regardless of language label case
    import re as _re
    text = _re.sub(r"^```[a-zA-Z]*\s*", "", text)
    text = _re.sub(r"\s*```$", "", text).strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    # LLM sometimes wraps array in an object with a key
    if isinstance(parsed, dict):
        for key in ("expectations", "items", "results", "data", "checks"):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
        else:
            return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _col_profile(series: pd.Series, max_samples: int = 5, max_top: int = 8) -> dict[str, Any]:
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
        "sample_values": non_null.astype(str).head(max_samples).tolist(),
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

    if non_null_count and (
        pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series)
    ):
        as_text = non_null.astype(str)
        lengths = as_text.str.len()
        numeric_matches = as_text.str.fullmatch(_NUMERIC_VALUE_PATTERN)
        profile.update(
            {
                "len_min": int(lengths.min()),
                "len_max": int(lengths.max()),
                "len_p95": float(lengths.quantile(0.95)),
                "numeric_parse_pct": round(float(numeric_matches.mean() * 100), 2),
                "trimmed_pct": round(float((as_text == as_text.str.strip()).mean() * 100), 2),
            }
        )
        top = as_text.value_counts(dropna=True).head(max_top)
        if not top.empty:
            # Only include top_values when cardinality is low enough to be meaningful
            if non_null.nunique() <= 50:
                profile["top_values"] = {str(k): int(v) for k, v in top.items()}

    return profile


def _dataset_profile(df: pd.DataFrame, max_columns: int = 25, max_samples: int = 5, max_top: int = 8) -> dict[str, Any]:
    selected_columns = list(df.columns)[:max_columns]
    return {
        "row_count": int(df.shape[0]),
        "column_count": int(df.shape[1]),
        "columns": {
            str(col): _col_profile(df[col], max_samples=max_samples, max_top=max_top)
            for col in selected_columns
        },
    }


def _batch_profile(
    df: pd.DataFrame,
    columns: list,
    max_samples: int = 5,
    max_top: int = 8,
) -> dict[str, Any]:
    """Profile for a column subset — tells the LLM the full dataset size for context."""
    return {
        "row_count": int(df.shape[0]),
        "total_columns": int(df.shape[1]),
        "batch_columns": len(columns),
        "columns": {
            str(col): _col_profile(df[col], max_samples=max_samples, max_top=max_top)
            for col in columns
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
        cleaned_kwargs["mostly"] = min(1.0, max(0.95, mostly_value))

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


def _ensure_minimum_column_coverage(
    df: pd.DataFrame,
    specs: list[AutoExpectationSpec],
    minimum_per_column: int = 2,
) -> list[AutoExpectationSpec]:
    supplemented = list(specs)

    for column in df.columns:
        column_name = str(column)
        series = df[column]
        non_null = series.dropna()
        existing_types = {
            spec.expectation_type for spec in supplemented if spec.column == column_name
        }
        candidates: list[AutoExpectationSpec] = [
            AutoExpectationSpec(
                expectation_type="expect_column_values_to_not_be_null",
                column=column_name,
                kwargs={
                    "column": column_name,
                    "mostly": 0.95,
                },
                rationale="Baseline policy requires at least 95% populated values.",
                confidence="MEDIUM",
                generation_source="PROFILE_FALLBACK",
            )
        ]

        if _IDENTIFIER_COLUMN_PATTERN.search(column_name):
            candidates.append(
                AutoExpectationSpec(
                    expectation_type="expect_column_values_to_be_unique",
                    column=column_name,
                    kwargs={"column": column_name},
                    rationale="Identifier columns should uniquely identify records.",
                    confidence="HIGH",
                    generation_source="PROFILE_FALLBACK",
                )
            )
        elif _DATE_COLUMN_PATTERN.search(column_name):
            candidates.append(
                AutoExpectationSpec(
                    expectation_type="expect_column_values_to_match_regex",
                    column=column_name,
                    kwargs={"column": column_name, "regex": _DATE_VALUE_PATTERN},
                    rationale="Date-like columns should use a recognizable, consistent date format.",
                    confidence="HIGH",
                    generation_source="PROFILE_FALLBACK",
                )
            )
        else:
            text_values = non_null.astype(str)
            numeric_ratio = (
                float(text_values.str.fullmatch(_NUMERIC_VALUE_PATTERN).mean())
                if not text_values.empty else 0.0
            )
            pattern = _NUMERIC_VALUE_PATTERN if numeric_ratio >= 0.5 else _TRIMMED_TEXT_PATTERN
            rationale = (
                "Numeric-like columns should not contain words or malformed numbers."
                if numeric_ratio >= 0.5
                else "Text values should not contain leading or trailing whitespace."
            )
            candidates.append(
                AutoExpectationSpec(
                    expectation_type="expect_column_values_to_match_regex",
                    column=column_name,
                    kwargs={"column": column_name, "regex": pattern},
                    rationale=rationale,
                    confidence="MEDIUM",
                    generation_source="PROFILE_FALLBACK",
                )
            )

        for candidate in candidates[:minimum_per_column]:
            if candidate.expectation_type in existing_types:
                continue
            supplemented.append(candidate)
            existing_types.add(candidate.expectation_type)

    return supplemented


def _build_outcomes(specs: list[AutoExpectationSpec], validation_result) -> list[dict[str, Any]]:
    outcomes: list[dict[str, Any]] = []
    raw_results = list(getattr(validation_result, "results", []) or [])
    unmatched_specs = list(specs)

    for result in raw_results:
        config = result.expectation_config
        expectation_type = str(getattr(config, "type", "")).lower()
        config_kwargs = dict(getattr(config, "kwargs", {}) or {})
        config_kwargs.pop("batch_id", None)
        column = str(config_kwargs.get("column", ""))

        matching_index = next(
            (
                index for index, candidate in enumerate(unmatched_specs)
                if candidate.expectation_type == expectation_type
                and candidate.column == column
                and candidate.kwargs == config_kwargs
            ),
            None,
        )
        if matching_index is None:
            matching_index = next(
                (
                    index for index, candidate in enumerate(unmatched_specs)
                    if candidate.expectation_type == expectation_type
                    and candidate.column == column
                ),
                None,
            )
        if matching_index is None:
            continue

        spec = unmatched_specs.pop(matching_index)
        passed = bool(result.success)
        failure_details: dict[str, str] = {}
        if not passed:
            failure_details = _format_failure_details(
                spec.expectation_type,
                result.result or {},
            )

        outcomes.append(
            {
                "index": len(outcomes) + 1,
                "expectation": spec.expectation_type,
                "expectation_label": _human_expectation_label(spec.expectation_type),
                "column": spec.column,
                "params": spec.kwargs,
                "confidence": spec.confidence,
                "rationale": spec.rationale,
                "generation_source": spec.generation_source,
                "passed": passed,
                "status": "PASS" if passed else "FAIL",
                "status_icon": "✅" if passed else "❌",
                "failure_details": failure_details,
            }
        )

    return outcomes


def run_auto_expectations(df: pd.DataFrame, suite_name: str | None = None) -> AutoExpectationRun:
    try:
        total_chars, finish_reasons, llm_parsed, specs = _propose_with_diagnostics(df)
        llm_spec_count = len(specs)
        specs = _ensure_minimum_column_coverage(df, specs)
        allowed_columns = {str(c) for c in df.columns}
        n_batches = max(1, -(-len(df.columns) // _BATCH_SIZE))  # ceil division

        rejected_type = sum(
            1 for item in llm_parsed
            if str(item.get("expectation_type", "")).strip().lower() not in _ALLOWED_TYPES
        )
        rejected_col = sum(
            1 for item in llm_parsed
            if str(item.get("expectation_type", "")).strip().lower() in _ALLOWED_TYPES
            and str(item.get("column", "")).strip() not in allowed_columns
        )

        diag: dict[str, Any] = {
            "batches": n_batches,
            "llm_response_chars": total_chars,
            "llm_finish_reasons": finish_reasons,
            "llm_items_parsed": len(llm_parsed),
            "specs_accepted": len(specs),
            "llm_specs_accepted": llm_spec_count,
            "profile_fallback_specs": len(specs) - llm_spec_count,
            "rejected_unknown_type": rejected_type,
            "rejected_bad_column": rejected_col,
        }
        any_truncated = "length" in finish_reasons
        any_empty = total_chars == 0
        if not llm_parsed:
            diag["hint"] = (
                ("One or more batches were truncated — response was empty." if any_truncated
                 else "LLM returned no parseable JSON items.")
                + (" Possible content filter or token limit." if any_empty else "")
            )
        elif not specs:
            diag["hint"] = (
                f"LLM returned {len(llm_parsed)} item(s) across {n_batches} batch(es) "
                f"but all were rejected. Bad type: {rejected_type}, "
                f"unrecognised column: {rejected_col}."
            )

        gx_expectations = _build_gx_expectations(specs)
        if not gx_expectations:
            reason = "No valid expectations were generated for this file."
            if specs:
                reason = (
                    f"{len(specs)} spec(s) were proposed but none could be converted "
                    "to Great Expectations objects — kwargs may be invalid."
                )
            return AutoExpectationRun(
                specs=specs, outcomes=[], report=None, error=reason, diagnostic=diag
            )

        result = run_expectations(df, gx_expectations, suite_name=suite_name)
        report = build_report(result)
        outcomes = _build_outcomes(specs, result)
        return AutoExpectationRun(specs=specs, outcomes=outcomes, report=report, diagnostic=diag)
    except Exception as exc:
        return AutoExpectationRun(
            specs=[], outcomes=[], report=None, error=str(exc),
            diagnostic={"hint": "Exception raised before diagnostics were collected."},
        )


_BATCH_SIZE = 8  # columns per LLM call


def _propose_with_diagnostics(
    df: pd.DataFrame,
) -> tuple[int, list[str], list[dict[str, Any]], list[AutoExpectationSpec]]:
    """Batches columns, makes one LLM call per batch, merges specs.

    Returns (total_chars, finish_reasons, all_parsed_items, accepted_specs).
    """
    if df.empty:
        return 0, [], [], []

    all_columns = list(df.columns)
    batches = [all_columns[i:i + _BATCH_SIZE] for i in range(0, len(all_columns), _BATCH_SIZE)]
    allowed_columns = {str(c) for c in all_columns}

    total_chars = 0
    finish_reasons: list[str] = []
    all_parsed: list[dict[str, Any]] = []
    specs: list[AutoExpectationSpec] = []
    seen: set[tuple[str, str, str]] = set()

    for batch_cols in batches:
        profile_json = json.dumps(_batch_profile(df, batch_cols), ensure_ascii=False)
        raw, finish_reason = chat(_EXPECTATION_SYSTEM, profile_json, max_tokens=1200)

        # Retry this batch with fewer samples if truncated or empty
        if not raw.strip() or finish_reason == "length":
            profile_json = json.dumps(_batch_profile(df, batch_cols, max_samples=3, max_top=5), ensure_ascii=False)
            raw, finish_reason = chat(_EXPECTATION_SYSTEM, profile_json, max_tokens=1200)

        total_chars += len(raw)
        finish_reasons.append(finish_reason)
        parsed = _to_json_clean(raw)
        all_parsed.extend(parsed)

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

    return total_chars, finish_reasons, all_parsed, specs
