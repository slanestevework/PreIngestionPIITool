"""Shared remediation helpers used by both app.py and api.py."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Hashable

import pandas as pd

from patterns import PII_REGEXES
from scanner import analyzer as presidio_analyzer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NAME_LIKE_COLUMN_HINTS = {"name", "customer_name", "employee_name", "user_name", "full_name"}

FULL_NAME_PATTERN = re.compile(
    r"^\s*[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?(?:\s+[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?){1,2}\s*$"
)
PERSON_CONTEXT_PATTERN = re.compile(
    r"\b([A-Z][a-z]+(?:[-'][A-Z][a-z]+)?\s+[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?)(?=\s+(?:called|met|requested|asked|reported|stated|emailed|contacted)\b)"
)
LOCATION_FULL_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)(?:,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:AL|GA|NC|TN)(?:\s+\d{5})?)?\b"
)
LOCATION_STREET_PATTERN = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)\b"
)
LOCATION_CITY_STATE_ZIP_PATTERN = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(AL|GA|NC|TN)\s+\d{5}\b"
)
LOCATION_CITY_STATE_PATTERN = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(AL|GA|NC|TN)\b"
)

REMEDIATION_PATTERN_PRIORITY: dict[str, int] = {
    "LOCATION": 10,
    "PERSON": 20,
    "EMAIL_ADDRESS": 30,
    "PHONE_NUMBER": 40,
    "email": 50,
    "phone": 60,
    "ssn": 70,
    "zip": 80,
    "DATE_TIME": 90,
    "URL": 100,
}

REMEDIATION_PATTERN_OPTIONS: list[str] = sorted(
    set(PII_REGEXES.keys())
    | {
        "PERSON",
        "LOCATION",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "DATE_TIME",
        "URL",
        "US_SSN",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "UK_NHS",
    }
)

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class RemediationRecord:
    file_name: str
    column: str
    pattern: str
    detection_source: str
    strategy: str
    cells_changed: int

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def coerce_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if pd.isna(value):
        return ""
    return str(value)


def is_name_like_column(column_name: str) -> bool:
    col_lower = column_name.lower()
    return any(hint in col_lower for hint in NAME_LIKE_COLUMN_HINTS)


def remediation_label(remediation_mode: str) -> str:
    labels = {"redact": "REDACT", "hash": "HASH", "mask_last4": "MASK_LAST4"}
    return labels.get(remediation_mode, "REDACT")


def transform_value(value: str, pattern: str, remediation_mode: str, salt: str) -> str:
    if remediation_mode == "hash":
        digest = hashlib.sha256(f"{salt}|{pattern}|{value}".encode("utf-8")).hexdigest()[:12]
        return f"<PII_HASH:{pattern}:{digest}>"
    if remediation_mode == "mask_last4":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4 and pattern in {
            "ssn", "credit_card", "bank_account", "routing_number", "phone",
        }:
            return f"<PII_MASK:{pattern}:***{digits[-4:]}>"
        return f"<PII_MASK:{pattern}>"
    return f"<PII_REDACT:{pattern}>"


def replace_by_regex(
    series: pd.Series, pattern_name: str, remediation_mode: str, salt: str
) -> tuple[pd.Series, int]:
    regex_pattern = PII_REGEXES.get(pattern_name)
    if regex_pattern is None:
        return series, 0
    updated_values = []
    changed = 0
    for value in series.fillna("").astype(str):
        stripped = value.strip()
        if regex_pattern.fullmatch(stripped):
            updated_values.append(transform_value(stripped, pattern_name, remediation_mode, salt))
            changed += 1
        else:
            updated_values.append(value)
    return pd.Series(updated_values, index=series.index), changed


def replace_by_samples(
    series: pd.Series,
    pattern_name: str,
    samples: list[str],
    remediation_mode: str,
    salt: str,
) -> tuple[pd.Series, int]:
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


def apply_person_context_fallback(
    value: str, column_name: str, remediation_mode: str, salt: str
) -> str:
    value = coerce_text(value)
    stripped = value.strip()
    if is_name_like_column(column_name) and FULL_NAME_PATTERN.fullmatch(stripped):
        return transform_value(stripped, "PERSON", remediation_mode, salt)

    def _replace(match: re.Match) -> str:
        return transform_value(match.group(1), "PERSON", remediation_mode, salt)

    return PERSON_CONTEXT_PATTERN.sub(_replace, value)


def apply_location_context_fallback(value: str, remediation_mode: str, salt: str) -> str:
    value = coerce_text(value)

    def _replace(match: re.Match) -> str:
        return transform_value(match.group(0), "LOCATION", remediation_mode, salt)

    updated = LOCATION_FULL_ADDRESS_PATTERN.sub(_replace, value)
    updated = LOCATION_STREET_PATTERN.sub(_replace, updated)
    updated = LOCATION_CITY_STATE_ZIP_PATTERN.sub(_replace, updated)
    updated = LOCATION_CITY_STATE_PATTERN.sub(_replace, updated)
    return updated


def replace_by_presidio_entity(
    series: pd.Series,
    column_name: str,
    entity_type: str,
    remediation_mode: str,
    salt: str,
    strict_person_fallback: bool,
    strict_location_fallback: bool,
) -> tuple[pd.Series, int]:
    updated_values = []
    changed = 0
    for original in series.astype(str):
        value = coerce_text(original)
        if entity_type == "PERSON" and strict_person_fallback:
            value = apply_person_context_fallback(value, column_name, remediation_mode, salt)
        if entity_type == "LOCATION" and strict_location_fallback:
            value = apply_location_context_fallback(value, remediation_mode, salt)
        entities = presidio_analyzer.analyze(text=value, language="en")
        target_entities = [e for e in entities if e.entity_type == entity_type]
        for entity in sorted(target_entities, key=lambda x: x.start, reverse=True):
            detected_text = value[entity.start:entity.end]
            replacement = transform_value(detected_text, entity_type, remediation_mode, salt)
            value = value[:entity.start] + replacement + value[entity.end:]
        if value != original:
            changed += 1
        updated_values.append(value)
    return pd.Series(updated_values, index=series.index), changed


def remediation_priority(finding: dict[Hashable, Any]) -> tuple[int, int, str]:
    detection_source = str(finding.get("detection_source", ""))
    pattern = str(finding.get("pattern", ""))
    source_priority = 0 if detection_source == "PRESIDIO_NLP" else 1
    pattern_priority = REMEDIATION_PATTERN_PRIORITY.get(pattern, 999)
    return source_priority, pattern_priority, pattern


def sub_with_transform(
    value: str,
    regex: re.Pattern,
    pattern_name: str,
    remediation_mode: str,
    salt: str,
) -> tuple[str, int]:
    def _replace(match: re.Match) -> str:
        return transform_value(match.group(0), pattern_name, remediation_mode, salt)

    return regex.subn(_replace, value)


def replace_contextual_digit_tokens(
    value: str,
    remediation_mode: str,
    salt: str,
    selected_patterns: set[str] | None,
) -> tuple[str, set[str]]:
    updated = value
    changed_types: set[str] = set()
    digit_pattern = re.compile(r"(?<!\d)\d{8,17}(?!\d)")
    for match in sorted(digit_pattern.finditer(updated), key=lambda m: m.start(), reverse=True):
        token = match.group(0)
        start, end = match.start(), match.end()
        context = updated[max(0, start - 28): min(len(updated), end + 28)].lower()
        replacement_label = ""
        if len(token) == 9 and ("routing" in context or "aba" in context):
            replacement_label = "routing_number"
        elif any(k in context for k in ["account", "acct", "bank", "iban"]):
            replacement_label = "bank_account"
        if replacement_label and (not selected_patterns or replacement_label in selected_patterns):
            replacement = transform_value(token, replacement_label, remediation_mode, salt)
            updated = updated[:start] + replacement + updated[end:]
            changed_types.add(replacement_label)
    return updated, changed_types


def apply_common_pii_fallback_value(
    value: str,
    remediation_mode: str,
    salt: str,
    enable_contextual_date_fallback: bool,
    selected_patterns: set[str] | None,
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
        if selected_patterns and pattern_name not in selected_patterns:
            continue
        updated, replacements = sub_with_transform(updated, regex, pattern_name, remediation_mode, salt)
        if replacements > 0:
            changed_types.add(pattern_name)
    updated, contextual_types = replace_contextual_digit_tokens(updated, remediation_mode, salt, selected_patterns)
    changed_types.update(contextual_types)
    if enable_contextual_date_fallback and (not selected_patterns or "dob" in selected_patterns):
        date_context = updated.lower()
        if any(k in date_context for k in ["dob", "birth", "born", "date of birth"]):
            date_regex = re.compile(r"(?<!\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-]\d{4}(?!\d)")
            updated, replacements = sub_with_transform(updated, date_regex, "dob", remediation_mode, salt)
            if replacements > 0:
                changed_types.add("dob")
    return updated, changed_types


def apply_common_pii_fallback_series(
    series: pd.Series,
    remediation_mode: str,
    salt: str,
    enable_contextual_date_fallback: bool,
    selected_patterns: set[str] | None,
) -> tuple[pd.Series, dict[str, int]]:
    updated_values = []
    type_change_counts: dict[str, int] = {}
    for original in series.astype(str):
        updated, changed_types = apply_common_pii_fallback_value(
            original, remediation_mode, salt, enable_contextual_date_fallback, selected_patterns
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
    selected_patterns: set[str] | None,
) -> tuple[pd.DataFrame, list[RemediationRecord]]:
    remediated = df.copy()
    records: list[RemediationRecord] = []
    touched_columns: set[str] = set()

    if findings_df.empty:
        return remediated, records

    ordered_findings = sorted(findings_df.to_dict("records"), key=remediation_priority)

    for finding in ordered_findings:
        raw_column = finding.get("column")
        raw_pattern = finding.get("pattern")
        risk = str(finding.get("risk", ""))
        detection_source = str(finding.get("detection_source", ""))

        if not isinstance(raw_column, str) or not raw_column:
            continue
        if not isinstance(raw_pattern, str) or not raw_pattern:
            continue

        column, pattern = raw_column, raw_pattern

        if column not in remediated.columns or not pattern:
            continue
        if selected_patterns and pattern not in selected_patterns:
            continue

        touched_columns.add(column)

        if not include_review_findings and risk == "REVIEW":
            continue

        if detection_source == "REGEX_RULE" and pattern in PII_REGEXES:
            updated_series, changed = replace_by_regex(remediated[column], pattern, remediation_mode, hash_salt)
        elif detection_source == "PRESIDIO_NLP":
            updated_series, changed = replace_by_presidio_entity(
                remediated[column], column, pattern, remediation_mode, hash_salt,
                strict_person_fallback, strict_location_fallback,
            )
        else:
            sample_matches = [
                s for s in [
                    finding.get(f"sample_match_{i}", "") for i in range(1, 6)
                ] if isinstance(s, str) and s
            ]
            updated_series, changed = replace_by_samples(
                remediated[column], pattern, sample_matches, remediation_mode, hash_salt
            )

        if changed > 0:
            remediated[column] = updated_series
            records.append(RemediationRecord(
                file_name=file_name, column=column, pattern=pattern,
                detection_source=detection_source,
                strategy=remediation_label(remediation_mode), cells_changed=changed,
            ))

    if strict_common_fallback:
        for column in sorted(touched_columns):
            updated_series, fallback_counts = apply_common_pii_fallback_series(
                remediated[column], remediation_mode, hash_salt,
                strict_date_fallback, selected_patterns,
            )
            if fallback_counts:
                remediated[column] = updated_series
                for pattern_name, cells_changed in fallback_counts.items():
                    records.append(RemediationRecord(
                        file_name=file_name, column=column, pattern=pattern_name,
                        detection_source="STRICT_FALLBACK",
                        strategy=remediation_label(remediation_mode), cells_changed=cells_changed,
                    ))

    return remediated, records
