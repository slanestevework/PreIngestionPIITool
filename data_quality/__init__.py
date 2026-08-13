"""
data_quality
============
Self-contained data quality module built on Great Expectations + Azure OpenAI.

Public API — rule-based (Great Expectations)
---------------------------------------------
validate_input(df)              – validate a raw DataFrame before PII scanning
validate_output(findings_df)    – validate the findings DataFrame after scanning
DQReport / DQFailure            – result dataclasses

Public API — AI-powered
------------------------
detect_anomalies(df)            – IsolationForest anomaly detection per column
generate_narrative(report, ...)  – Azure OpenAI plain-English DQ failure summary
assess_semantic_pii_risk(df)    – Azure OpenAI semantic PII column risk scoring
SemanticRisk / AnomalyResult    – result dataclasses

Azure OpenAI checks require env vars:
  AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY, AZURE_OPENAI_DEPLOYMENT (default: gpt-4o)

The module is intentionally isolated from the rest of the PII scanner so it
can be extracted to a standalone package without changes.
"""
from __future__ import annotations

try:
    import great_expectations  # noqa: F401  (verify the package is installed)
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "great-expectations is required for data quality validation. "
        "Install it with: pip install great-expectations"
    ) from exc

import pandas as pd

from ._report import DQFailure, DQReport, build_report
from ._runner import run_expectations
from ._suites import build_scan_input_suite, build_scan_output_suite
from ._anomaly import AnomalyResult, detect_anomalies
from ._narrative import generate_narrative
from ._semantic import SemanticRisk, assess_semantic_pii_risk
from ._regulatory import (
    RegulatoryFlag,
    QuasiIdentifierGroup,
    FormatAnomaly,
    assess_regulatory_risk,
    detect_quasi_identifiers,
    detect_format_anomalies,
)
from ._dq_intelligence import (
    PlausibilityIssue,
    ConsistencyIssue,
    CompletenessIssue,
    assess_value_plausibility,
    detect_consistency_violations,
    assess_completeness,
)

__all__ = [
    "validate_input",
    "validate_output",
    "DQReport",
    "DQFailure",
    "detect_anomalies",
    "AnomalyResult",
    "generate_narrative",
    "assess_semantic_pii_risk",
    "SemanticRisk",
    "assess_regulatory_risk",
    "RegulatoryFlag",
    "detect_quasi_identifiers",
    "QuasiIdentifierGroup",
    "detect_format_anomalies",
    "FormatAnomaly",
    "assess_value_plausibility",
    "PlausibilityIssue",
    "detect_consistency_violations",
    "ConsistencyIssue",
    "assess_completeness",
    "CompletenessIssue",
]


def validate_input(df: pd.DataFrame, suite_name: str = "scan_input") -> DQReport:
    """
    Validates a raw input DataFrame before PII scanning.

    Checks for an empty table and completely-null columns.
    Returns a :class:`DQReport` with the results.
    """
    expectations = build_scan_input_suite(df)
    result = run_expectations(df, expectations, suite_name=suite_name)
    return build_report(result)


def validate_output(findings_df: pd.DataFrame, suite_name: str = "scan_output") -> DQReport:
    """
    Validates the findings DataFrame produced by :func:`scanner.scan_dataframe`.

    Checks required columns, allowed confidence/risk values, and numeric ranges.
    Returns a :class:`DQReport` with the results.
    """
    expectations = build_scan_output_suite()
    result = run_expectations(findings_df, expectations, suite_name=suite_name)
    return build_report(result)
