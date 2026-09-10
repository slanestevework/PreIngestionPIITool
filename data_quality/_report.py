from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DQFailure:
    expectation: str
    column: str | None
    details: dict


@dataclass
class DQReport:
    passed: bool
    evaluated: int
    successful: int
    failed: int
    failures: list[DQFailure] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.evaluated == 0:
            return 1.0
        return round(self.successful / self.evaluated, 4)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "evaluated": self.evaluated,
            "successful": self.successful,
            "failed": self.failed,
            "success_rate": self.success_rate,
            "failures": [
                {
                    "expectation": f.expectation,
                    "column": f.column,
                    "details": f.details,
                }
                for f in self.failures
            ],
        }


_HUMAN_LABELS: dict[str, str] = {
    "expect_table_row_count_to_be_between": "Row count out of range",
    "expect_column_to_exist": "Missing required column",
    "expect_column_values_to_not_be_null": "Column has too many nulls",
    "expect_column_values_to_be_in_set": "Column contains unexpected values",
    "expect_column_values_to_be_between": "Column values out of allowed range",
    "expect_column_values_to_be_unique": "Column values must be unique",
    "expect_column_values_to_match_regex": "Column value format mismatch",
    "expect_column_value_lengths_to_be_between": "Column value length out of range",
}


def _label(exp_type_raw: str) -> str:
    """Convert a GX snake_case expectation type to a readable label."""
    key = exp_type_raw.lower()
    if key in _HUMAN_LABELS:
        return _HUMAN_LABELS[key]
    # Fallback: strip "expect_" prefix and title-case remaining words
    return key.removeprefix("expect_").replace("_", " ").title()


def build_report(validation_result) -> DQReport:
    """Converts a GX ValidationResult into a DQReport."""
    stats = validation_result.statistics or {}
    failures: list[DQFailure] = []

    for result in validation_result.results:
        if not result.success:
            cfg = result.expectation_config
            # GX 1.x stores the type as a snake_case string on .type
            raw_type = getattr(cfg, "type", None) or type(cfg).__name__
            column = (
                getattr(cfg, "column", None)
                or (cfg.kwargs.get("column") if hasattr(cfg, "kwargs") else None)
            )
            raw = result.result or {}
            details = _build_details(raw_type, column, raw)
            failures.append(DQFailure(expectation=_label(raw_type), column=column, details=details))

    return DQReport(
        passed=bool(validation_result.success),
        evaluated=int(stats.get("evaluated_expectations", 0)),
        successful=int(stats.get("successful_expectations", 0)),
        failed=int(stats.get("unsuccessful_expectations", 0)),
        failures=failures,
    )


def _build_details(raw_type: str, column: str | None, raw: dict) -> dict:
    """Extract the most human-useful keys from a GX result dict."""
    key = raw_type.lower()
    out: dict = {}

    if "row_count" in key:
        if "observed_value" in raw:
            out["rows_found"] = str(raw["observed_value"])
    elif "not_be_null" in key:
        out["null_count"] = str(raw.get("unexpected_count", ""))
        pct = raw.get("unexpected_percent")
        if pct is not None:
            out["null_pct"] = f"{float(pct):.1f}%"
    elif "to_exist" in key:
        pass  # column name is already in the DQFailure.column field
    elif "to_be_in_set" in key:
        out["bad_values"] = str(raw.get("partial_unexpected_list", ""))
    elif "to_be_between" in key:
        out["observed"] = str(raw.get("observed_value", ""))

    return out
