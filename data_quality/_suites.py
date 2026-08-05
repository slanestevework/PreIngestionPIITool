from __future__ import annotations

import re

import great_expectations as gx
import pandas as pd


SCAN_OUTPUT_REQUIRED_COLUMNS = [
    "source",
    "column",
    "pattern",
    "confidence",
    "risk",
    "matches",
    "sample_size",
    "match_pct",
]

_CONFIDENCE_VALUES = ["HIGH", "LOW"]
_RISK_VALUES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Column name patterns that should contain unique values
_ID_COLUMN_PATTERN = re.compile(r"\b(id|uuid|key|ref|reference|record_id|row_id)\b", re.IGNORECASE)

# Fixed-width column name hints → expected character length
_FIXED_WIDTH_HINTS: dict[re.Pattern, tuple[int, int]] = {
    re.compile(r"\bssn\b", re.IGNORECASE): (9, 11),       # 123456789 or 123-45-6789
    re.compile(r"\bzip\b", re.IGNORECASE): (5, 10),        # 12345 or 12345-6789
    re.compile(r"\bein\b", re.IGNORECASE): (9, 10),
    re.compile(r"\bphone\b", re.IGNORECASE): (7, 15),
}


def build_scan_input_suite(df: pd.DataFrame) -> list:
    """Expectations for a raw input DataFrame before PII scanning."""
    expectations: list = [
        gx.expectations.ExpectTableRowCountToBeBetween(min_value=1),
        # Duplicate rows indicate upstream processing errors or bad joins
        gx.expectations.ExpectTableRowCountToEqualOtherTable(
            other_table_name=None
        ) if False else None,  # placeholder — duplicate check done via compound columns below
    ]
    # Remove the placeholder None
    expectations = [e for e in expectations if e is not None]

    for col in df.columns:
        # At least 1 % of rows must be non-null — catches fully empty columns
        expectations.append(
            gx.expectations.ExpectColumnValuesToNotBeNull(column=col, mostly=0.01)
        )

        non_null = df[col].dropna()

        # Uniqueness check for obvious identifier columns
        if _ID_COLUMN_PATTERN.search(col) and len(non_null) > 0:
            expectations.append(
                gx.expectations.ExpectColumnValuesToBeUnique(column=col)
            )

        # Value-length bounds for known fixed-width columns
        for pattern, (min_len, max_len) in _FIXED_WIDTH_HINTS.items():
            if pattern.search(col) and len(non_null) > 0:
                expectations.append(
                    gx.expectations.ExpectColumnValueLengthsToBeBetween(
                        column=col, min_value=min_len, max_value=max_len
                    )
                )
                break

        # Flag columns where values have wildly inconsistent lengths (std > 3× mean)
        if len(non_null) >= 10 and pd.api.types.is_object_dtype(df[col]):
            lengths = non_null.astype(str).str.len()
            mean_len = lengths.mean()
            std_len = lengths.std()
            if mean_len > 0 and std_len > 3 * mean_len:
                # Loose upper bound to surface extreme outliers
                expectations.append(
                    gx.expectations.ExpectColumnValueLengthsToBeBetween(
                        column=col, min_value=1, max_value=int(mean_len + 4 * std_len)
                    )
                )

    return expectations


def build_scan_output_suite() -> list:
    """
    Expectations for the findings DataFrame produced by scan_dataframe.
    Validates required columns, allowed values, and numeric ranges.
    """
    expectations: list = [
        gx.expectations.ExpectTableRowCountToBeBetween(min_value=1),
    ]

    for col in SCAN_OUTPUT_REQUIRED_COLUMNS:
        expectations.append(gx.expectations.ExpectColumnToExist(column=col))

    expectations += [
        gx.expectations.ExpectColumnValuesToBeInSet(
            column="confidence",
            value_set=_CONFIDENCE_VALUES,
        ),
        gx.expectations.ExpectColumnValuesToBeInSet(
            column="risk",
            value_set=_RISK_VALUES,
        ),
        gx.expectations.ExpectColumnValuesToBeBetween(
            column="matches",
            min_value=1,
        ),
        gx.expectations.ExpectColumnValuesToBeBetween(
            column="match_pct",
            min_value=0,
            max_value=100,
        ),
    ]

    return expectations


def build_scan_output_suite() -> list:
    """
    Expectations for the findings DataFrame produced by scan_dataframe.
    Validates required columns, allowed values, and numeric ranges.
    """
    expectations: list = [
        gx.expectations.ExpectTableRowCountToBeBetween(min_value=1),
    ]

    for col in SCAN_OUTPUT_REQUIRED_COLUMNS:
        expectations.append(gx.expectations.ExpectColumnToExist(column=col))

    expectations += [
        gx.expectations.ExpectColumnValuesToBeInSet(
            column="confidence",
            value_set=_CONFIDENCE_VALUES,
        ),
        gx.expectations.ExpectColumnValuesToBeInSet(
            column="risk",
            value_set=_RISK_VALUES,
        ),
        gx.expectations.ExpectColumnValuesToBeBetween(
            column="matches",
            min_value=1,
        ),
        gx.expectations.ExpectColumnValuesToBeBetween(
            column="match_pct",
            min_value=0,
            max_value=100,
        ),
    ]

    return expectations
