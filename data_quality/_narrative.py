from __future__ import annotations

import json

from ._llm import chat
from ._report import DQReport

_SYSTEM = (
    "You are a data quality analyst. "
    "Given a structured summary of data quality check failures, "
    "write a concise plain-English explanation (3-6 sentences) of what is wrong "
    "and what the user should do to fix it. "
    "Be specific about column names and percentages when they are available. "
    "Do not use bullet points or headers — write a single coherent paragraph."
)


def generate_narrative(report: DQReport, file_name: str = "") -> str:
    """
    Calls Azure OpenAI to produce a plain-English summary of a DQReport's failures.
    Returns an empty string if the report passed or if no failures exist.
    """
    if report.passed or not report.failures:
        return ""

    failures_payload = [
        {
            "issue": f.expectation,
            "column": f.column or "(table-level)",
            **f.details,
        }
        for f in report.failures
    ]

    user_msg = (
        f"File: {file_name or 'unknown'}\n"
        f"Checks run: {report.evaluated}, passed: {report.successful}, failed: {report.failed}\n"
        f"Failures:\n{json.dumps(failures_payload, indent=2)}"
    )

    return chat(_SYSTEM, user_msg, max_tokens=256)
