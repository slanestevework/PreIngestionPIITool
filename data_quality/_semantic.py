from __future__ import annotations

import json
from dataclasses import dataclass

import pandas as pd

from ._llm import chat

_SYSTEM = (
    "You are a data privacy expert. "
    "Given a list of column names and sample values from a dataset, "
    "identify any columns that likely contain Personally Identifiable Information (PII) "
    "that a regex-based scanner may have missed. "
    "For each suspicious column return a JSON array of objects with keys: "
    "\"column\", \"risk\" (HIGH/MEDIUM/LOW), \"reason\" (one sentence). "
    "Return only the JSON array, no prose."
)

_MAX_SAMPLE_ROWS = 5
_MAX_COLUMNS = 30


@dataclass
class SemanticRisk:
    column: str
    risk: str
    reason: str


def assess_semantic_pii_risk(
    df: pd.DataFrame,
    known_pii_columns: set[str] | None = None,
) -> list[SemanticRisk]:
    """
    Asks Azure OpenAI to review column names and sample values for undetected PII.

    Skips columns already flagged by the regex/NLP scanner (pass them in
    *known_pii_columns* to avoid duplicate warnings).
    Returns a list of :class:`SemanticRisk` for columns the LLM considers risky.
    """
    if df.empty:
        return []

    skip = known_pii_columns or set()
    cols = [c for c in df.columns if c not in skip][:_MAX_COLUMNS]

    if not cols:
        return []

    # Build a compact column→samples map
    samples: dict[str, list[str]] = {}
    for col in cols:
        non_null = df[col].dropna().astype(str)
        samples[col] = non_null.head(_MAX_SAMPLE_ROWS).tolist()

    user_msg = json.dumps(samples, ensure_ascii=False)

    raw, _ = chat(_SYSTEM, user_msg, max_tokens=512)

    # Strip markdown fences if the model wraps the JSON
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        items = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return []

    results: list[SemanticRisk] = []
    for item in items:
        col = str(item.get("column", "")).strip()
        risk = str(item.get("risk", "MEDIUM")).strip().upper()
        reason = str(item.get("reason", "")).strip()
        if col and col in df.columns:
            results.append(SemanticRisk(column=col, risk=risk, reason=reason))

    return results
