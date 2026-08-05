from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


@dataclass
class AnomalyResult:
    column: str
    anomalous_row_count: int
    total_rows: int
    anomaly_pct: float
    explanation: str = ""
    sample_anomalous_values: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.anomalous_row_count > 0


def _explain_numeric(normal: pd.Series, anomalous: pd.Series) -> str:
    mean = normal.mean()
    std = normal.std()
    a_mean = anomalous.mean()
    if std == 0:
        return "Values are identical across the column — these differ."
    z = (a_mean - mean) / std
    direction = "above" if z > 0 else "below"
    return (
        f"Typical values average {mean:.2f} (±{std:.2f}). "
        f"Flagged values average {a_mean:.2f} — {abs(z):.1f} standard deviations {direction} the norm."
    )


def _explain_text(normal: pd.Series, anomalous: pd.Series) -> str:
    normal_str = normal.astype(str)
    anomalous_str = anomalous.astype(str)

    # Length check first — more informative than rarity for text columns
    normal_lens = normal_str.str.len()
    anom_lens = anomalous_str.str.len()
    mean_len = normal_lens.mean()
    anom_mean_len = anom_lens.mean()
    if mean_len > 0:
        ratio = anom_mean_len / mean_len
        if ratio > 2.5:
            return (
                f"Typical values are ~{mean_len:.0f} characters long. "
                f"Flagged values are ~{anom_mean_len:.0f} characters — "
                "significantly longer, suggesting free-text or concatenated data."
            )
        if ratio < 0.4:
            return (
                f"Typical values are ~{mean_len:.0f} characters long. "
                f"Flagged values are ~{anom_mean_len:.0f} characters — "
                "unusually short, possibly truncated or placeholder values."
            )

    # Rarity check — only meaningful when values repeat across rows
    total = len(normal_str)
    if total > 0:
        value_counts = normal_str.value_counts()
        most_common_freq = value_counts.iloc[0] / total if len(value_counts) > 0 else 0
        # Only call it "rare" if the column has repeating values (not all unique)
        if most_common_freq > 0.05:
            anom_freqs = anomalous_str.map(lambda v: value_counts.get(v, 0) / total)
            if anom_freqs.mean() < 0.02:
                return (
                    "These values appear rarely or not at all among typical entries — "
                    "they may be test data, errors, or outlier records."
                )

    # Cardinality check — all-unique column with some structurally different values
    unique_ratio = normal_str.nunique() / len(normal_str) if len(normal_str) > 0 else 0
    if unique_ratio > 0.9:
        return (
            "This column has mostly unique values. "
            "Flagged entries have an unusual structure compared to the typical pattern."
        )

    return (
        "Values have an unusual combination of characteristics compared to "
        "the rest of the column — they may warrant manual review."
    )


def detect_anomalies(
    df: pd.DataFrame,
    contamination: float = 0.05,
    max_sample_values: int = 5,
) -> list[AnomalyResult]:
    """
    Runs IsolationForest per column and returns columns where anomalous rows were found.

    Numeric columns are used directly; categorical/text columns are label-encoded
    by value frequency so rare values score as anomalous.
    """
    if df.empty:
        return []

    results: list[AnomalyResult] = []

    for col in df.columns:
        series = df[col].copy()
        n_total = len(series)

        non_null = series.dropna()
        if len(non_null) < 10:
            continue

        is_numeric = pd.api.types.is_numeric_dtype(non_null)

        if is_numeric:
            values = non_null.values.reshape(-1, 1).astype(float)
        else:
            le = LabelEncoder()
            encoded = le.fit_transform(non_null.astype(str))
            freq = np.bincount(encoded)
            inv_freq = (1.0 / (freq[encoded] + 1)).reshape(-1, 1)
            values = inv_freq

        clf = IsolationForest(contamination=contamination, random_state=42, n_jobs=1)
        labels = clf.fit_predict(values)

        anomaly_mask = labels == -1
        normal_mask = labels == 1
        anomalous_original = non_null.iloc[anomaly_mask]
        normal_original = non_null.iloc[normal_mask]
        n_anomalous = int(anomaly_mask.sum())

        if n_anomalous == 0:
            continue

        if is_numeric:
            explanation = _explain_numeric(
                normal_original.astype(float), anomalous_original.astype(float)
            )
        else:
            explanation = _explain_text(
                normal_original, anomalous_original
            )

        sample = (
            anomalous_original.astype(str)
            .drop_duplicates()
            .head(max_sample_values)
            .tolist()
        )

        results.append(
            AnomalyResult(
                column=col,
                anomalous_row_count=n_anomalous,
                total_rows=n_total,
                anomaly_pct=round(100 * n_anomalous / n_total, 1),
                explanation=explanation,
                sample_anomalous_values=sample,
            )
        )

    return results

    return results
