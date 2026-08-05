from datetime import datetime
import os
import pandas as pd
from patterns import (PII_NAME_HINTS, PII_REGEXES, COLUMN_PATTERN_MAP, HIGH_RISK_PATTERNS)
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()


SAMPLE_LIMIT = 500
PRESIDIO_PRIORITY_COLUMN_HINTS = {
    "name",
    "address",
    "street",
    "city",
    "location",
    "note",
    "notes",
    "narrative",
    "comment",
    "comments",
    "description",
    "message",
    "text",
}

def presidio_scan(values):

    findings = {}
    samples = {}
    scores = {}

    for value in values:

        try:

            text_value = str(value)

            entities = analyzer.analyze(
                text=text_value,
                language="en"
            )

            entity_types_found = set()

            for entity in entities:

                entity_type = entity.entity_type

                detected_text = text_value[
                    entity.start:entity.end
                ]

                entity_types_found.add(
                    entity_type
                )

                # Keep highest Presidio score seen for each entity type
                if (
                    entity_type not in scores
                    or entity.score > scores[entity_type]
                ):
                    scores[entity_type] = round(
                        entity.score,
                        3
                    )

                # Keep up to 5 unique examples
                if entity_type not in samples:
                    samples[entity_type] = []

                if (
                    detected_text not in samples[entity_type]
                    and len(samples[entity_type]) < 5
                ):
                    samples[entity_type].append(
                        detected_text
                    )

            # Count rows containing each entity type,
            # not total entity occurrences
            for entity_type in entity_types_found:

                findings[entity_type] = (
                    findings.get(entity_type, 0)
                    + 1
                )

        except Exception as e:

            print(
                f"Presidio failed: {e}"
            )

    return findings, samples, scores
    
def is_candidate_column(col_name: str) -> bool:
    col_lower = col_name.lower()
    return any(hint in col_lower for hint in PII_NAME_HINTS)


def should_prioritize_presidio(col_name: str) -> bool:
    col_lower = col_name.lower()
    return any(hint in col_lower for hint in PRESIDIO_PRIORITY_COLUMN_HINTS)


def sample_values(series):
    values = (
        series.dropna()
        .astype(str)
        .str.strip()
    )

    values = values[values != ""].unique()
    return values[:SAMPLE_LIMIT]


def scan_column(values):

    results = {}
    samples = {}

    for name, pattern in PII_REGEXES.items():

        matched_values = [
            str(v)
            for v in values
            if pattern.fullmatch(str(v))
        ]

        match_count = len(
            matched_values
        )

        if match_count > 0:

            results[name] = match_count

            samples[name] = (
                matched_values[:5]
            )

    return results, samples

def determine_confidence(column_name, pattern_name):
    """
    Returns HIGH when the column name suggests
    the detected pattern is expected.
    """

    column_name = column_name.lower()

    expected_hints = COLUMN_PATTERN_MAP.get(
        pattern_name,
        []
    )

    if any(
        hint in column_name
        for hint in expected_hints
    ):
        return "HIGH"

    return "LOW"

def should_run_presidio(values):
    """
    Determines if a column looks like free text
    and would benefit from NLP analysis.
    """

    if len(values) == 0:
        return False

    avg_length = (
        sum(len(str(v)) for v in values)
        / len(values)
    )

    multi_word_pct = (
        sum(
            1
            for v in values
            if len(str(v).split()) > 3
        )
        / len(values)
    )

    return (
        avg_length > 15
        or multi_word_pct > 0.25
    )


def should_scan_column(col_name: str, values, source_name: str) -> bool:
    if source_name.lower().endswith(".txt"):
        return True

    if is_candidate_column(col_name):
        return True

    return should_run_presidio(values)


def has_dominant_regex_match(matches: dict[str, int], sample_size: int) -> bool:
    if sample_size <= 0:
        return False

    return any((count / sample_size) >= 0.8 for count in matches.values())

def scan_dataframe(df, source_name):
    findings = []

    stats = {
        "source": source_name,
        "columns_scanned": 0,
        "findings": 0
    }

    for col in df.columns:
        values = sample_values(df[col])

        if not should_scan_column(col, values, source_name):
            continue

        stats["columns_scanned"] += 1
        matches, regex_samples = scan_column(values)

        presidio_matches = {}
        presidio_samples = {}
        presidio_scores = {}
        prioritize_presidio = should_prioritize_presidio(col)
        dominant_regex_match = has_dominant_regex_match(matches, len(values))

        if (
            len(values) > 0
            and (
                should_run_presidio(values)
                or prioritize_presidio
            )
            and (prioritize_presidio or not dominant_regex_match)
        ):
            print(
                f"Running Presidio on {col}"
            )

            presidio_matches, presidio_samples, presidio_scores = presidio_scan(
                values
            )
            print("\nPresidio Results")
            
            print(presidio_matches)
            
            print(presidio_samples)

        for pattern_name, count in matches.items():

            confidence = determine_confidence(
                col,
                pattern_name
            )
            match_pct = round(
                (count / len(values)) * 100,2
                )
            
            if confidence == "HIGH" and match_pct > 80:
                risk = "HIGH"

            elif confidence == "HIGH":
                risk = "MEDIUM"

            else:
                risk = "LOW"

            if (
                pattern_name in HIGH_RISK_PATTERNS and
                confidence == "HIGH"
            ):
                risk = "CRITICAL"
            examples = regex_samples.get(pattern_name,[])
            findings.append({
                "source": source_name,
                "column": col,
                "pattern": pattern_name,
                "confidence": confidence,
                "risk": risk,
                "matches": count,
                "sample_size": len(values),
                "match_pct": match_pct,

                "presidio_score": None,

                "sample_match_1":
                    examples[0]
                    if len(examples) > 0
                    else "",

                "sample_match_2":
                    examples[1]
                    if len(examples) > 1
                    else "",

                "sample_match_3":
                    examples[2]
                    if len(examples) > 2
                    else "",

                "sample_match_4":
                    examples[3]
                    if len(examples) > 3
                    else "",

                "sample_match_5":
                    examples[4]
                    if len(examples) > 4
                    else "",

                "detection_source": "REGEX_RULE",
                "detection_timestamp":
                    datetime.now().isoformat()
            })
            print(type(presidio_matches))
            print(presidio_matches)
        for entity_type, count in presidio_matches.items():

            match_pct = round(
                (count / len(values)) * 100,
                2
            )

            examples = presidio_samples.get(
                entity_type,
                []
            )

            findings.append({
                "source": source_name,
                "column": col,
                "pattern": entity_type,
                "confidence": "AI",
                "risk": "REVIEW",
                "matches": count,
                "sample_size": len(values),
                "match_pct": match_pct,
                "presidio_score": presidio_scores.get(
                    entity_type,
                    0
                ),
                "sample_match_1": examples[0] if len(examples) > 0 else "",
                "sample_match_2": examples[1] if len(examples) > 1 else "",
                "sample_match_3": examples[2] if len(examples) > 2 else "",
                "sample_match_4": examples[3] if len(examples) > 3 else "",
                "sample_match_5": examples[4] if len(examples) > 4 else "",
                "detection_source": "PRESIDIO_NLP",
                "detection_timestamp": datetime.now().isoformat()
        })

    stats["findings"] = len(findings)

    return findings, stats


def read_file(file_path):
    ext = file_path.lower().split(".")[-1]

    try:
        if ext == "csv":
            return pd.read_csv(
                file_path,
                dtype=str
            )

        elif ext == "json":
            return pd.read_json(
                file_path,
                lines=True
            )

        elif ext == "parquet":
            return pd.read_parquet(file_path)

        elif ext == "txt":
            return pd.read_csv(
                file_path,
                header=None,
                names=["value"]
            )
        elif ext in ["xlsx", "xls"]:
            return pd.read_excel(
            file_path,
            dtype=str
            )

        else:
            return None

    except Exception as e:
        print(f"Failed to read {file_path}: {e}")
        return None


def scan_directory(path):
    all_findings = []
    all_stats = []

    for root, _, files in os.walk(path):

        for file in files:
            file_path = os.path.join(root, file)

            df = read_file(file_path)

            if df is None:
                continue

            findings, stats = scan_dataframe(
                df,
                file_path
            )

            all_findings.extend(findings)
            all_stats.append(stats)

    return all_findings, all_stats
