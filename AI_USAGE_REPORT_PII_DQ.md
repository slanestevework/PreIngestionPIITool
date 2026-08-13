# AI Usage Report: PII Detection and Data Quality

Date: 2026-08-07
Audience: Kim
Scope: This report describes where AI is used, and how, in the PII Detection and Data Quality capabilities.

## Executive Summary

- PII Detection is hybrid: deterministic regex rules plus NLP-based entity detection (Microsoft Presidio).
- Data Quality is hybrid: deterministic Great Expectations checks plus ML/LLM intelligence features.
- The platform uses Azure OpenAI for several semantic/data-quality interpretation tasks.
- Not every run uses all AI features; usage depends on selected options in the app flow.

## Product 1: PII Detection

### What uses AI

- NLP entity detection is performed with Microsoft Presidio via AnalyzerEngine and `analyzer.analyze(...)`.
- Presidio is run selectively on columns likely to contain free text or prioritized PII-like fields.
- Presidio findings are labeled as `PRESIDIO_NLP` and include confidence scores.

### What does not use AI

- Regex pattern matching against known PII formats is deterministic.
- Confidence/risk tiering for regex findings is rule-based (column hints + threshold logic).

### How it works (operationally)

- Sample values are taken per column.
- Regex checks run first.
- Presidio NLP runs when heuristics indicate likely free-text PII, or when priority columns are detected.
- Findings from both paths are merged into one output list.

### AI technologies used

- Microsoft Presidio Analyzer (NLP NER pipeline).
- spaCy-backed Presidio components (via project dependency chain).

### Main code evidence

- scanner.py: Presidio initialization and use (`AnalyzerEngine`, `presidio_scan`, `analyzer.analyze`).
- scanner.py: Rule-based regex path (`scan_column`, `determine_confidence`, risk assignment).

## Product 2: Data Quality (DQ)

### What uses AI/ML

- LLM semantic PII risk review (columns that regex/NLP may miss).
- LLM regulatory risk assessment (HIPAA/GDPR/CCPA obligations).
- LLM quasi-identifier detection (re-identification risk by column combinations).
- LLM format anomaly reasoning (value format mismatch vs column intent).
- LLM plausibility checks (implausible values).
- LLM cross-column consistency checks (for example, date order, zip/state mismatch).
- LLM completeness checks (missing companion columns, suspicious blanks).
- LLM narrative generation for failed DQ checks.
- ML anomaly detection via IsolationForest (scikit-learn) for per-column outliers.

### What does not use AI

- Core DQ validation checks (input/output schemas and expectation checks) use Great Expectations and are deterministic.

### How it works (operationally)

- Deterministic DQ validation can run before and after scanning.
- Optional AI/ML enrichments can run per file based on user-selected toggles.
- LLM prompts are structured and request JSON-only responses for machine-readability.

### AI technologies used

- Azure OpenAI chat completions (`AzureOpenAI`) for semantic and narrative checks.
- scikit-learn IsolationForest for anomaly detection.

### Main code evidence

- data_quality/_llm.py: Azure OpenAI client and chat wrapper.
- data_quality/_semantic.py: semantic PII risk assessment.
- data_quality/_regulatory.py: regulatory/quasi-identifier/format anomaly assessments.
- data_quality/_dq_intelligence.py: plausibility, cross-column consistency, and completeness checks.
- data_quality/_narrative.py: natural-language DQ summary generation.
- data_quality/_anomaly.py: IsolationForest anomaly detection.
- data_quality/_runner.py: deterministic Great Expectations execution.

## App-Level Control of AI Usage

- app.py orchestrates which checks run through feature flags/toggles.
- If NLP findings are excluded, Presidio-derived findings are filtered out before final outputs.
- This means AI usage can vary run-to-run depending on options selected by the operator.

## Data Handling Notes

- LLM-based checks send sampled column names and sample values to Azure OpenAI.
- DQ narrative sends structured failure summaries to Azure OpenAI.
- Presidio processing runs locally in-process.

## Quick Answer for Stakeholders

- PII Detection uses AI for NLP entity detection (Presidio) and rules for pattern matching.
- DQ uses both deterministic validation (Great Expectations) and AI/ML enhancements (Azure OpenAI + IsolationForest).
