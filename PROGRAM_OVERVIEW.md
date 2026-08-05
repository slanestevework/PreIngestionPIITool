# Pre-Ingestion PII Tool — Program Overview

**Prepared for:** Leadership Briefing  
**Date:** August 2026  
**Status:** Active Development — Internal Use

---

## What Problem Does This Solve?

Before data files are moved into cloud platforms, data lakes, or shared analytics environments, they often contain Personally Identifiable Information (PII) that was never meant to leave the source system. Once that data lands in a cloud environment, the cost of remediation — legal, technical, and reputational — increases dramatically.

This tool intercepts that risk **before ingestion**. Files are scanned, assessed, and cleaned entirely on-premises, on the analyst's own workstation. Nothing leaves the local environment until it has been reviewed and explicitly exported.

---

## What the Tool Does

The platform has four interconnected capabilities:

### 1. PII Detection
The scanner uses a **three-layer detection engine** to find sensitive data across any structured or semi-structured file:

| Layer | Method | What It Catches |
|---|---|---|
| **Column name analysis** | Matches column names against a library of known PII field name patterns | `email`, `ssn`, `routing_number`, `dob`, `passport`, `iban`, and 20+ others |
| **Regex pattern matching** | Applies validated regular expressions to cell values | Email addresses, phone numbers, SSNs, credit cards, ZIP codes, IP addresses, dates of birth, driver's licenses, passport numbers, EINs, routing numbers, bank account numbers |
| **NLP (Microsoft Presidio)** | Runs a natural language processing engine trained for entity recognition | Person names, physical addresses, locations, and free-text PII in narrative fields |

Each finding is assigned a **risk level** (CRITICAL / HIGH / MEDIUM / LOW / REVIEW) and a **confidence score**. Up to five sample matched values are captured for review without storing full records.

**Supported file formats:** CSV, JSON, JSONL, Parquet, Excel (.xlsx/.xls), plain text, and ZIP archives containing any of the above.

---

### 2. Remediation
Once PII is detected, analysts can generate a **cloud-ready copy** of each file with sensitive values replaced. Three remediation strategies are available:

| Strategy | How It Works | Best For |
|---|---|---|
| **Redact** | Replaces values with a typed token, e.g. `<PII_REDACT:ssn>` | Audit trails, non-production environments |
| **Mask (keep last 4)** | Replaces most digits while preserving the last four, e.g. `<PII_MASK:credit_card:***1234>` | Customer service views, partial verification |
| **Hash tokenize** | Replaces values with a salted SHA-256 hash token, e.g. `<PII_HASH:email:a3f92c1d4e7b>` | Deterministic linkage across systems without exposing raw values |

Analysts can **select which PII types to remediate**, include or exclude lower-confidence "REVIEW" findings, and control fallback detection aggressiveness for names, addresses, and free-text fields. A remediation summary report is bundled with every cloud-ready export.

---

### 3. Data Quality (Rule-Based)
Powered by **Great Expectations**, the tool validates files before and after scanning against a structured set of rules:

**Input checks (run before scanning):**
- Table is not empty
- No columns are entirely null (>99% missing values)
- Columns named like identifiers (`id`, `uuid`, `key`) contain unique values
- Known fixed-width fields (`ssn`, `zip`, `phone`, `ein`) contain values of the correct length
- No columns exhibit extreme value-length variance suggesting mixed data types

**Output checks (run after scanning):**
- All required findings columns are present
- Risk and confidence values are within allowed sets
- Match counts and percentages are within valid numeric ranges

These checks run silently and surface only when something fails, keeping the interface clean for routine use.

---

### 4. AI-Powered Data Quality (Azure OpenAI — GPT 5.6 Terra)
The platform integrates **Azure OpenAI** to extend data quality analysis beyond what rule-based checks can detect. Six AI checks are available as opt-in features:

| Check | What It Does |
|---|---|
| **Anomaly detection** | Uses machine learning (Isolation Forest) to flag rows or values that are statistically unusual within each column — catches outliers, test data left in production sets, and corrupted values without any pre-defined rules. Each flagged column includes a plain-English explanation of why it was flagged (e.g. values far above the column average, unusually long text, or values that appear nowhere else in the dataset) |
| **DQ failure narrative** | When rule-based checks fail, GPT generates a plain-English paragraph explaining exactly what is wrong and what action to take — removing the need for analysts to interpret technical output |
| **Semantic PII risk** | GPT reviews column names and sample values to identify PII that the regex and NLP layers may have missed — catches disguised, renamed, or non-standard PII fields |
| **Regulatory risk — HIPAA / GDPR / CCPA** | GPT identifies which columns and column combinations may trigger obligations under major privacy regulations, specifying the category of data (PHI, PII, Sensitive Personal Data) and the specific obligation triggered |
| **Quasi-identifier detection** | GPT identifies groups of columns that individually appear harmless but together could re-identify a specific individual — a risk that no single-column rule can detect |
| **Format anomaly check** | GPT checks whether column values actually match the format implied by the column name (e.g. a "phone" column containing descriptive text, or a "zip" column with non-numeric entries) |

All AI checks are **opt-in per scan** and are disabled by default. They require valid Azure OpenAI credentials and make no external calls when turned off.

---

## How Analysts Use It

**Streamlit web interface** (local, browser-based):
1. Open the tool in a browser at `localhost:8501`
2. Upload one or more files (or a ZIP archive)
3. Select scan options and AI checks from the sidebar
4. Click **Scan**
5. Review findings, risk summary, and data quality results
6. Download the cloud-ready remediated files as a ZIP

**REST API** (for pipeline integration):
The tool also exposes a secured FastAPI service that allows upstream systems and pipelines to submit files or JSON payloads programmatically. Endpoints include:

| Endpoint | Function |
|---|---|
| `POST /scan/file` | Scan an uploaded file and return findings |
| `POST /scan/records` | Scan a JSON record array inline |
| `POST /scan/text` | Scan raw free text |
| `POST /quality/validate` | Run data quality checks on a record payload |
| `POST /quality/validate/file` | Run data quality checks on an uploaded file |

All API endpoints are secured with an API key.

---

## Architecture & Extensibility

The tool is built to be **modular and extractable**:

- The **`data_quality/`** package has no dependency on the PII scanner and can be extracted to a standalone microservice or shared library with no code changes
- Detection patterns are defined in a single `patterns.py` file and can be extended without touching scanner logic
- The AI checks in `data_quality/` each live in their own module and can be individually enabled, disabled, or replaced

**Technology stack:** Python, Streamlit, FastAPI, Microsoft Presidio, Great Expectations, scikit-learn, Azure OpenAI (GPT 5.6 Terra), pandas

**Deployment model:** Fully local / on-premises. No data is transmitted to any external system unless the Azure OpenAI AI checks are explicitly enabled by the analyst.

---

## Summary

This tool gives the team a repeatable, auditable process for identifying and remediating PII before it enters any cloud or shared environment. The combination of rule-based detection, NLP, machine learning anomaly detection, and generative AI coverage means very few sensitive data patterns will pass through undetected. The AI regulatory risk and quasi-identifier checks in particular go beyond what any purely rule-based tool can offer, providing the kind of contextual judgment that previously required a manual review step.

The platform is actively being enhanced and is designed to scale — either as a desktop tool for individual analysts or as an API service integrated into existing data pipelines.
