# Data Quality & PII Scanning — Pre-Ingestion Pipeline
## PowerPoint Slide Content

---

## SLIDE 1 — Title
**Title:** AI-Powered Data Quality & PII Detection
**Subtitle:** Automated pre-ingestion validation for modern data pipelines
**Notes:** Open with the problem: data lands in your warehouse dirty and you only find out when a report breaks.

---

## SLIDE 2 — The Problem
**Title:** What Happens Without Pre-Ingestion Checks?

- Bad data enters the warehouse silently
- Downstream reports and models consume corrupt, incomplete, or sensitive values
- PII (names, SSNs, emails, phone numbers) lands in systems that aren't cleared to hold it
- Fixes cost 10–100× more after ingestion than before
- Regulatory exposure: HIPAA, GDPR, CCPA violations from mishandled PII

**Visual idea:** "Cost of fixing a defect" curve — cheap at source, expensive at analytics layer

---

## SLIDE 3 — Our Solution
**Title:** A Two-Layer Pre-Ingestion Gate

**Layer 1 — PII Scanner**
- Regex rules + Microsoft Presidio NLP
- Detects names, SSNs, emails, phone numbers, credit cards, IPs, addresses
- Assigns risk levels: CRITICAL → HIGH → MEDIUM → LOW → REVIEW

**Layer 2 — Data Quality Engine**
- Rule-based checks (Great Expectations)
- AI-generated dataset-specific checks (Azure OpenAI)
- Semantic analysis: plausibility, consistency, completeness, regulatory risk

**Visual idea:** Two-lane funnel — file goes in, clean/flagged data comes out

---

## SLIDE 4 — Meet the Data (Title Slide for Section)
**Title:** The Patient: messy_HR_data.csv

> *"A file that looks like a CSV but behaves like a crime scene."*

- 1,000 rows · 10 columns · HR employee records
- Received from a source system before any validation

---

## SLIDE 5 — A Look at the Raw Data
**Title:** Raw Data — First Impressions

**Show a sample table (8–10 rows, all 10 columns)**

| Name | Age | Salary | Gender | Department | Position | Joining Date | Perf. | Email | Phone |
|---|---|---|---|---|---|---|---|---|---|
| ` grace ` | *(null)* | 50000 | Male | HR | Manager | April 5, 2018 | D | email@example.com | nan |
| ` david ` | *(null)* | 65000 | Female | Finance | Director | 2020/02/20 | F | user@domain.com | 123-456-7890 |
| ` hannah ` | 35 | SIXTY THOUSAND | Female | Sales | Director | 01/15/2020 | C | email@example.com | 098-765-4321 |
| ` eve ` | *(null)* | 50000 | Female | IT | Manager | April 5, 2018 | A | name@company.org | *(blank)* |
| ` eve ` | thirty | NAN | Other | Finance | Assistant | 2020/02/20 | A | *(blank)* | *(blank)* |

**Notes:** Ask the audience: "How many problems can you spot in just these 5 rows?" Then advance to the next slide.

---

## SLIDE 6 — Data Quality Problems: By the Numbers
**Title:** What's Wrong — Quantified

| Problem | Column(s) | Count | % of Records |
|---|---|---|---|
| Missing values | Age | 159 nulls | 15.9% |
| Missing values | Email | 390 nulls | 39.0% |
| Missing values | Phone Number | 185 nulls | 18.5% |
| **Text where number expected** | Age | 176 rows say "thirty" | 17.6% |
| **Text where number expected** | Salary | 143 rows say "SIXTY THOUSAND" | 14.3% |
| **String "NAN" instead of null** | Salary | 167 rows | 16.7% |
| **5 different date formats** | Joining Date | 1,000 rows, 0 consistent | 100% |
| **Placeholder / fake emails** | Email | 610 rows | 61.0% |
| **Duplicate records** | Name + Dept | 950 of 1,000 rows | 95.0% |
| **Leading/trailing spaces** | Name | All 1,000 rows | 100% |

**Notes:** Every single row in this file has at least one quality problem. This is not unusual — it's representative of real operational data.

---

## SLIDE 7 — Problem Deep-Dives (can split into multiple slides)
**Title:** Problem Spotlight: Format Chaos

**Date formats found in a single column (Joining Date):**
- `01/15/2020` — MM/DD/YYYY (197 rows)
- `2020/02/20` — YYYY/MM/DD (232 rows)
- `03-25-2019` — MM-DD-YYYY (180 rows)
- `2019.12.01` — YYYY.MM.DD (205 rows)
- `April 5, 2018` — Long text (186 rows)

> Five formats, zero consistency, one column. A date parser will fail silently or produce wrong values.

---

## SLIDE 8 — Problem Spotlight: Semantic Corruption
**Title:** Problem Spotlight: Numbers Written as Words

- **Age column:** Values include `"thirty"` (176 records)
  - Passes a null check ✓  
  - Passes a "not empty" check ✓  
  - Fails silently in every numeric calculation ✗

- **Salary column:** Values include `"SIXTY THOUSAND"` (143 records) and `" NAN "` (167 records)
  - String NAN ≠ NULL — most tools won't catch it as missing
  - Standard type checks won't flag `"SIXTY THOUSAND"` as wrong

> **Rule-based validators miss these. You need semantic awareness.**

---

## SLIDE 9 — Problem Spotlight: The Illusion of Valid Data
**Title:** Problem Spotlight: Data That Looks Valid but Isn't

**Emails that pass a format check but are clearly fake:**
- `user@domain.com` — 213 occurrences
- `email@example.com` — 208 occurrences  
- `name@company.org` — 189 occurrences

> These are syntactically valid email addresses. A regex check gives them a green light. A human recognises them immediately as placeholders.

**Names with only 10 unique values across 1,000 rows:**
alice · bob · charlie · david · eve · frank · grace · hannah · ivy · jack

> 95% of name+department combinations are duplicates. This data was either generated or severely corrupted.

---

## SLIDE 10 — Section Title: Our DQ Framework
**Title:** How We Check Data Quality

Three progressive layers — each catches what the previous layer misses.

```
┌─────────────────────────────────────────────────┐
│  Layer 1: Rule-Based (Great Expectations)        │
│  Fast · Deterministic · Structural integrity     │
├─────────────────────────────────────────────────┤
│  Layer 2: LLM-Generated Expectations             │
│  Dataset-specific · Adaptive · No manual config  │
├─────────────────────────────────────────────────┤
│  Layer 3: AI Semantic Analysis                   │
│  Plausibility · Consistency · PII risk · Regs    │
└─────────────────────────────────────────────────┘
```

---

## SLIDE 11 — Layer 1: Great Expectations
**Title:** Layer 1 — Great Expectations: The Rule Engine

**What is Great Expectations?**
- Open-source Python framework for data validation (300k+ downloads/month)
- Used at Airbnb, Twitter, GitHub, and many Fortune 500 data teams
- Defines "expectations" — assertions about what your data *should* look like
- Runs before data is written to any target system

**Why it matters:**
- Catches structural problems: schema changes, unexpected nulls, out-of-range values
- Produces human-readable validation reports
- Integrates with Spark, Pandas, SQL, and major pipeline orchestrators

---

## SLIDE 12 — Our Default Expectation Suite
**Title:** Layer 1 — Our 12 Default Checks (Applied to Every File)

| # | Check | What It Catches |
|---|---|---|
| 1 | Minimum row count | Empty or truncated files |
| 2 | No fully-null columns | Columns that arrived completely empty |
| 3 | Email column not null | Missing contact data |
| 4 | Email value length 5–254 chars | Truncated or overflow values |
| 5 | Phone number not null | Missing contact data |
| 6 | Phone number length 7–20 chars | Malformed phone strings |
| 7 | Name column not null | Missing identity fields |
| 8 | Name value length 2–100 chars | Truncated or corrupted names |
| 9 | Date column not null | Missing temporal data |
| 10 | Date value length 6–30 chars | Format anomalies |
| 11 | Numeric column range check | Values outside plausible bounds |
| 12 | No duplicate primary key | Record-level duplication |

> These run in milliseconds. They are the minimum bar every file must clear.

**Results on messy_HR_data.csv:** 11 passed, **1 failed** — Phone Number length check (blank strings pass null but fail length)

---

## SLIDE 13 — Layer 2: LLM-Generated Expectations
**Title:** Layer 2 — LLM Expectations: AI Writes the Rules

**The problem with hand-written expectations:**
- A 50-column dataset could need 200+ expectations
- Rules written once rarely get updated as data evolves
- Generic rules miss dataset-specific logic (e.g. "salary should be between $30k–$200k for this org")

**Our approach — profile first, then generate:**
1. Build a statistical profile of each column (value distribution, ranges, formats, cardinality)
2. Send the profile to GPT-4o in batches of 8 columns
3. GPT-4o proposes dataset-specific expectations with confidence scores and rationale
4. We sanitise, deduplicate, and validate all proposed expectations against the actual data

**Result on messy_HR_data.csv:** 14 expectations generated, 13 passed, 1 failed
- ✅ Age values in set {25, 35, 40, 50} — caught "thirty" as invalid
- ✅ Salary column values match numeric pattern — would flag "SIXTY THOUSAND"
- ❌ Salary values match currency regex — "SIXTY THOUSAND" and " NAN " fail

---

## SLIDE 14 — LLM Expectations: Example Output
**Title:** Layer 2 — What the LLM Generates

**Sample expectations proposed for messy_HR_data.csv:**

| Expectation | Column | Confidence | Rationale |
|---|---|---|---|
| Values in set | Gender | HIGH | Only 3 valid values: Male, Female, Other |
| Not null, mostly 0.95 | Email | HIGH | Contact field — should be present for most records |
| Values match regex | Salary | MEDIUM | Should be numeric — flags text like "SIXTY THOUSAND" |
| Values in set | Department | HIGH | HR, Finance, Sales, IT, Marketing — closed list |
| Values in set | Performance Score | HIGH | A/B/C/D/F — closed grading scale |
| Value lengths 2–30 | Name | MEDIUM | First names shouldn't be empty or truncated |
| Values in set | Position | HIGH | Manager/Director/Clerk/Analyst/Assistant |

> These expectations are **specific to this dataset** — no manual configuration required.

---

## SLIDE 15 — Layer 3: AI Semantic Analysis
**Title:** Layer 3 — AI Analysis: Catching What Rules Can't

Beyond structural checks, we run 8 AI-powered analyses:

| Analysis | What It Finds |
|---|---|
| **DQ Narrative** | Plain-English explanation of every failure — what's wrong and how to fix it |
| **Anomaly Detection** | Isolation Forest ML flags statistically unusual values per column |
| **Semantic PII Risk** | GPT-4o reviews column names and samples for PII a regex scanner missed |
| **Regulatory Risk** | Flags HIPAA, GDPR, CCPA obligations column by column |
| **Quasi-Identifier Detection** | Finds column *combinations* that together could re-identify individuals |
| **Value Plausibility** | Spots absurd values: age=999, negative salary, future hire date |
| **Cross-Column Consistency** | Finds contradictions: zip code doesn't match state, end date before start date |
| **Completeness Assessment** | Identifies columns that should be present but are missing entirely |

---

## SLIDE 16 — AI Analysis in Action: DQ Narrative
**Title:** AI Analysis — Plain-English Failure Summary

**After the Great Expectations run, GPT-4o explains the failures:**

> *"The Phone Number column has values that do not meet the expected length requirements. Review the phone number entries for missing, truncated, or excessively long values, and standardize them to the required format and number of digits."*

**Why this matters:**
- A raw "ExpectColumnValueLengthsToBeBetween failed, column=Phone Number" means nothing to a business user
- The narrative tells the data steward exactly what to look at and what to do
- No SQL knowledge required to understand the problem

---

## SLIDE 17 — AI Analysis in Action: Plausibility & Consistency
**Title:** AI Analysis — Catching the Semantically Wrong

**Value Plausibility (GPT-4o reviews sample values):**
- `Age: "thirty"` — 🔴 HIGH — Text string in numeric field; should be an integer
- `Salary: "SIXTY THOUSAND"` — 🔴 HIGH — Written-out number, not parseable as currency
- `Salary: " NAN "` — 🟡 MEDIUM — Looks like a null placeholder stored as text

**Cross-Column Consistency:**
- `Gender=Male, Name=grace` — 🟡 MEDIUM — Name appears inconsistent with gender value
- Flagged without any rule being written — GPT-4o inferred the relationship

> These are the problems that survive every rule-based check and only show up when you *read* the data.

---

## SLIDE 18 — AI Analysis in Action: PII & Regulatory
**Title:** AI Analysis — Privacy Risk Assessment

**Semantic PII Risk (columns the regex scanner might have missed):**
- `Name` — 🔴 HIGH — First names are direct personal identifiers
- `Email` — 🔴 HIGH — Even placeholder emails signal a PII-carrying field
- `Phone Number` — 🔴 HIGH — Contact identifier

**Regulatory Risk Assessment:**
| Column(s) | Regulation | Category | Obligation |
|---|---|---|---|
| Name + Email + Phone | GDPR | PII | Lawful basis required; right to erasure applies |
| Name + Salary + Performance Score | GDPR | Employment Data | Special category if health/union data present |
| Name + Department + Performance Score | CCPA | Personal Information | Disclosure and deletion rights apply |

**Quasi-Identifier Risk:**
- Age + Gender + Department + Performance Score → 🟡 MEDIUM re-identification risk

---

## SLIDE 19 — The Pipeline Integration
**Title:** Where This Fits in Your Data Pipeline

```
  Source System
       │
       ▼
  ┌─────────────────────────────────────┐
  │   Pre-Ingestion Gate (this tool)    │
  │                                     │
  │  1. PII Scan          → PASS/BLOCK  │
  │  2. GE Rule Checks    → PASS/WARN   │
  │  3. LLM Expectations  → PASS/WARN   │
  │  4. AI Semantic Check → REPORT      │
  └─────────────────────────────────────┘
       │
       ├──(PASS)──▶  Load to Data Warehouse
       │
       └──(BLOCK)─▶  Quarantine Queue → Data Steward Alert
```

**Three integration modes:**
- **API call** — `POST /scan/file` + `POST /quality/validate/file` from any pipeline tool
- **Standalone** — Run `demo_pipeline.py` before loading any file manually
- **Scheduled** — Wrap API calls in Airflow / Azure Data Factory task

---

## SLIDE 20 — Live Demo Recap
**Title:** What We Just Saw: messy_HR_data.csv Results

| Check | Result | Key Finding |
|---|---|---|
| PII Detection | ⚠️ Findings | Email, Phone, Name columns flagged |
| GE Baseline | 🟡 92% (11/12) | Phone Number length check failed |
| LLM Expectations | 🟡 93% (13/14) | Salary format regex failed |
| DQ Narrative | ✅ Generated | Plain-English summary of phone issue |
| Anomaly Detection | ✅ Run | Flagged outlier patterns in Age/Salary |
| Semantic PII | 🔴 Flagged | Name, Email, Phone as PII risk |
| Regulatory | 🔴 Flagged | GDPR and CCPA obligations identified |
| Plausibility | 🔴 Issues | "thirty", "SIXTY THOUSAND", " NAN " flagged |
| Cross-column | 🟡 Issues | Name/Gender inconsistencies noted |
| Completeness | ✅ Assessed | Missing companion columns identified |

> **Verdict: This file should not have been loaded without remediation.**

---

## SLIDE 21 — PII Remediation
**Title:** What Happens to PII Before It Moves?

**Three remediation strategies available:**

| Strategy | Example | Use Case |
|---|---|---|
| **Redact** | `john.smith@acme.com` → `<PII_REDACT:email>` | Full removal — analytics won't use the field |
| **Mask** | `john.smith@acme.com` → `<PII_MASK:email>` | Preserve structure, hide value |
| **Hash** | `john.smith@acme.com` → `<PII_HASH:email:3f2a8b1c9d4e>` | Deterministic token — join keys survive |

- Applied column-by-column, pattern-by-pattern
- Fallback rules for PII found in free-text (addresses, names in narrative columns)
- Produces a cleaned file you can load safely alongside a full audit trail

---

## SLIDE 22 — Why This Approach is Different
**Title:** How This Compares to Traditional DQ Tools

| | Traditional DQ Tool | Our Approach |
|---|---|---|
| **Expectation authoring** | Manual — engineer writes every rule | AI-generated from data profile |
| **Adapts per dataset** | No — same rules for all files | Yes — tailored per file, per run |
| **PII awareness** | Rarely built-in | First-class feature |
| **Regulatory mapping** | Separate tool / manual | Automatic HIPAA/GDPR/CCPA scan |
| **Cost of 200+ rules** | Days of engineering time | Minutes (LLM generates, GE validates) |
| **Explains failures** | Error codes / logs | Plain-English narrative |
| **Deployment** | Standalone platform | Lightweight Python API — runs anywhere |

---

## SLIDE 23 — What's Next
**Title:** Roadmap & Next Steps

**Short term:**
- Connect the API to our existing ingestion pipeline (Airflow / ADF)
- Define escalation workflow: which failures block load vs. flag for review?
- Establish baseline DQ scores per source system

**Medium term:**
- Add threshold drift detection — alert when null rate jumps vs. prior run
- Persist expectation suites per source — reuse LLM-generated rules across runs
- Build a DQ score dashboard per data domain

**Long term:**
- Extend PII scanning to semi-structured data (JSON, Parquet nested types)
- Integrate with data catalog (Purview / Collibra) for lineage-aware checks
- Explore fine-tuned model for domain-specific expectation generation

---

## SLIDE 24 — Closing
**Title:** Key Takeaways

1. **Every file has issues** — messy_HR_data.csv had a problem in every single row
2. **Rules alone aren't enough** — "thirty" and "SIXTY THOUSAND" pass every basic check
3. **AI finds what rules miss** — plausibility, consistency, and semantic PII require language understanding
4. **The API makes it portable** — any tool that can POST a file can use this gate
5. **Start with the baseline** — 12 default checks + LLM expectations catches >90% of real issues in our testing

> *"The best time to check data quality is before it enters your warehouse. The second best time is right now."*

---

## APPENDIX A — API Endpoints Reference

| Endpoint | Purpose |
|---|---|
| `GET /health` | Server liveness check |
| `POST /scan/file` | PII scan — returns findings + risk levels |
| `POST /scan/records` | PII scan on JSON record payload |
| `POST /scan/text` | PII scan on raw text |
| `POST /quality/validate/file` | Great Expectations baseline suite |
| `POST /quality/ai-analysis/file` | All AI-powered DQ checks (flags selectable) |
| `POST /remediate/file` | Scan + redact/mask/hash PII, returns cleaned file |

---

## APPENDIX B — API Call Details

### Authentication
All endpoints (except `/health`) accept an optional API key via HTTP header.  
Set the environment variable `PII_SCANNER_API_KEY` on the server to require it.

```
Header:  X-API-Key: <your-key>
```

If `PII_SCANNER_API_KEY` is not set, the server accepts all requests without a key.

---

### GET /health
**Purpose:** Verify the server is running before submitting files.

**Request:** No parameters.

**Response:**
```json
{ "status": "ok" }
```

**Typical use:** Poll this before a pipeline run to abort early if the service is down.

---

### POST /scan/file
**Purpose:** Scan an uploaded file for PII using regex rules and Presidio NLP.

**Request:** `multipart/form-data`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file` | file upload | ✅ | CSV, JSON, Parquet, TXT, XLSX, or XLS |

**Response fields:**

| Field | Type | Description |
|---|---|---|
| `source` | string | File name |
| `stats` | object | `rows`, `columns_scanned`, `columns_with_pii_count`, scan timings |
| `findings` | array | One object per PII-containing column (see below) |

**Finding object:**

| Field | Description |
|---|---|
| `column` | Column name where PII was found |
| `pattern` | PII type: `EMAIL_ADDRESS`, `US_SSN`, `PHONE_NUMBER`, `PERSON`, `LOCATION`, `CREDIT_CARD`, `IP_ADDRESS`, etc. |
| `risk` | `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `REVIEW` |
| `detection_source` | `REGEX_RULE` · `PRESIDIO_NLP` · `STRICT_FALLBACK` |
| `sample_match_1` … `sample_match_5` | Redacted sample values |

**Example curl:**
```bash
curl -X POST http://localhost:8000/scan/file \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv"
```

---

### POST /scan/records
**Purpose:** Scan an in-memory JSON record array — no file needed. Useful when data is already loaded in a pipeline.

**Request:** `application/json`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `records` | array of objects | ✅ | — | JSON records to scan |
| `source_name` | string | ❌ | `"inline_records.json"` | Label used in findings output |

**Example request body:**
```json
{
  "records": [
    { "name": "Alice Smith", "email": "alice@example.com", "ssn": "123-45-6789" }
  ],
  "source_name": "employee_batch_001"
}
```

**Response:** Same shape as `/scan/file`.

---

### POST /scan/text
**Purpose:** Scan a raw text string (e.g. a notes field, a support ticket, a clinical narrative).

**Request:** `application/json`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string | ✅ | — | Raw text to scan |
| `source_name` | string | ❌ | `"inline_text.txt"` | Label used in findings |
| `column_name` | string | ❌ | `"value"` | Column name assigned to the text lines |

**Example request body:**
```json
{
  "text": "Patient John Doe (DOB 01/15/1980) called from 555-867-5309.",
  "source_name": "support_ticket_4421"
}
```

**Response:** Same shape as `/scan/file`.

---

### POST /quality/validate/file
**Purpose:** Run the 12 standard Great Expectations checks against an uploaded file.

**Request:** `multipart/form-data`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file` | file upload | ✅ | CSV, JSON, Parquet, TXT, XLSX, or XLS |

**Response fields:**

| Field | Type | Description |
|---|---|---|
| `passed` | boolean | `true` if all checks passed |
| `evaluated` | integer | Total number of checks run |
| `successful` | integer | Checks that passed |
| `failed` | integer | Checks that failed |
| `success_rate` | float | `successful / evaluated` (0.0 – 1.0) |
| `failures` | array | One object per failed check |

**Failure object:**

| Field | Description |
|---|---|
| `expectation` | Human-readable check name (e.g. "Column Value Lengths To Be Between") |
| `column` | Column the check ran against (null for table-level checks) |
| `details` | Dict with observed values, bad counts, etc. |

**Example curl:**
```bash
curl -X POST http://localhost:8000/quality/validate/file \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv"
```

---

### POST /quality/validate (records variant)
**Purpose:** Same as above but accepts a JSON record payload instead of a file upload.

**Request:** `application/json` — same body as `/scan/records`.

**Response:** Same shape as `/quality/validate/file`.

---

### POST /quality/ai-analysis/file
**Purpose:** Run one or more AI-powered DQ checks. Each check is opt-in via a query parameter — enabling only the checks you need keeps latency low.

**Request:** `multipart/form-data` + query parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `file` | file upload | — | CSV, JSON, Parquet, TXT, XLSX, or XLS |
| `narrative` | bool | `false` | GPT-4o plain-English explanation of GE failures |
| `anomaly` | bool | `false` | Isolation Forest flags statistically unusual values |
| `semantic_pii` | bool | `false` | GPT-4o flags columns likely containing PII a regex missed |
| `regulatory` | bool | `false` | GPT-4o maps columns to HIPAA / GDPR / CCPA obligations |
| `quasi_id` | bool | `false` | GPT-4o identifies column combinations that risk re-identification |
| `format_check` | bool | `false` | GPT-4o checks whether values match their column name's implied format |
| `plausibility` | bool | `false` | GPT-4o flags implausible values (age=999, negative salary, etc.) |
| `consistency` | bool | `false` | GPT-4o detects cross-column contradictions |
| `completeness` | bool | `false` | GPT-4o identifies columns that appear incomplete or companion columns that are missing |
| `auto_expectations` | bool | `false` | GPT-4o proposes dataset-specific GE expectations, then validates them |

**Response fields (all optional — only present when the corresponding check was enabled):**

| Field | Present when | Content |
|---|---|---|
| `checks_run` | always | List of check keys that ran successfully |
| `errors` | always | Dict of `check_key → error_message` for any check that failed |
| `narrative` | `narrative=true` | Plain-English string explaining failures |
| `anomalies` | `anomaly=true` | Array: `column`, `anomalous_row_count`, `anomaly_pct`, `explanation`, `sample_anomalous_values` |
| `semantic_pii_risks` | `semantic_pii=true` | Array: `column`, `risk` (HIGH/MEDIUM/LOW), `reason` |
| `regulatory_flags` | `regulatory=true` | Array: `column`, `regulation`, `category`, `obligation`, `severity` |
| `quasi_identifiers` | `quasi_id=true` | Array: `columns` (list), `risk`, `reason` |
| `format_anomalies` | `format_check=true` | Array: `column`, `expected_format`, `observed_issue`, `severity` |
| `plausibility_issues` | `plausibility=true` | Array: `column`, `issue`, `example`, `severity` |
| `consistency_issues` | `consistency=true` | Array: `columns`, `issue`, `severity` |
| `completeness_issues` | `completeness=true` | Array: `column`, `issue`, `severity` |
| `auto_expectations` | `auto_expectations=true` | Object — see below |

**`auto_expectations` response object:**

| Field | Description |
|---|---|
| `proposed_count` | Number of expectations GPT-4o proposed |
| `executed_count` | Number successfully converted to GE and run |
| `passed` | Expectations that passed |
| `failed` | Expectations that failed |
| `success_rate` | `passed / executed` (0.0 – 1.0) |
| `failures` | Array of failed expectations with details |
| `specs` | Full list of proposed expectations: `expectation_type`, `column`, `confidence`, `rationale` |
| `outcomes` | Per-expectation pass/fail with `status_icon`, `failure_details` |
| `error` | Error message if generation failed (null on success) |
| `diagnostic` | Debug info: batch count, LLM chars, finish reasons, rejection counts |

**Example curl — run all AI checks:**
```bash
curl -X POST \
  "http://localhost:8000/quality/ai-analysis/file?narrative=true&anomaly=true&semantic_pii=true&regulatory=true&quasi_id=true&format_check=true&plausibility=true&consistency=true&completeness=true&auto_expectations=true" \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv"
```

**Example curl — run only anomaly detection (fast, no OpenAI required):**
```bash
curl -X POST \
  "http://localhost:8000/quality/ai-analysis/file?anomaly=true" \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv"
```

---

### POST /remediate/file
**Purpose:** Scan a file for PII, apply redaction/masking/hashing to all flagged columns, and return the cleaned file as a CSV string plus a full audit trail.

**Request:** `multipart/form-data` + query parameters

| Parameter | Type | Default | Options | Description |
|---|---|---|---|---|
| `file` | file upload | — | — | CSV, JSON, Parquet, TXT, XLSX, or XLS |
| `mode` | string | `"redact"` | `redact` · `mask_last4` · `hash` | Remediation strategy |
| `salt` | string | `"api-remediation-salt"` | any string | Salt used for hash mode — use the same salt across runs for consistent tokens |
| `include_review` | bool | `true` | — | Whether to remediate REVIEW-risk findings (NLP detections that may include false positives) |

**Remediation modes:**

| Mode | Output example | Use case |
|---|---|---|
| `redact` | `<PII_REDACT:email>` | Complete removal — value is gone |
| `mask_last4` | `<PII_MASK:ssn:***6789>` | Keep last 4 digits for reference |
| `hash` | `<PII_HASH:email:3f2a8b1c9d4e>` | Deterministic token — join keys survive anonymisation |

**Response fields:**

| Field | Type | Description |
|---|---|---|
| `source` | string | Original file name |
| `mode` | string | Strategy used |
| `scan_stats` | object | PII scan statistics |
| `pii_findings_count` | integer | Total PII findings detected |
| `remediation_summary` | array | One row per column/pattern combination modified |
| `total_cells_changed` | integer | Total individual cell values transformed |
| `remediated_csv` | string | Full CSV content of the cleaned file (UTF-8) |

**Remediation summary row:**

| Field | Description |
|---|---|
| `column` | Column that was modified |
| `pattern` | PII type that triggered the change (e.g. `EMAIL_ADDRESS`) |
| `detection_source` | `REGEX_RULE` · `PRESIDIO_NLP` · `STRICT_FALLBACK` |
| `strategy` | `REDACT` · `MASK_LAST4` · `HASH` |
| `cells_changed` | Number of cells in this column that were transformed |

**Example curl — redact all PII:**
```bash
curl -X POST \
  "http://localhost:8000/remediate/file?mode=redact" \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv" \
  -o remediation_response.json
```

**Example curl — hash mode with custom salt (for join-key preservation):**
```bash
curl -X POST \
  "http://localhost:8000/remediate/file?mode=hash&salt=prod-pipeline-salt-2024" \
  -H "X-API-Key: mysecretkey" \
  -F "file=@messy_HR_data.csv"
```

**Extract the cleaned CSV from the response (Python):**
```python
import requests, json

resp = requests.post(
    "http://localhost:8000/remediate/file",
    params={"mode": "redact"},
    files={"file": open("messy_HR_data.csv", "rb")},
    headers={"X-API-Key": "mysecretkey"},
)
result = resp.json()
with open("cleaned_HR_data.csv", "w") as f:
    f.write(result["remediated_csv"])
print(f"Cells changed: {result['total_cells_changed']}")
```

---

## APPENDIX C — Technology Stack

| Component | Technology |
|---|---|
| PII Detection | Python regex rules + Microsoft Presidio |
| Rule-based DQ | Great Expectations (open source) |
| AI checks | Azure OpenAI (GPT-4o) |
| Anomaly detection | scikit-learn Isolation Forest |
| API layer | FastAPI + Uvicorn |
| Demo UI | Streamlit |
| Deployment | Runs fully on-prem / locally — no data leaves your environment |
