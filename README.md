# PreIngestionPIITool

PreIngestionPIITool scans local files for potential PII and produces cloud-ready remediated outputs.

It combines:
- Regex rules for structured PII detection
- Microsoft Presidio NLP detection for free text
- Streamlit UI for multi-file upload, scan, review, and export

## Features

- Multi-file upload (`csv`, `json`, `parquet`, `txt`, `xlsx`, `xls`)
- ZIP ingestion (scan many files from one archive)
- Risk and finding summaries
- Per-file status and findings tabs
- Cloud remediation strategies:
  - Redact
  - Mask keep last 4 (for compatible numeric patterns)
  - Hash tokenize (deterministic with salt)
- Strict fallback options to catch misses in narrative text
- Downloadable outputs:
  - `pii_findings.csv`
  - `cloud_ready_outputs.zip`
  - `remediation_report.csv` (inside ZIP)

## Project Files

- `app.py`: Streamlit front-end
- `scanner.py`: core scan logic (regex + Presidio)
- `patterns.py`: regex patterns and mapping metadata
- `run_scan.py`: CLI-style local scan entry point

## Requirements

Install dependencies:

```powershell
pip install -r requirements.txt
```

If you see missing model/component errors from Presidio, install spaCy English model:

```powershell
python -m spacy download en_core_web_lg
```

If `en_core_web_lg` is not available in your environment, use:

```powershell
python -m spacy download en_core_web_sm
```

## Run Streamlit UI

```powershell
streamlit run .\app.py
```

Open the local URL shown in terminal (typically `http://localhost:8501`).

## Typical Workflow

1. Upload files directly or upload ZIP archives.
2. Enable scan/remediation options.
3. Click **Scan**.
4. Review:
   - Risk summary
   - Top findings
   - Per-file scan status
   - Per-file findings tabs
5. Download:
   - Findings CSV
   - Cloud-ready ZIP outputs

## Remediation Options

### Strategy

- **Redact**: Replace detected values with `<PII_REDACT:TYPE>` style tokens.
- **Mask keep last 4**: Preserve only last 4 digits where applicable.
- **Hash tokenize**: Deterministic pseudonymization token using SHA-256 and your salt.

### Strict fallback controls

- **Missed names in narrative text**
- **Missed locations in narrative text**
- **Common PII patterns** (email, phone, SSN, card-like, account/routing contextual, EIN, IP)
- **Contextual date fallback** (DOB/birth context)

Use strict fallbacks for pre-cloud hardening, and review remediation report for precision.

## Output Artifacts

- `pii_findings.csv`: finding-level output from current scan.
- `cloud_ready_outputs.zip`:
  - remediated file per input (`*_cloud_ready.ext`)
  - `anonymization_manifest.json`
  - `remediation_report.csv` with row-level replacement counts by file/column/pattern.

## Notes

- All scanning/remediation runs locally unless you deploy the app elsewhere.
- Presidio/NLP detection may still have false positives/false negatives; strict fallback options improve recall in narrative text.

## Troubleshooting

### `streamlit run .\app.py` exits with code 1

Run dependency install first:

```powershell
pip install -r requirements.txt
```

Then run again:

```powershell
streamlit run .\app.py
```

### `gh` not found in PowerShell

Use full path (if GitHub CLI installed):

```powershell
& "C:\Program Files\GitHub CLI\gh.exe" --version
```

### Git identity warning on commit

Set identity once:

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```
