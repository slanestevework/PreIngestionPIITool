# PreIngestionPIITool

PreIngestionPIITool scans local files for potential PII and produces cloud-ready remediated outputs.

It combines:
- Regex rules for structured PII detection
- Microsoft Presidio NLP detection for free text
- Streamlit UI for multi-file upload, scan, review, and export
- FastAPI service for on-prem API integration (for example, Copilot Studio custom connectors)

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
- `api.py`: FastAPI service exposing scan endpoints
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

## Run API Service

```powershell
uvicorn api:app --host 0.0.0.0 --port 8000
```

OpenAPI docs:

- `http://localhost:8000/docs`
- `http://localhost:8000/openapi.json`

Optional API key protection:

```powershell
$env:PII_SCANNER_API_KEY = "change-me"
uvicorn api:app --host 0.0.0.0 --port 8000
```

When `PII_SCANNER_API_KEY` is set, include header `x-api-key: <value>` in requests.

## API Endpoints

- `GET /health`
  - Returns service status.

- `POST /scan/records`
  - Request body:

```json
{
  "source_name": "customers.json",
  "records": [
    {"name": "John Smith", "email": "john@example.com", "phone": "6155551212"}
  ]
}
```

- `POST /scan/text`
  - Request body:

```json
{
  "source_name": "notes.txt",
  "column_name": "value",
  "text": "Patient Jane Doe called from 123 Main Street Nashville TN 37201"
}
```

- `POST /scan/file`
  - Multipart upload field: `file`
  - Supported extensions: `csv`, `json`, `parquet`, `txt`, `xlsx`, `xls`

Response for all scan endpoints:

```json
{
  "source": "customers.json",
  "stats": {
    "source": "customers.json",
    "columns_scanned": 3,
    "findings": 2
  },
  "findings": [
    {
      "source": "customers.json",
      "column": "email",
      "pattern": "email",
      "risk": "CRITICAL",
      "detection_source": "REGEX_RULE"
    }
  ]
}
```

## Quick API Smoke Test

Health check:

```powershell
curl http://localhost:8000/health
```

Records scan:

```powershell
curl -X POST "http://localhost:8000/scan/records" \
  -H "Content-Type: application/json" \
  -d '{"source_name":"sample.json","records":[{"name":"Jane Doe","email":"jane@example.com","ssn":"123-45-6789"}]}'
```

File scan:

```powershell
curl -X POST "http://localhost:8000/scan/file" \
  -F "file=@data/sample_pii.csv"
```

## RHEL Deployment (Recommended)

Use `gunicorn` with `uvicorn` workers behind your internal reverse proxy.

1. Create and activate Python environment.
2. Install dependencies:

```bash
pip install -r requirements.txt gunicorn
```

3. Start service:

```bash
PII_SCANNER_API_KEY='change-me' \
gunicorn -w 2 -k uvicorn.workers.UvicornWorker api:app --bind 0.0.0.0:8000
```

4. Put NGINX/Apache in front with TLS and IP allow-listing.
5. Configure your Copilot Studio connector to call this API and send the API key header.

### Minimal systemd unit example

```ini
[Unit]
Description=PII Scanner API
After=network.target

[Service]
User=piiapi
WorkingDirectory=/opt/pii_scanner
Environment=PII_SCANNER_API_KEY=change-me
ExecStart=/opt/pii_scanner/.venv/bin/gunicorn -w 2 -k uvicorn.workers.UvicornWorker api:app --bind 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
```

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
