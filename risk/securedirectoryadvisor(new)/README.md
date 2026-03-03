# Secure Directory Advisor

Desktop safety assistant focused on non-technical users.

It checks files and websites before opening and explains results in plain
language, with optional online threat-intel lookups.

## Features

- File scanning with extension/name heuristics
- URL scanning with suspicious-pattern and lookalike-domain checks
- Email scanning with phishing/attachment checks and SPF/DKIM/DMARC signals
- IMAP OAuth2 auth modes for Google, Microsoft, and Yahoo (XOAUTH2)
- Optional VirusTotal file reputation lookups
- Optional Google Safe Browsing URL checks
- Automatic downloads-folder monitoring
- Trusted-contact email escalation
- SQLite-backed scan history with risk score and confidence
- Shareable risk report (view/copy)
- Settings/help UX aimed at accessibility

## Requirements

- Python 3.10+
- Standard library for core app
- Optional extras in [requirements.txt](requirements.txt):
  - `keyring` (secure API-key storage)
  - `send2trash` (safe delete to recycle bin/trash)

## Run

```bash
cd /path/to/securedirectoryadvisor
python main.py
```

## Verdict Metadata

Each scan now returns:

- `overall_risk`: `safe|caution|danger`
- `risk_score`: `0-100`
- `confidence`: `low|medium|high`
- `verdict_summary`: one-line plain-English summary

This metadata is deterministic and documented in
[docs/RISK_SCORING.md](docs/RISK_SCORING.md).

## Project Docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ROADMAP.md](ROADMAP.md)
- [PHASE1_CHECKLIST.md](PHASE1_CHECKLIST.md)
- [docs/API_CONTRACT.md](docs/API_CONTRACT.md)
- [docs/RISK_SCORING.md](docs/RISK_SCORING.md)
- [docs/RISK_REPORTING.md](docs/RISK_REPORTING.md)
- [docs/QUALITY_HARNESS.md](docs/QUALITY_HARNESS.md)

## Privacy Notes

- Runs locally on your machine.
- File content is not uploaded by default.
- If configured, external checks may send file hashes and URLs to providers.

This tool is a helper, not a full antivirus replacement.

## Quality Harness (in development)

Run deterministic regression checks:

```bash
python -m harness.regression_harness
```

Run benchmark checks :

```bash
python -m harness.benchmark_harness
```

Create or refresh a benchmark baseline:

```bash
python -m harness.benchmark_harness --write-baseline
```

Generate per-release quality metrics:

```bash
python -m harness.quality_metrics_pipeline --run-inputs
```

Run the full quality gate (compile + regression + benchmark + metrics):

```bash
python -m harness.quality_gate
```

Detailed usage is documented in [docs/QUALITY_HARNESS.md](docs/QUALITY_HARNESS.md).
