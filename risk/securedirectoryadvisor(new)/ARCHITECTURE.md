# Secure Directory Advisor - Target Architecture

This document defines the practical target architecture for evolving the app
from a single-process desktop utility into a stronger security product.

**Related docs:** [API Contract](docs/API_CONTRACT.md) · [Risk Scoring](docs/RISK_SCORING.md) · [Risk Reporting](docs/RISK_REPORTING.md) · [Roadmap](ROADMAP.md) · [Phase 1 Checklist](PHASE1_CHECKLIST.md)

## 1) Current (this repo)

- UI: `tkinter` in [`modules/ui.py`](modules/ui.py)
- Detection: rule-based checks in [`modules/analyzer.py`](modules/analyzer.py)
- Provider adapters: pluggable external-provider boundary with retries in [`modules/provider_adapters.py`](modules/provider_adapters.py)
- Domain intel: Tranco-based typosquat/lookalike detection in [`modules/domain_db.py`](modules/domain_db.py)
- Email analysis: phishing/scam + sender-authentication checks (SPF/DKIM/DMARC) in [`modules/email_analyzer.py`](modules/email_analyzer.py)
- Monitoring: polling watcher in [`modules/monitor.py`](modules/monitor.py)
- Email monitoring: IMAP inbox poller in [`modules/email_monitor.py`](modules/email_monitor.py)
- Trusted-contact escalation: pre-filled help-request email in [`modules/contact.py`](modules/contact.py)
- Email auth adapters: unified OAuth provider registry in [`modules/provider_adapters.py`](modules/provider_adapters.py)
- Email auth runtime: OAuth2 flow/token/XOAUTH2 helpers in [`modules/google_oauth.py`](modules/google_oauth.py)
- Persistence: JSON config in [`modules/config.py`](modules/config.py) + SQLite scan history in [`modules/history_store.py`](modules/history_store.py)

## 2) Near-Term Architecture (Phase 1)

Phase 1 is largely implemented. Keep the current stack and enforce clear internal boundaries:

- `UI layer`
  - Responsible only for user interactions and rendering.
  - Never computes risk logic directly.
- `Analyzer layer`
  - Produces raw findings from file, URL, and email checks.
  - Integrates optional external providers (VirusTotal, Google Safe Browsing).
  - Uses `domain_db` for typosquat/lookalike detection.
- `Verdict layer` ([`modules/verdict.py`](modules/verdict.py))
  - Converts findings into:
    - `overall_risk`
    - `risk_score` (0-100)
    - `confidence` (`low|medium|high`)
    - `verdict_summary`
    - `signal_titles` (top evidence labels)
- `Reporting layer` ([`modules/reporting.py`](modules/reporting.py))
  - Generates a shareable, plain-text risk report for users/caregivers.
- `Storage layer` ([`modules/config.py`](modules/config.py))
  - Config: user settings, API keys (keychain when available), trusted contact.
  - Scan history: last 100 results via `add_scan_history()`.
  - Should not embed UI assumptions.

## 3) Scalable Target (Phase 2+)

When moving to a richer stack (Tauri/Electron + web UI), keep the same logical
boundaries and expose the analyzer via explicit contracts:

- **Desktop client** (React/Tauri/Electron): thin UI that calls the local scan service; no risk logic.
- **Local scan service** (Rust/Go/Python): exposes a REST or gRPC API for file/URL/email scans.
- **Optional cloud intel service**: feeds (threat intel, blocklists), telemetry aggregation, policy sync for managed deployments.

## 4) Design Rules

- Deterministic verdicting first; no opaque model-only decisions.
- Every verdict must include explainable evidence.
- Provider outages (VirusTotal, Google Safe Browsing, etc.) must degrade gracefully: no crashes, clear fallback behavior.
- History schema must remain backward compatible: additive-only fields; `coerce_verdict_fields()` backfills missing verdict metadata for older entries.

## 5) Data Flow

1. User submits file/URL/email (or monitor detects new download, or email monitor detects new inbox message).
2. Analyzer generates findings (file-, URL-, or email-specific checks).
3. Verdict layer scores findings and sets confidence.
4. UI displays verdict + explanations.
5. Result is persisted via `config.add_scan_history()`.

Manual scans and monitor-triggered scans follow the same flow; the monitor only differs in how the input is obtained.
