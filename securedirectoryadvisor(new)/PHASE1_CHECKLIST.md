# Phase 1 Checklist

This checklist is a practical "done" definition for Phase 1.

## Product

- [x] File scan workflow works (manual + auto-monitor)
- [x] URL scan workflow works
- [x] Results are explainable in plain English
- [x] Trusted-contact escalation includes score/confidence
- [x] Risk report is viewable and copyable

## Risk Reporting

- [x] Scan results include `risk_score`, `confidence`, `verdict_summary`
- [x] Scan results include `risk_report` (plain-text, shareable)
- [x] Report structure follows NIST/ISO-inspired principles (not compliance)
- [ ] PCASP report mapping added (needs clarification on which "PCASP" reference you mean)

## Reliability

- [x] Config writes are thread-safe and atomic
- [x] Download monitoring waits for stable files and stops cleanly
- [x] UI callbacks are safe during shutdown (`_safe_after`)

## UX

- [x] Settings tab scrolls when window is small
- [x] Downloads-folder Info help text exists (menu + inline button)

## Dev

- [x] `py_compile` passes on all modules
- [x] Docs exist: architecture, roadmap, API contract, scoring, reporting
