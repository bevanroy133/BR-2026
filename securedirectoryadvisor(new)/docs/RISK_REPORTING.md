# Risk Reporting (Phase 1)

The app produces a shareable, plain-text "Risk Report" for each scan.

## Goals

- Be understandable to non-technical users.
- Be explainable: tie the report directly back to observed findings.
- Use a reporting structure inspired by common security frameworks:
  - NIST CSF-style actions: Identify / Protect / Detect / Respond / Recover
  - ISO-style risk process: identify, analyze (likelihood/impact), evaluate, treat

This is **not** a compliance report.

## Report Sections

- Summary
  - Overall risk, risk score, confidence, plain-English summary
- Risk analysis (ISO-style)
  - Likelihood (low/medium/high)
  - Impact (low/medium/high, with a short explanation)
  - Suggested treatment (avoid/mitigate/accept)
- Evidence (what we observed)
  - A list of findings with severity and details
- Recommended actions (NIST CSF-style)
  - Identify: verify sender/source and expectations
  - Protect: safe default actions (do not open, scan with antivirus, etc.)
  - Detect: warning signs to watch for (urgency, credential requests)
  - Respond: what to do if already clicked/opened
  - Recover: backup/password hygiene
- Limitations

## Where it's used

- UI "View Report" / "Copy Report" actions.
- Intended for sharing with a trusted contact when needed.
