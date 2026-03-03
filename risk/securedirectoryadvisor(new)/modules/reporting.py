"""
reporting.py - Generate a user-facing risk report from a scan result.

Phase-1 goal:
- Keep the report *deterministic* and *explainable*.
- Use familiar risk-reporting principles found in common frameworks:
  - NIST-style: Identify, Protect, Detect, Respond, Recover
  - ISO-style: Risk identification, analysis (likelihood/impact), evaluation, treatment

We intentionally do NOT try to be "compliant" with any standard here. Instead,
we borrow the reporting structure so results are easier to understand and share.
"""

from __future__ import annotations

from datetime import datetime

from modules.verdict import RISK_SAFE, RISK_CAUTION, RISK_DANGER, coerce_verdict_fields


def build_risk_report(scan_result: dict) -> dict:
    """Return a report payload to attach to scan results.

    Returns:
      {
        "frameworks": [ ... ],
        "text": "plain text report"
      }
    """
    scan_type = str(scan_result.get("type", "")).lower()
    verdict = coerce_verdict_fields(scan_result)
    overall_risk = str(verdict.get("overall_risk", RISK_CAUTION)).lower()
    score = verdict.get("risk_score")
    confidence = str(verdict.get("confidence", "")).strip().lower()
    scanned_at = scan_result.get("scanned_at") or datetime.now().isoformat()

    likelihood = _estimate_likelihood(overall_risk, score)
    impact = _estimate_impact(scan_type, scan_result)
    treatment = _recommended_treatment(overall_risk)

    title = "Secure Directory Advisor - Risk Report"
    target = _target_line(scan_type, scan_result)
    findings = scan_result.get("findings", []) or []

    lines: list[str] = []
    lines.append(title)
    lines.append(f"Scanned at: {scanned_at}")
    lines.append(target)
    lines.append("")

    # Summary section: quick triage for non-technical users.
    lines.append("Summary")
    lines.append(f"- Overall risk: {overall_risk.upper()}")
    if isinstance(score, int):
        lines.append(f"- Risk score: {score}/100")
    if confidence:
        lines.append(f"- Confidence: {confidence.upper()}")
    summary = str(verdict.get("verdict_summary", "")).strip()
    if summary:
        lines.append(f"- Notes: {summary}")
    lines.append("")

    # ISO-style risk analysis: likelihood and impact are the two basic dimensions.
    lines.append("Risk analysis (ISO-style)")
    lines.append(f"- Likelihood: {likelihood}")
    lines.append(f"- Impact: {impact}")
    lines.append(f"- Suggested treatment: {treatment}")
    lines.append("")

    # Evidence section: what the app actually saw.
    lines.append("Evidence (what we observed)")
    if not findings:
        lines.append("- No detailed findings were recorded.")
    else:
        for finding in findings:
            risk = str(finding.get("risk", RISK_CAUTION)).upper()
            title = str(finding.get("title", "")).strip()
            detail = str(finding.get("detail", "")).strip()
            if title:
                lines.append(f"- [{risk}] {title}")
            if detail:
                # Indent detail as a continuation line for readability.
                lines.append(f"    {detail}")
    lines.append("")

    # NIST CSF-inspired actions. These are framed as user actions, not controls.
    lines.append("Recommended actions (NIST CSF-style)")
    actions = _recommended_actions(scan_type, overall_risk)
    lines.append(f"- Identify: {actions['identify']}")
    lines.append(f"- Protect:  {actions['protect']}")
    lines.append(f"- Detect:   {actions['detect']}")
    lines.append(f"- Respond:  {actions['respond']}")
    lines.append(f"- Recover:  {actions['recover']}")
    lines.append("")

    # Report limitations: avoid false assurance.
    lines.append("Limitations")
    lines.append("- This is a helper report based on heuristics and optional online checks.")
    lines.append("- It cannot guarantee a file/site is safe. Use updated antivirus and safe browsing habits.")

    return {
        "frameworks": [
            "NIST CSF-style (Identify/Protect/Detect/Respond/Recover)",
            "ISO-style (risk identification/analysis/evaluation/treatment)",
        ],
        "text": "\n".join(lines),
    }


def _target_line(scan_type: str, scan_result: dict) -> str:
    if scan_type == "file":
        name = scan_result.get("filename") or "(unknown file)"
        size = scan_result.get("file_size") or ""
        sha256 = scan_result.get("file_hash") or ""
        parts = [f"File: {name}"]
        if size:
            parts.append(f"Size: {size}")
        if sha256:
            parts.append(f"SHA-256: {sha256}")
        return " | ".join(parts)
    if scan_type == "email":
        sender = scan_result.get("sender") or "(unknown sender)"
        subject = scan_result.get("subject") or "(no subject)"
        parts = [f"Email from: {sender}", f"Subject: {subject}"]
        att_count = scan_result.get("attachment_count", 0)
        url_count = scan_result.get("url_count", 0)
        if att_count:
            parts.append(f"Attachments: {att_count}")
        if url_count:
            parts.append(f"Links: {url_count}")
        return " | ".join(parts)
    url = scan_result.get("url") or "(unknown url)"
    return f"Website: {url}"


def _estimate_likelihood(overall_risk: str, score) -> str:
    # Likelihood: how likely the item is malicious or unsafe.
    # We derive this from the score because Phase-1 has no behavioral telemetry.
    if overall_risk == RISK_DANGER:
        return "High"
    if overall_risk == RISK_CAUTION:
        return "Medium"
    if isinstance(score, int) and score >= 25:
        return "Medium"
    return "Low"


def _estimate_impact(scan_type: str, scan_result: dict) -> str:
    # Impact: if this is malicious, how bad could it be?
    if scan_type == "file":
        ext = str(scan_result.get("ext", "")).lower()
        if ext in {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr"}:
            return "High (can execute code)"
        if ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf"}:
            return "Medium (documents can contain risky content)"
        if ext in {".zip", ".rar", ".7z", ".tar", ".gz"}:
            return "Medium (archives can hide other files)"
        if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".wav", ".mov", ".mkv"}:
            return "Low (usually non-executable)"
        return "Medium (unknown file type)"

    if scan_type == "email":
        att_count = scan_result.get("attachment_count", 0)
        if att_count > 0:
            return "High (email contains attachments that could be harmful)"
        return "Medium (could be phishing or credential theft)"

    # For URLs, impact often depends on whether the user might enter credentials/payment info.
    return "Medium (could be phishing or a scam)"


def _recommended_treatment(overall_risk: str) -> str:
    # ISO 31000-style treatment labels (avoid / mitigate / transfer / accept).
    if overall_risk == RISK_DANGER:
        return "Avoid (do not open/visit)"
    if overall_risk == RISK_CAUTION:
        return "Mitigate (verify before opening/visiting)"
    return "Accept with care (only if expected)"


def _recommended_actions(scan_type: str, overall_risk: str) -> dict:
    # These are written for end users. Keep them short and action-oriented.
    if overall_risk == RISK_DANGER:
        identify = "Confirm who sent it and why. If unexpected, treat as suspicious."
        protect = "Do not open it. Consider deleting/quarantining it. Keep antivirus updated."
        detect = "Watch for follow-up emails/texts pushing urgency or asking for passwords."
        respond = "Ask a trusted contact to verify. If you already opened it, disconnect from the internet and run a full scan."
        recover = "If something changed, restore from backups and change passwords from a safe device."
    elif overall_risk == RISK_CAUTION:
        identify = "Check the sender and whether you were expecting this."
        protect = "Scan with antivirus. Open only after verification."
        detect = "Look for spelling mistakes, urgency, or requests for personal information."
        respond = "If unsure, ask a trusted contact before proceeding."
        recover = "If you entered passwords, change them and enable 2-factor authentication."
    else:
        identify = "Make sure the source is someone/site you trust."
        protect = "Keep your system and antivirus up to date."
        detect = "Be cautious if the site/file asks for passwords or payment info."
        respond = "If anything feels wrong, stop and ask for help."
        recover = "Keep backups so you can recover from accidental issues."

    # Slightly tailor language for URL vs file.
    if scan_type == "url":
        protect = protect.replace("open it", "visit it")
    elif scan_type == "email":
        protect = protect.replace("open it", "interact with it")
        respond = respond.replace("already opened it", "already clicked a link or opened an attachment")
    return {
        "identify": identify,
        "protect": protect,
        "detect": detect,
        "respond": respond,
        "recover": recover,
    }
