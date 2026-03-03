"""
contact.py - Opens the user's default mail app pre-filled with a help request.
"""

import re
import urllib.parse
import webbrowser

from modules.verdict import coerce_verdict_fields

# Basic RFC-5321 sanity check: local@domain.tld
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(address: str) -> bool:
    """Return True if *address* looks like a plausible email address."""
    return bool(_EMAIL_RE.match(address.strip()))


def compose_message(scan_result: dict) -> tuple[str, str]:
    """Return (subject, body) for the help-request email."""
    verdict = coerce_verdict_fields(scan_result)
    risk = verdict.get("overall_risk", "unknown")
    score = verdict.get("risk_score")
    confidence = str(verdict.get("confidence", "")).strip().title()
    summary = str(verdict.get("verdict_summary", "")).strip()
    scan_type = scan_result.get("type", "file")

    # Include the scored verdict when available so the trusted contact can
    # quickly triage urgency without opening the app.
    verdict_parts = []
    if isinstance(score, int):
        verdict_parts.append(f"Risk score: {score}/100")
    if confidence:
        verdict_parts.append(f"Confidence: {confidence}")
    verdict_line = f"Assessment: {' | '.join(verdict_parts)}\n" if verdict_parts else ""
    summary_line = f"Summary: {summary}\n" if summary else ""

    if scan_type == "file":
        name = scan_result.get("filename", "a file")
        subject = f"[Secure File Advisor] Can you help me check this file? — {name}"
        body = (
            f"Hello,\n\n"
            f"I'm using Secure File Advisor and it flagged something I need help with.\n\n"
            f"File name: {name}\n"
            f"Risk level: {risk.upper()}\n\n"
            f"{verdict_line}"
            f"{summary_line}"
            f"Findings:\n"
        )
    elif scan_type == "email":
        sender = scan_result.get("sender", "unknown sender")
        email_subject = scan_result.get("subject", "(no subject)")
        subject = f"[Secure File Advisor] Can you help me check this email? — from {sender}"
        body = (
            f"Hello,\n\n"
            f"I'm using Secure File Advisor and it flagged an email I need help with.\n\n"
            f"Email from: {sender}\n"
            f"Email subject: {email_subject}\n"
            f"Risk level: {risk.upper()}\n\n"
            f"{verdict_line}"
            f"{summary_line}"
            f"Findings:\n"
        )
    else:
        url = scan_result.get("url", "a website")
        subject = f"[Secure File Advisor] Can you help me check this website? — {url}"
        body = (
            f"Hello,\n\n"
            f"I'm using Secure File Advisor and it flagged a website I need help with.\n\n"
            f"Website: {url}\n"
            f"Risk level: {risk.upper()}\n\n"
            f"{verdict_line}"
            f"{summary_line}"
            f"Findings:\n"
        )

    for finding in scan_result.get("findings", []):
        body += f"\n• {finding['title']}\n  {finding['detail']}\n"

    body += "\nCould you please take a look and let me know if it's safe?\n\nThank you!"
    return subject, body


def open_mailto(to_email: str, subject: str, body: str) -> bool:
    """Open the system's default mail app with a pre-composed message.

    Returns True if the mailto link was opened successfully, False if the
    email address failed basic validation.
    """
    if not is_valid_email(to_email):
        return False
    params = urllib.parse.urlencode({"subject": subject, "body": body})
    mailto = f"mailto:{to_email}?{params}"
    webbrowser.open(mailto)
    return True
