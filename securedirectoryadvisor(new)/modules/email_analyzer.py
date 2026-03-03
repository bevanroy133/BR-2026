"""
email_analyzer.py - Security analysis for email messages.

Checks emails for common phishing indicators, suspicious senders,
dangerous attachments, sender-authentication signals (SPF/DKIM/DMARC),
and suspicious links. Uses the same risk model (safe/caution/danger)
and verdict pipeline as file and URL analysis.
"""

import email
import email.header
import email.policy
import email.utils
import logging
import os
import re
import urllib.parse
from datetime import datetime
from html.parser import HTMLParser

from modules.analyzer import (
    DANGEROUS_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    SCAM_URL_KEYWORDS,
    TRUSTED_DOMAINS,
    RISK_SAFE,
    RISK_CAUTION,
    RISK_DANGER,
    _higher_risk,
    _check_lookalike,
    check_google_safe_browsing,
)
from modules.verdict import build_verdict
from modules.reporting import build_risk_report

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phishing / social engineering keyword sets
# ---------------------------------------------------------------------------
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "action required", "suspend",
    "expire", "expiring", "locked", "compromised", "unauthorized",
    "verify your", "confirm your", "update your", "validate your",
    "within 24 hours", "within 48 hours", "limited time",
    "final notice", "last warning", "important notice",
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "bank account", "credit card", "social security",
    "tax refund", "irs", "inheritance", "lottery", "prize",
    "bitcoin", "crypto", "investment opportunity", "money transfer",
    "western union", "gift card", "payment required",
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "sign in", "sign-in", "username",
    "credentials", "reset your password", "click here to verify",
    "click the link", "click below", "ssn", "date of birth",
]

# Common free email providers often used in impersonation attacks.
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "icloud.com", "live.com",
}

_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

_AUTH_RESULT_PATTERN = re.compile(
    r"\b(dkim|spf|dmarc)\s*=\s*([a-z0-9_-]+)",
    re.IGNORECASE,
)


class _AnchorLinkParser(HTMLParser):
    """Extract <a href> links and visible anchor text from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._current_href = ""
        self._text_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "a":
            return
        href = ""
        for key, value in attrs:
            if key and key.lower() == "href" and value:
                href = value.strip()
                break
        self._current_href = href
        self._text_chunks = []

    def handle_data(self, data: str):
        if self._current_href:
            self._text_chunks.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() != "a":
            return
        if self._current_href:
            text = " ".join(self._text_chunks).strip()
            self.links.append({"href": self._current_href, "text": text})
        self._current_href = ""
        self._text_chunks = []


def _decode_bytes(payload: bytes, charset: str | None) -> str:
    """Decode bytes safely even if the declared charset is invalid."""
    encodings: list[str] = []
    if charset:
        encodings.append(charset)
    encodings.extend(["utf-8", "latin-1"])
    for enc in encodings:
        try:
            return payload.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def _decode_header(raw: str | None) -> str:
    """Decode an RFC 2047 encoded header into a plain string."""
    if not raw:
        return ""
    parts = email.header.decode_header(raw)
    decoded = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded.append(_decode_bytes(data, charset))
        else:
            decoded.append(data)
    return " ".join(decoded).strip()


def _extract_body_text(msg: email.message.Message) -> str:
    """Walk MIME parts and return concatenated plain-text body."""
    texts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    texts.append(_decode_bytes(payload, charset))
            elif ct == "text/html" and not texts:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html = _decode_bytes(payload, charset)
                    texts.append(re.sub(r"<[^>]+>", " ", html))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = _decode_bytes(payload, charset)
            if msg.get_content_type() == "text/html":
                text = re.sub(r"<[^>]+>", " ", text)
            texts.append(text)
    return "\n".join(texts)


def _extract_urls(text: str) -> list[str]:
    """Pull all http/https URLs out of a text body."""
    return _URL_PATTERN.findall(text)


def _extract_html_links(msg: email.message.Message) -> list[dict]:
    """Return [{"href": "...", "text": "..."}] for HTML anchor links."""
    links: list[dict] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_type() != "text/html":
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        html = _decode_bytes(payload, charset)
        parser = _AnchorLinkParser()
        try:
            parser.feed(html)
        except Exception:
            continue
        links.extend(parser.links)
    return links


def _normalize_http_url(value: str) -> str:
    """Normalize candidate URL and keep only absolute http/https links."""
    if not value:
        return ""
    url = value.strip().strip("<>\"'()[]")
    if url.startswith("//"):
        url = "https:" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return url
    return ""


def _url_hostname(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return (parsed.hostname or "").lower().removeprefix("www.")


def _is_trusted_host(hostname: str) -> bool:
    if not hostname:
        return False
    return any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)


def _same_or_subdomain(host_a: str, host_b: str) -> bool:
    return (
        host_a == host_b
        or host_a.endswith("." + host_b)
        or host_b.endswith("." + host_a)
    )


def _collect_message_urls(msg: email.message.Message, body_text: str) -> tuple[list[str], list[dict]]:
    """Collect normalized URLs and possible deceptive HTML link pairs."""
    urls: list[str] = []
    seen: set[str] = set()

    for raw in _extract_urls(body_text):
        normalized = _normalize_http_url(raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)

    deceptive_links: list[dict] = []
    for link in _extract_html_links(msg):
        href = _normalize_http_url(str(link.get("href", "")))
        if href and href not in seen:
            seen.add(href)
            urls.append(href)

        shown_urls = _extract_urls(str(link.get("text", "")))
        if not href or not shown_urls:
            continue

        shown = _normalize_http_url(shown_urls[0])
        if not shown:
            continue

        shown_host = _url_hostname(shown)
        actual_host = _url_hostname(href)
        if shown_host and actual_host and not _same_or_subdomain(shown_host, actual_host):
            deceptive_links.append({
                "shown_url": shown,
                "actual_url": href,
                "shown_host": shown_host,
                "actual_host": actual_host,
            })

    return urls, deceptive_links


def _merge_auth_results(current: str, incoming: str) -> str:
    if incoming in {"pass", "bestguesspass"}:
        return "pass"
    if current == "pass":
        return current
    if incoming == "fail":
        return "fail"
    if current == "fail":
        return current
    if incoming in {"temperror", "permerror"}:
        return "error"
    if current == "error":
        return current
    if incoming == "softfail":
        return "softfail"
    if current == "softfail":
        return current
    if incoming == "neutral":
        return "neutral"
    if current == "neutral":
        return current
    if incoming == "none":
        return "none"
    return current


def _extract_sender_auth_results(msg: email.message.Message) -> dict:
    """Best-effort parse of SPF/DKIM/DMARC results from received headers."""
    auth = {"spf": "", "dkim": "", "dmarc": ""}

    for raw in msg.get_all("Authentication-Results", []):
        text = str(raw).lower()
        for mechanism, value in _AUTH_RESULT_PATTERN.findall(text):
            mech = mechanism.lower()
            auth[mech] = _merge_auth_results(auth[mech], value.lower())

    for raw in msg.get_all("Received-SPF", []):
        text = str(raw).strip().lower()
        match = re.match(r"^([a-z0-9_-]+)", text)
        if match:
            auth["spf"] = _merge_auth_results(auth["spf"], match.group(1))

    return auth


def _extract_attachments(msg: email.message.Message) -> list[dict]:
    """Return metadata for every attachment in the message."""
    attachments: list[dict] = []
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition.lower() or part.get_filename():
            filename = _decode_header(part.get_filename()) or "(unnamed)"
            size = len(part.get_payload(decode=True) or b"")
            _, ext = os.path.splitext(filename.lower())
            attachments.append({
                "filename": filename,
                "ext": ext,
                "size": size,
                "content_type": part.get_content_type(),
            })
    return attachments


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------
def analyze_email_message(
    raw_email: bytes | str,
    *,
    gsb_api_key: str = "",
    vt_api_key: str = "",
    message_uid: str = "",
) -> dict:
    """Analyze a raw email (bytes or string) for security threats.

    Returns a result dict matching the same schema as analyze_file / analyze_url
    (type, findings, overall_risk, verdict, report).
    """
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8", errors="replace")

    msg = email.message_from_bytes(raw_email, policy=email.policy.default)

    subject = _decode_header(msg.get("Subject"))
    from_header = _decode_header(msg.get("From"))
    to_header = _decode_header(msg.get("To"))
    date_header = _decode_header(msg.get("Date"))
    reply_to = _decode_header(msg.get("Reply-To"))
    return_path = _decode_header(msg.get("Return-Path"))

    sender_name, sender_email = email.utils.parseaddr(from_header)
    sender_email = sender_email.lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    body_text = _extract_body_text(msg)
    body_lower = body_text.lower()
    subject_lower = subject.lower()
    combined_text = f"{subject_lower} {body_lower}"

    urls, deceptive_links = _collect_message_urls(msg, body_text)
    attachments = _extract_attachments(msg)

    findings: list[dict] = []
    overall_risk = RISK_SAFE

    # ------------------------------------------------------------------
    # 1. Sender domain analysis
    # ------------------------------------------------------------------
    if sender_domain:
        lookalike = _check_lookalike(sender_domain)
        if lookalike:
            findings.append({
                "risk": RISK_DANGER,
                "title": "DANGER Sender is impersonating a known brand",
                "detail": (
                    f"The sender domain '{sender_domain}' is very similar to '{lookalike}' "
                    "but is not the real domain. This is a common phishing technique. "
                    "Do not click links or reply to this message."
                ),
            })
            overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # Display-name vs actual-address mismatch (conservative severity).
    display_name_mismatch = False
    if sender_name and sender_email:
        name_lower = sender_name.lower()
        for brand in TRUSTED_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name and brand_name in name_lower and brand not in sender_email:
                display_name_mismatch = True
                mismatch_risk = RISK_DANGER if sender_domain in FREE_EMAIL_PROVIDERS else RISK_CAUTION
                findings.append({
                    "risk": mismatch_risk,
                    "title": (
                        "DANGER Sender name does not match the email address"
                        if mismatch_risk == RISK_DANGER
                        else "CAUTION Sender name may not match the email address"
                    ),
                    "detail": (
                        f"The sender claims to be '{sender_name}' but the address is '{sender_email}'. "
                        "This can be legitimate for some marketing systems, but it is also a "
                        "common phishing pattern. Verify independently before acting."
                    ),
                })
                overall_risk = _higher_risk(overall_risk, mismatch_risk)
                break

    # Reply-To mismatch.
    reply_mismatch = False
    if reply_to:
        _, reply_email = email.utils.parseaddr(reply_to)
        reply_email = reply_email.lower()
        if reply_email and reply_email != sender_email:
            reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
            if reply_domain != sender_domain:
                reply_mismatch = True
                findings.append({
                    "risk": RISK_CAUTION,
                    "title": "CAUTION Reply address differs from sender",
                    "detail": (
                        f"This email was sent from '{sender_email}' but replies go to '{reply_email}'. "
                        "This is sometimes legitimate, but scammers also use it to redirect replies."
                    ),
                })
                overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    # ------------------------------------------------------------------
    # 1b. Sender authentication checks (SPF / DKIM / DMARC)
    # ------------------------------------------------------------------
    auth = _extract_sender_auth_results(msg)
    dmarc_result = auth.get("dmarc", "")
    spf_result = auth.get("spf", "")
    dkim_result = auth.get("dkim", "")

    if dmarc_result == "fail":
        findings.append({
            "risk": RISK_DANGER,
            "title": "DANGER Sender authentication failed (DMARC)",
            "detail": (
                "The message failed DMARC authentication checks. This is a strong sign "
                "the sender identity may be spoofed. Do not click links or open attachments."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif dmarc_result == "pass":
        findings.append({
            "risk": RISK_SAFE,
            "title": "OK Sender authentication passed (DMARC)",
            "detail": (
                "DMARC checks passed for this message. This lowers spoofing risk, "
                "but does not guarantee the content is safe."
            ),
        })
    else:
        if spf_result == "fail" and dkim_result == "fail":
            findings.append({
                "risk": RISK_CAUTION,
                "title": "CAUTION Sender authentication checks failed",
                "detail": (
                    "Both SPF and DKIM checks failed. This can happen for legitimate forwarding, "
                    "but it can also indicate spoofing."
                ),
            })
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
        elif spf_result == "fail" or dkim_result == "fail":
            failed_mech = "SPF" if spf_result == "fail" else "DKIM"
            findings.append({
                "risk": RISK_CAUTION,
                "title": f"CAUTION {failed_mech} authentication failed",
                "detail": (
                    f"{failed_mech} validation failed for this message. This can be benign, "
                    "but treat unexpected requests with extra caution."
                ),
            })
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
        elif spf_result == "pass" and dkim_result == "pass":
            findings.append({
                "risk": RISK_SAFE,
                "title": "OK Sender authentication passed (SPF + DKIM)",
                "detail": (
                    "SPF and DKIM checks passed. This reduces spoofing risk, but you should "
                    "still verify unusual requests."
                ),
            })

    # ------------------------------------------------------------------
    # 2. Subject and body keyword analysis
    # ------------------------------------------------------------------
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
    financial_hits = [kw for kw in FINANCIAL_KEYWORDS if kw in combined_text]
    credential_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in combined_text]

    if urgency_hits and (financial_hits or credential_hits):
        findings.append({
            "risk": RISK_DANGER,
            "title": "DANGER This email uses high-pressure scam language",
            "detail": (
                f"The email contains urgency words ({', '.join(urgency_hits[:3])}) "
                f"combined with {'financial topics' if financial_hits else 'login credentials'}. "
                "This pattern is common in phishing messages. Do not provide any information."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif urgency_hits:
        findings.append({
            "risk": RISK_CAUTION,
            "title": "CAUTION This email uses urgent language",
            "detail": (
                f"The email contains pressure words ({', '.join(urgency_hits[:3])}). "
                "Legitimate companies rarely require urgent action by email."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    if financial_hits and not urgency_hits:
        findings.append({
            "risk": RISK_CAUTION,
            "title": "CAUTION This email mentions financial topics",
            "detail": (
                f"References to financial matters ({', '.join(financial_hits[:3])}) were found. "
                "Be cautious with any requested financial action."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    if credential_hits and not urgency_hits:
        findings.append({
            "risk": RISK_CAUTION,
            "title": "CAUTION This email asks about login credentials",
            "detail": (
                f"The email mentions credentials ({', '.join(credential_hits[:3])}). "
                "Legitimate services do not ask for passwords by email."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    # ------------------------------------------------------------------
    # 3. Link analysis
    # ------------------------------------------------------------------
    suspicious_urls: list[str] = []
    caution_urls: list[str] = []
    safe_urls: list[str] = []

    for url in urls[:20]:
        url_lower = url.lower()
        host = _url_hostname(url)
        lookalike_target = _check_lookalike(host) if host else None
        has_scam_kw = any(kw in url_lower for kw in SCAM_URL_KEYWORDS)
        is_trusted = _is_trusted_host(host)

        gsb_flagged = False
        if gsb_api_key:
            gsb_flagged = check_google_safe_browsing(url, gsb_api_key)

        if gsb_flagged or lookalike_target or (has_scam_kw and not is_trusted):
            suspicious_urls.append(url)
        elif not host:
            caution_urls.append(url)
        elif not is_trusted:
            caution_urls.append(url)
        else:
            safe_urls.append(url)

    if deceptive_links:
        sample = deceptive_links[0]
        findings.append({
            "risk": RISK_DANGER,
            "title": "DANGER Link text does not match destination",
            "detail": (
                f"A link displayed as '{sample['shown_url']}' actually points to "
                f"'{sample['actual_url']}'. This is a common phishing trick."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    if suspicious_urls:
        findings.append({
            "risk": RISK_DANGER,
            "title": "DANGER Suspicious links found",
            "detail": (
                f"This email contains {len(suspicious_urls)} suspicious link(s). "
                "Do not click these links. "
                f"Example: {suspicious_urls[0][:80]}..."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif caution_urls:
        has_other_risk_signal = bool(
            urgency_hits
            or financial_hits
            or credential_hits
            or display_name_mismatch
            or reply_mismatch
            or dmarc_result == "fail"
            or spf_result == "fail"
            or dkim_result == "fail"
        )
        if has_other_risk_signal:
            findings.append({
                "risk": RISK_CAUTION,
                "title": "CAUTION Links point to unrecognized domains",
                "detail": (
                    f"This email has {len(caution_urls)} link(s) to domains outside our "
                    "trusted set. Because there are other warning signals, verify before clicking."
                ),
            })
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
    elif urls and safe_urls and not suspicious_urls:
        findings.append({
            "risk": RISK_SAFE,
            "title": "OK Links appear to point to expected sites",
            "detail": (
                "The links in this message point to domains that look normal. "
                "Keep normal caution if the request is unexpected."
            ),
        })

    # ------------------------------------------------------------------
    # 4. Attachment analysis
    # ------------------------------------------------------------------
    dangerous_attachments: list[str] = []
    caution_attachments: list[str] = []

    for att in attachments:
        ext = att["ext"]
        name = att["filename"]
        if ext in DANGEROUS_EXTENSIONS or ext in SCRIPT_EXTENSIONS:
            dangerous_attachments.append(name)
        elif ext in ARCHIVE_EXTENSIONS:
            caution_attachments.append(name)

    if dangerous_attachments:
        findings.append({
            "risk": RISK_DANGER,
            "title": "DANGER This email has dangerous attachments",
            "detail": (
                "The following attachment(s) could run programs on your computer: "
                f"{', '.join(dangerous_attachments)}. Do not open these files."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif caution_attachments:
        findings.append({
            "risk": RISK_CAUTION,
            "title": "CAUTION This email has compressed attachments",
            "detail": (
                "The following archive(s) could contain hidden files: "
                f"{', '.join(caution_attachments)}. Open only if expected and verified."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
    elif attachments:
        names = [a["filename"] for a in attachments]
        findings.append({
            "risk": RISK_SAFE,
            "title": "OK Attachments look like common file types",
            "detail": f"Attached files: {', '.join(names)}.",
        })

    # ------------------------------------------------------------------
    # 5. General positive signal if nothing triggered
    # ------------------------------------------------------------------
    if not findings:
        findings.append({
            "risk": RISK_SAFE,
            "title": "OK No obvious warning signs found",
            "detail": (
                "No clear phishing indicators, dangerous attachments, or malicious links "
                "were detected. Stay cautious with unexpected emails."
            ),
        })

    # ------------------------------------------------------------------
    # Build verdict + report
    # ------------------------------------------------------------------
    verdict = build_verdict(findings=findings, initial_risk=overall_risk)
    scanned_at = datetime.now().isoformat()

    result = {
        "type": "email",
        "subject": subject,
        "sender": from_header,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "recipient": to_header,
        "date": date_header,
        "return_path": return_path,
        "message_uid": message_uid,
        "url_count": len(urls),
        "attachment_count": len(attachments),
        "attachments": [a["filename"] for a in attachments],
        "auth_results": auth,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "signal_titles": verdict["signal_titles"],
        "findings": findings,
        "scanned_at": scanned_at,
    }

    # vt_api_key is reserved for future attachment reputation checks.
    _ = vt_api_key

    report = build_risk_report(result)
    result["risk_report"] = report
    return result


def analyze_eml_file(filepath: str, **kwargs) -> dict:
    """Convenience wrapper: analyze a .eml file from disk."""
    with open(filepath, "rb") as f:
        raw = f.read()
    result = analyze_email_message(raw, **kwargs)
    result["filepath"] = filepath
    result["filename"] = os.path.basename(filepath)
    return result
