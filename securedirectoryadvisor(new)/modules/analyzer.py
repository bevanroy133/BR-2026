"""
analyzer.py - Core file and URL risk analysis logic
Uses plain-English, friendly messaging suitable for elderly/non-technical users.
Optionally integrates with VirusTotal and Google Safe Browsing APIs.
"""

import hashlib
import ipaddress
import logging
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from modules.verdict import build_verdict
from modules.reporting import build_risk_report
from modules.domain_db import get_domain_db
from modules.provider_adapters import RetryPolicy, get_file_adapter, get_url_adapter

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------
RISK_SAFE = "safe"
RISK_CAUTION = "caution"
RISK_DANGER = "danger"

_RISK_ORDER = [RISK_SAFE, RISK_CAUTION, RISK_DANGER]

_PROVIDER_RETRY_POLICY = RetryPolicy(
    max_attempts=3,
    initial_delay_s=0.35,
    backoff_multiplier=2.0,
    max_delay_s=2.0,
    jitter_s=0.1,
)
_REACHABILITY_RETRYABLE_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}
_REACHABILITY_MAX_ATTEMPTS = 3
_REACHABILITY_BASE_DELAY_S = 0.25
_REACHABILITY_MAX_DELAY_S = 1.0


def _sleep_with_backoff(attempt: int, base_delay_s: float, max_delay_s: float):
    delay = min(max_delay_s, base_delay_s * (2 ** (attempt - 1)))
    time.sleep(max(0.0, delay))


def _higher_risk(current: str, new: str) -> str:
    """Return whichever risk level is more severe."""
    if _RISK_ORDER.index(new) > _RISK_ORDER.index(current):
        return new
    return current


def _verdict_payload(findings: list[dict], initial_risk: str) -> dict:
    """Translate findings into consistent verdict metadata.

    Keeping this centralized ensures file and URL paths produce the same
    score/confidence contract for the UI and future APIs.
    """
    return build_verdict(findings=findings, initial_risk=initial_risk)


def _invalid_url_result(raw_url: str) -> dict:
    findings = [{
        "risk": RISK_CAUTION,
        "title": "⚠️ We couldn't understand this web address",
        "detail": f"The address '{raw_url}' doesn't look like a normal web address. Please double-check it.",
    }]
    verdict = _verdict_payload(findings, RISK_CAUTION)
    scanned_at = datetime.now().isoformat()
    report = build_risk_report({
        "type": "url",
        "url": raw_url,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "findings": findings,
        "scanned_at": scanned_at,
    })
    return {
        "type": "url",
        "url": raw_url,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "signal_titles": verdict["signal_titles"],
        "risk_report": report,
        "findings": findings,
        "scanned_at": scanned_at,
    }


def _is_valid_hostname(hostname: str) -> bool:
    """Basic host validation for user-entered URLs."""
    if not hostname:
        return False
    if len(hostname) > 253:
        return False
    if any(ch.isspace() for ch in hostname):
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    normalized = hostname[:-1] if hostname.endswith(".") else hostname
    labels = normalized.split(".")
    if any(not label for label in labels):
        return False

    for label in labels:
        if len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    return True


def _is_plausible_web_url(url: str, parsed: urllib.parse.ParseResult) -> bool:
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    if any(ch.isspace() for ch in url):
        return False
    if not _is_valid_hostname(parsed.hostname or ""):
        return False
    try:
        parsed.port
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Extension lists
# ---------------------------------------------------------------------------
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi', '.jar',
    '.scr', '.lnk', '.hta', '.pif', '.com', '.reg', '.wsf',
    '.cpl', '.msc', '.msp', '.gadget', '.application'
}

SCRIPT_EXTENSIONS = {
    '.js', '.jse', '.vbe', '.wsh', '.wsc', '.sh', '.bash',
    '.zsh', '.fish', '.py', '.rb', '.pl', '.php'
}

DOCUMENT_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.ppt', '.pptx', '.txt', '.rtf', '.odt', '.csv'
}

MEDIA_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
}

ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz',
}

SUSPICIOUS_KEYWORDS = [
    'invoice', 'payment', 'urgent', 'update', 'tracking',
    'details', 'confirmation', 'receipt', 'refund', 'verify',
    'account', 'suspended', 'click', 'free', 'prize', 'winner',
    'bank', 'password', 'credential', 'login'
]

SCAM_URL_KEYWORDS = [
    'free', 'winner', 'prize', 'claim', 'urgent', 'verify',
    'suspended', 'confirm', 'unusual', 'limited', 'act-now',
    'click-here', 'login-required', 'update-required'
]

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'bbc.com', 'bbc.co.uk', 'nhs.uk', 'gov.uk',
    'usa.gov', 'irs.gov', 'medicare.gov', 'wikipedia.org',
    'facebook.com', 'gmail.com', 'outlook.com', 'yahoo.com'
}

# ---------------------------------------------------------------------------
# Friendly message templates
# ---------------------------------------------------------------------------
MESSAGES = {
    "double_extension": (
        RISK_DANGER,
        "🛑 This file is trying to trick you!",
        "The file '{name}' is pretending to be a '{fake_ext}' file, but it's actually "
        "a program that could run on your computer. This is a very common trick used by "
        "scammers. Please do NOT open this file. If someone sent it to you, do not reply "
        "— contact a family member or friend for help."
    ),
    "dangerous_extension": (
        RISK_DANGER,
        "🛑 This file could be dangerous",
        "The file '{name}' is a type of program (ending in '{ext}'). Programs can make "
        "changes to your computer — sometimes harmful ones. Unless you were specifically "
        "expecting to install something, it's safest not to open this. Ask a trusted "
        "person before continuing."
    ),
    "script_extension": (
        RISK_DANGER,
        "🛑 This is a script file — be careful",
        "The file '{name}' is a script (ending in '{ext}'). Scripts are like mini-programs "
        "and can change things on your computer. If you didn't ask for this, don't open it. "
        "Ask someone you trust to take a look first."
    ),
    "suspicious_name_danger": (
        RISK_DANGER,
        "⚠️ This looks like it could be a scam file",
        "The file is named '{name}' and uses the word '{keyword}' — scammers often use "
        "urgent-sounding words like this to trick people into opening dangerous files. "
        "Be very cautious."
    ),
    "document_with_macro_risk": (
        RISK_CAUTION,
        "⚠️ This is a document — just double-check before opening",
        "The file '{name}' looks like a normal document, which is usually fine. However, "
        "documents can sometimes contain hidden programs called 'macros'. If your computer "
        "asks you to 'Enable Macros' or 'Enable Content' after opening it — say NO and "
        "close the file. When in doubt, ask a family member."
    ),
    "archive_file": (
        RISK_CAUTION,
        "⚠️ This is a compressed archive — check what's inside",
        "The file '{name}' is a compressed archive (like a folder of files). Archives can "
        "contain anything, including dangerous programs. Don't open files inside it unless "
        "you trust whoever sent it. Ask a family member if you're unsure."
    ),
    "media_or_safe": (
        RISK_SAFE,
        "✅ This file looks safe",
        "The file '{name}' appears to be a {type_description}. This type of file is "
        "generally safe to open. Still, only open files from people or websites you trust."
    ),
    "unknown_extension": (
        RISK_CAUTION,
        "⚠️ We're not sure about this file",
        "The file '{name}' has an unusual type ('{ext}') that we don't recognise. "
        "It might be perfectly fine, but if you weren't expecting it, it's worth asking "
        "someone you trust before opening it."
    ),
    "empty_file": (
        RISK_CAUTION,
        "⚠️ This file appears to be empty",
        "The file '{name}' contains no data at all. An empty file is unusual and may "
        "mean the download didn't finish properly, or that something went wrong. "
        "You can safely delete it and try downloading again if you need it."
    ),
    "suspicious_name_caution": (
        RISK_CAUTION,
        "⚠️ This file has an attention-grabbing name — double-check before opening",
        "The file is named '{name}' and uses the word '{keyword}'. Scammers often use "
        "urgent or exciting words like this to trick people into opening files. If you "
        "weren't expecting this file, it's worth asking someone you trust before opening it."
    ),
    "virustotal_clean": (
        RISK_SAFE,
        "✅ Checked with security services — looks clean",
        "We checked this file against online security databases and no threats were found. "
        "That's a good sign, though it's still best to only open files you were expecting."
    ),
    "virustotal_detected": (
        RISK_DANGER,
        "🛑 Security services flagged this file!",
        "We checked this file against online security databases and {count} security "
        "service(s) flagged it as potentially harmful. Do NOT open this file. "
        "You should delete it and let a trusted person know."
    ),
}

URL_MESSAGES = {
    "trusted_domain": (
        RISK_SAFE,
        "✅ This looks like a well-known, trusted website",
        "The address '{url}' appears to belong to a well-known and trusted website. "
        "It should be safe to visit, but always make sure the spelling is exactly right — "
        "scammers sometimes use addresses that look almost right (like 'arnazon.com' instead of 'amazon.com')."
    ),
    "suspicious_keywords": (
        RISK_DANGER,
        "🛑 This website looks suspicious",
        "The address '{url}' contains words often used in scam or phishing websites. "
        "We strongly suggest you do NOT visit this site. If a message or email told you "
        "to go there, it could be a scam. Ask a family member or friend for help."
    ),
    "non_https": (
        RISK_CAUTION,
        "⚠️ This website may not be secure",
        "The address '{url}' doesn't use a secure connection (it starts with 'http' rather "
        "than 'https'). Avoid entering any personal details, passwords, or payment "
        "information on this site."
    ),
    "long_or_odd_url": (
        RISK_CAUTION,
        "⚠️ This web address looks unusual",
        "The address '{url}' looks more complicated than normal websites. Legitimate "
        "websites usually have short, simple addresses. Be cautious and check with "
        "someone you trust before visiting."
    ),
    "safe_url": (
        RISK_SAFE,
        "✅ This web address looks okay",
        "The address '{url}' doesn't show obvious warning signs. It should be fine to "
        "visit, but always be careful about entering personal information on any website."
    ),
    "google_flagged": (
        RISK_DANGER,
        "🛑 WARNING: This site has been reported as dangerous!",
        "The address '{url}' has been flagged by Google's safety services as a harmful "
        "or deceptive website. Do NOT visit this site. If someone sent you this link, "
        "do not reply to them — it may be a scam."
    ),
    "lookalike_domain": (
        RISK_DANGER,
        "🛑 This website is imitating a well-known site!",
        "The address '{url}' looks very similar to '{real_domain}' but the spelling is "
        "slightly different. This is a very common trick used by scammers to steal your "
        "personal information. Do NOT visit this site or enter any details."
    ),
    "ip_address_url": (
        RISK_CAUTION,
        "⚠️ This web address uses a raw number instead of a name",
        "The address '{url}' uses a numeric IP address instead of a normal website name. "
        "Legitimate websites almost never ask you to visit an address like this. This "
        "could be a trick. Unless you know exactly what this is, do not visit it."
    ),
    "known_domain": (
        RISK_SAFE,
        "✅ This domain appears in a popular-sites database",
        "The website '{domain}' appears in our database of the top 100,000 most-visited "
        "websites worldwide. This is a useful signal, but it is not a guarantee of safety."
    ),
    "known_domain_unreachable": (
        RISK_CAUTION,
        "⚠️ This domain is known, but it's currently unreachable",
        "The domain '{domain}' appears in a popular-sites database, but we could not reach "
        "it right now ({reason}). Temporary outages happen, but unavailable sites should be "
        "treated with caution."
    ),
    "typosquat_of_known": (
        RISK_DANGER,
        "🛑 This looks like a fake version of a real website!",
        "The address '{url}' is very similar to the well-known website '{real_domain}' "
        "but the spelling is slightly different. This is a common trick called "
        "'typosquatting' — scammers register misspelled web addresses to trick people. "
        "Do NOT visit this site."
    ),
}

# ---------------------------------------------------------------------------
# Lookalike / typosquatting / homoglyph domain detection
# ---------------------------------------------------------------------------

# Common digit/symbol substitutions used in phishing domains.
# e.g. amaz0n.com, paypai.com, g00gle.com, micr0soft.com
_HOMOGLYPH_MAP = str.maketrans({
    "0": "o",   # amaz0n → amazon
    "1": "l",   # paypa1 → paypal
    "!": "l",
    "|": "l",
    "5": "s",   # micro5oft → microsoft
    "8": "b",   # fa8ebook → facebook
    "@": "a",
    "$": "s",
    "3": "e",   # g3t → get
    "4": "a",   # p4ypal → paypal
    "6": "g",   # 6oogle → google
    "9": "g",   # 9oogle → google
    "7": "t",   # 7witter → twitter
    "2": "z",   # amazo2 → amazoz (less common but used)
})

# Brands most commonly targeted by phishing/typosquatting.
# Maps brand keyword → real canonical domain.
_LOOKALIKE_TARGETS = {
    "google":        "google.com",
    "youtube":       "youtube.com",
    "github":        "github.com",
    "microsoft":     "microsoft.com",
    "apple":         "apple.com",
    "amazon":        "amazon.com",
    "facebook":      "facebook.com",
    "instagram":     "instagram.com",
    "paypal":        "paypal.com",
    "netflix":       "netflix.com",
    "hulu":          "hulu.com",
    "ebay":          "ebay.com",
    "yahoo":         "yahoo.com",
    "outlook":       "outlook.com",
    "gmail":         "gmail.com",
    "wikipedia":     "wikipedia.org",
    "twitter":       "twitter.com",
    "linkedin":      "linkedin.com",
    "dropbox":       "dropbox.com",
    "icloud":        "icloud.com",
    "steam":         "steampowered.com",
    "discord":       "discord.com",
    "whatsapp":      "whatsapp.com",
    "tiktok":        "tiktok.com",
    "chase":         "chase.com",
    "wellsfargo":    "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
}


def _check_lookalike(base_domain: str) -> str | None:
    """Return the real domain being impersonated if *base_domain* looks like a
    phishing / typosquatting attempt, otherwise return None.

    Detection strategies (applied in order):
    1. Trusted-domain allow-list — skip if it's the genuine article.
    2. Subdomain spoofing  — paypal.evil.com  (brand appears as a subdomain label)
    3. Prefix/suffix attack — secure-paypal.com, paypal-login.com
    4. Homoglyph attack    — amaz0n.com (digit/symbol → letter normalization)
    5. Levenshtein typo    — amazom.com, gooogle.com (1-2 edit distance)
    """
    # 1. Allow real trusted domains through.
    if any(base_domain == td or base_domain.endswith("." + td)
           for td in TRUSTED_DOMAINS):
        return None

    labels = base_domain.lower().split(".")
    # The leftmost label is the most specific part (e.g. "amaz0n" in "amaz0n.com").
    raw_label = labels[0]
    # Normalize homoglyphs so digit/symbol substitutions collapse to letters.
    normalized_label = raw_label.translate(_HOMOGLYPH_MAP)

    for brand, real_domain in _LOOKALIKE_TARGETS.items():
        # Skip genuine canonical domains for this brand target.
        if base_domain == real_domain or base_domain.endswith("." + real_domain):
            continue

        # 2a. TLD-swap attack: github.cop vs github.com
        # Only triggers when the brand label is exact but the TLD is a likely
        # typo of the canonical TLD (edit distance <= 1).
        if raw_label == brand:
            input_tld = base_domain.rsplit(".", 1)[-1] if "." in base_domain else ""
            real_tld = real_domain.rsplit(".", 1)[-1]
            if input_tld and input_tld != real_tld and _levenshtein(input_tld, real_tld) <= 1:
                return real_domain

        # 2. Subdomain spoofing: paypal.evil.com or login.amazon.phishing.net
        #    The brand appears verbatim as a subdomain label but not as the
        #    registered domain (e.g. not paypal.com, already handled above).
        if brand in labels[:-1]:
            return real_domain

        # 3. Prefix/suffix attacks using hyphens:
        #    secure-paypal.com  paypal-login.com  amazon-support.com
        if (raw_label.startswith(brand + "-")
                or raw_label.endswith("-" + brand)):
            return real_domain

        # 4. Homoglyph attack: amaz0n → amazon after digit→letter normalization.
        #    IMPORTANT: we check normalized_label == brand (not raw_label),
        #    and only flag if the raw label is NOT already the brand (i.e. the
        #    substitution is what makes it match, not the legitimate domain).
        if normalized_label == brand and raw_label != brand:
            return real_domain

        # 5. Levenshtein typosquatting: amazom, gooogle, faceb00k (1-2 edits).
        #    We run this against the raw label so digits count as errors, giving
        #    a second chance to catch things the homoglyph map doesn't cover.
        if raw_label != brand and len(raw_label) >= 4:
            dist = _levenshtein(raw_label, brand)
            if 0 < dist <= 2:
                return real_domain

    return None


def _levenshtein(a: str, b: str) -> int:
    """Iterative Wagner-Fischer edit distance (no recursion limit risk)."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,   # deletion
                curr[j] + 1,       # insertion
                prev[j] + (0 if ca == cb else 1),  # substitution
            ))
        prev = curr
    return prev[-1]


def _check_site_reachability(url: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Best-effort reachability check for a URL.

    Returns (reachable, reason). `reason` is intended for user-friendly reporting
    when a domain appears in the known-sites DB but is currently unavailable.
    """
    headers = {"User-Agent": "SecureFileAdvisor/2.0"}
    last_reason = "connection error"

    def _probe_once(method: str) -> tuple[bool, str]:
        req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None)
            if status is None:
                return True, "reachable"
            code = int(status)
            if 200 <= code < 400:
                return True, f"HTTP {code}"
            return False, f"HTTP {code}"

    for attempt in range(1, _REACHABILITY_MAX_ATTEMPTS + 1):
        try:
            return _probe_once("HEAD")
        except urllib.error.HTTPError as exc:
            # Some servers reject HEAD; retry immediately with GET for probe only.
            if exc.code in {405, 501}:
                try:
                    return _probe_once("GET")
                except urllib.error.HTTPError as get_exc:
                    last_reason = f"HTTP {get_exc.code}"
                    retryable = get_exc.code in _REACHABILITY_RETRYABLE_HTTP_STATUS
                    if retryable and attempt < _REACHABILITY_MAX_ATTEMPTS:
                        _sleep_with_backoff(
                            attempt,
                            _REACHABILITY_BASE_DELAY_S,
                            _REACHABILITY_MAX_DELAY_S,
                        )
                        continue
                    return False, last_reason
                except urllib.error.URLError as get_exc:
                    reason = getattr(get_exc, "reason", get_exc)
                    last_reason = str(reason)
                    if attempt < _REACHABILITY_MAX_ATTEMPTS:
                        _sleep_with_backoff(
                            attempt,
                            _REACHABILITY_BASE_DELAY_S,
                            _REACHABILITY_MAX_DELAY_S,
                        )
                        continue
                    return False, last_reason
                except socket.timeout:
                    last_reason = "timeout"
                    if attempt < _REACHABILITY_MAX_ATTEMPTS:
                        _sleep_with_backoff(
                            attempt,
                            _REACHABILITY_BASE_DELAY_S,
                            _REACHABILITY_MAX_DELAY_S,
                        )
                        continue
                    return False, last_reason
                except Exception:
                    last_reason = "connection error"
                    if attempt < _REACHABILITY_MAX_ATTEMPTS:
                        _sleep_with_backoff(
                            attempt,
                            _REACHABILITY_BASE_DELAY_S,
                            _REACHABILITY_MAX_DELAY_S,
                        )
                        continue
                    return False, last_reason

            last_reason = f"HTTP {exc.code}"
            retryable = exc.code in _REACHABILITY_RETRYABLE_HTTP_STATUS
            if retryable and attempt < _REACHABILITY_MAX_ATTEMPTS:
                _sleep_with_backoff(
                    attempt,
                    _REACHABILITY_BASE_DELAY_S,
                    _REACHABILITY_MAX_DELAY_S,
                )
                continue
            return False, last_reason
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            last_reason = str(reason)
            if attempt < _REACHABILITY_MAX_ATTEMPTS:
                _sleep_with_backoff(
                    attempt,
                    _REACHABILITY_BASE_DELAY_S,
                    _REACHABILITY_MAX_DELAY_S,
                )
                continue
            return False, last_reason
        except socket.timeout:
            last_reason = "timeout"
            if attempt < _REACHABILITY_MAX_ATTEMPTS:
                _sleep_with_backoff(
                    attempt,
                    _REACHABILITY_BASE_DELAY_S,
                    _REACHABILITY_MAX_DELAY_S,
                )
                continue
            return False, last_reason
        except Exception:
            last_reason = "connection error"
            if attempt < _REACHABILITY_MAX_ATTEMPTS:
                _sleep_with_backoff(
                    attempt,
                    _REACHABILITY_BASE_DELAY_S,
                    _REACHABILITY_MAX_DELAY_S,
                )
                continue
            return False, last_reason

    return False, last_reason


# ---------------------------------------------------------------------------
# File size helper
# ---------------------------------------------------------------------------
def format_file_size(size_bytes: int) -> str:
    """Return a human-readable file size string."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    for unit in ("KB", "MB", "GB"):
        size_bytes /= 1024.0
        if size_bytes < 1024.0 or unit == "GB":
            return f"{size_bytes:.1f} {unit}"
    return f"{size_bytes:.1f} GB"


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------
def hash_file(filepath: str) -> str | None:
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError as exc:
        log.warning("Could not hash file %s: %s", filepath, exc)
        return None


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------
def analyze_file(filepath: str, vt_api_key: str = "") -> dict:
    filename = os.path.basename(filepath)
    name_lower = filename.lower()
    root, ext = os.path.splitext(name_lower)
    ext = ext.lower()

    findings = []
    overall_risk = RISK_SAFE
    file_hash = hash_file(filepath)

    try:
        file_size_bytes = os.path.getsize(filepath)
    except OSError:
        file_size_bytes = -1

    # 0. Empty-file check
    try:
        if file_size_bytes == 0:
            tpl = MESSAGES["empty_file"]
            findings.append({
                "risk": tpl[0],
                "title": tpl[1],
                "detail": tpl[2].format(name=filename)
            })
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
    except OSError:
        pass

    # 1. Double extension check
    if '.' in root and ext in DANGEROUS_EXTENSIONS:
        fake_ext = '.' + root.rsplit('.', 1)[-1]
        tpl = MESSAGES["double_extension"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, fake_ext=fake_ext, ext=ext)
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # 2. Extension risk
    if ext in DANGEROUS_EXTENSIONS:
        tpl = MESSAGES["dangerous_extension"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, ext=ext)
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif ext in SCRIPT_EXTENSIONS:
        tpl = MESSAGES["script_extension"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, ext=ext)
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    elif ext in DOCUMENT_EXTENSIONS:
        tpl = MESSAGES["document_with_macro_risk"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, ext=ext)
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
    elif ext in ARCHIVE_EXTENSIONS:
        tpl = MESSAGES["archive_file"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename)
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
    elif ext in MEDIA_EXTENSIONS:
        type_map = {
            **{e: "photo or image" for e in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']},
            **{e: "music or audio file" for e in ['.mp3', '.wav']},
            **{e: "video file" for e in ['.mp4', '.avi', '.mov', '.mkv']},
        }
        type_desc = type_map.get(ext, "media file")
        tpl = MESSAGES["media_or_safe"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, type_description=type_desc)
        })
    else:
        tpl = MESSAGES["unknown_extension"]
        findings.append({
            "risk": tpl[0],
            "title": tpl[1],
            "detail": tpl[2].format(name=filename, ext=ext if ext else "(none)")
        })
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    # 3. Suspicious keyword check
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in name_lower:
            if ext in DANGEROUS_EXTENSIONS or ext in SCRIPT_EXTENSIONS:
                tpl = MESSAGES["suspicious_name_danger"]
                findings.append({
                    "risk": tpl[0],
                    "title": tpl[1],
                    "detail": tpl[2].format(name=filename, keyword=kw)
                })
                overall_risk = _higher_risk(overall_risk, RISK_DANGER)
            elif ext in DOCUMENT_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                tpl = MESSAGES["suspicious_name_caution"]
                findings.append({
                    "risk": tpl[0],
                    "title": tpl[1],
                    "detail": tpl[2].format(name=filename, keyword=kw)
                })
                overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
            break

    # 4. VirusTotal check (if API key provided and hash available)
    if vt_api_key and file_hash:
        vt_result = check_virustotal_hash(file_hash, vt_api_key)
        if vt_result is not None:
            if vt_result == 0:
                tpl = MESSAGES["virustotal_clean"]
                findings.append({
                    "risk": tpl[0],
                    "title": tpl[1],
                    "detail": tpl[2]
                })
            elif vt_result > 0:
                tpl = MESSAGES["virustotal_detected"]
                findings.append({
                    "risk": tpl[0],
                    "title": tpl[1],
                    "detail": tpl[2].format(count=vt_result)
                })
                overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # Convert granular findings into a stable score/confidence payload.
    verdict = _verdict_payload(findings, overall_risk)
    scanned_at = datetime.now().isoformat()
    report = build_risk_report({
        "type": "file",
        "filename": filename,
        "filepath": filepath,
        "file_hash": file_hash,
        "file_size_bytes": file_size_bytes,
        "file_size": format_file_size(file_size_bytes) if file_size_bytes >= 0 else "unknown",
        "ext": ext,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "findings": findings,
        "scanned_at": scanned_at,
    })

    return {
        "type": "file",
        "filename": filename,
        "filepath": filepath,
        "file_hash": file_hash,
        "file_size_bytes": file_size_bytes,
        "file_size": format_file_size(file_size_bytes) if file_size_bytes >= 0 else "unknown",
        "ext": ext,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "signal_titles": verdict["signal_titles"],
        "risk_report": report,
        "findings": findings,
        "scanned_at": scanned_at,
    }


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------
def analyze_url(raw_url: str, gsb_api_key: str = "") -> dict:
    url = raw_url.strip()
    if not url:
        return _invalid_url_result(raw_url)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings = []
    overall_risk = RISK_SAFE

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return _invalid_url_result(raw_url)

    if not _is_plausible_web_url(url, parsed):
        return _invalid_url_result(raw_url)

    domain = parsed.netloc.lower()
    base_domain = domain.removeprefix("www.")
    full_lower = url.lower()

    # 1. Google Safe Browsing
    if gsb_api_key:
        flagged = check_google_safe_browsing(url, gsb_api_key)
        if flagged:
            tpl = URL_MESSAGES["google_flagged"]
            findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
            overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # 2. Lookalike domain check
    lookalike_match = _check_lookalike(base_domain)
    if lookalike_match:
        tpl = URL_MESSAGES["lookalike_domain"]
        findings.append({"risk": tpl[0], "title": tpl[1],
                         "detail": tpl[2].format(url=url, real_domain=lookalike_match)})
        # Add a second danger finding so the score reaches high-confidence danger
        # territory (two DANGER findings → score ≥ 72, confidence = high).
        findings.append({
            "risk": RISK_DANGER,
            "title": "🛑 Do not enter any personal information on this site",
            "detail": (
                f"Because this site is impersonating '{lookalike_match}', it may "
                "be designed to steal your password, bank details, or other personal "
                "information. Close this page immediately. If you have already entered "
                "any details, please change your password and contact your bank."
            ),
        })
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # 3. Domain database checks (Tranco top-100K)
    domain_db = get_domain_db()
    is_known_in_db = False
    if domain_db.is_loaded and not lookalike_match:
        if domain_db.is_known(base_domain):
            # Treat DB membership as a weak positive signal. If the site is
            # currently unreachable (e.g., HTTP 5xx), avoid giving a "safe"
            # signal because users may be seeing a dead/spoofed destination.
            reachable, reason = _check_site_reachability(url)
            if reachable:
                is_known_in_db = True
                tpl = URL_MESSAGES["known_domain"]
                findings.append({"risk": tpl[0], "title": tpl[1],
                                 "detail": tpl[2].format(domain=base_domain)})
            else:
                tpl = URL_MESSAGES["known_domain_unreachable"]
                findings.append({"risk": tpl[0], "title": tpl[1],
                                 "detail": tpl[2].format(domain=base_domain, reason=reason)})
                overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
        else:
            typosquat_target = domain_db.find_typosquat_target(base_domain)
            if typosquat_target:
                tpl = URL_MESSAGES["typosquat_of_known"]
                findings.append({"risk": tpl[0], "title": tpl[1],
                                 "detail": tpl[2].format(url=url, real_domain=typosquat_target)})
                findings.append({
                    "risk": RISK_DANGER,
                    "title": "🛑 Do not enter any personal information on this site",
                    "detail": (
                        f"Because this site appears to be impersonating '{typosquat_target}', "
                        "it may be designed to steal your password, bank details, or other "
                        "personal information. Close this page immediately."
                    ),
                })
                overall_risk = _higher_risk(overall_risk, RISK_DANGER)

    # 4. IP address URL check
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        is_ip_url = True
    except ValueError:
        is_ip_url = False
    if is_ip_url:
        tpl = URL_MESSAGES["ip_address_url"]
        findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
        overall_risk = _higher_risk(overall_risk, RISK_CAUTION)

    # 5. Trusted domain check (strict curated list only)
    is_trusted = any(
        base_domain == td or base_domain.endswith("." + td) for td in TRUSTED_DOMAINS
    )

    # 6. Suspicious keywords
    has_suspicious_kw = any(kw in full_lower for kw in SCAM_URL_KEYWORDS)

    # 7. HTTPS check
    is_https = parsed.scheme == "https"

    # 8. Unusual URL structure
    is_long_or_odd = len(url) > 100 or url.count(".") > 4 or "@" in url

    if is_trusted and is_https and not has_suspicious_kw:
        tpl = URL_MESSAGES["trusted_domain"]
        findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
    elif has_suspicious_kw and not is_trusted:
        tpl = URL_MESSAGES["suspicious_keywords"]
        findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
        overall_risk = _higher_risk(overall_risk, RISK_DANGER)
    else:
        if not is_https:
            tpl = URL_MESSAGES["non_https"]
            findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
        if is_long_or_odd:
            tpl = URL_MESSAGES["long_or_odd_url"]
            findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})
            overall_risk = _higher_risk(overall_risk, RISK_CAUTION)
        if not findings:
            tpl = URL_MESSAGES["safe_url"]
            findings.append({"risk": tpl[0], "title": tpl[1], "detail": tpl[2].format(url=url)})

    # Convert granular findings into a stable score/confidence payload.
    verdict = _verdict_payload(findings, overall_risk)
    scanned_at = datetime.now().isoformat()
    report = build_risk_report({
        "type": "url",
        "url": raw_url,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "findings": findings,
        "scanned_at": scanned_at,
    })

    return {
        "type": "url",
        "url": raw_url,
        "overall_risk": verdict["overall_risk"],
        "risk_score": verdict["risk_score"],
        "confidence": verdict["confidence"],
        "verdict_summary": verdict["verdict_summary"],
        "signal_titles": verdict["signal_titles"],
        "risk_report": report,
        "findings": findings,
        "scanned_at": scanned_at,
    }


# ---------------------------------------------------------------------------
# VirusTotal API
# ---------------------------------------------------------------------------
def check_virustotal_hash(file_hash: str, api_key: str) -> int | None:
    """Returns number of detections, or None if unavailable."""
    try:
        adapter = get_file_adapter(
            "virustotal",
            api_key=api_key,
            retry_policy=_PROVIDER_RETRY_POLICY,
        )
        return adapter.lookup_hash(file_hash)
    except Exception as exc:
        log.info("VirusTotal lookup failed for %s: %s", file_hash[:12], exc)
        return None


# ---------------------------------------------------------------------------
# Google Safe Browsing API
# ---------------------------------------------------------------------------
def check_google_safe_browsing(url: str, api_key: str) -> bool:
    """Returns True if URL is flagged as dangerous."""
    try:
        adapter = get_url_adapter(
            "google_safe_browsing",
            api_key=api_key,
            retry_policy=_PROVIDER_RETRY_POLICY,
        )
        return adapter.is_malicious(url)
    except Exception as exc:
        log.info("Google Safe Browsing lookup failed for %s: %s", url, exc)
        return False
