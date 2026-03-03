"""Shared deterministic scenarios for regression and benchmark harnesses.

The goal is to keep these scenarios stable over time so we can detect
unintended behavior drift and performance regressions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileScenario:
    case_id: str
    filename: str
    content: bytes
    expected_risk: str
    required_terms: tuple[str, ...] = ()


@dataclass(frozen=True)
class UrlScenario:
    case_id: str
    raw_url: str
    expected_risk: str
    required_terms: tuple[str, ...] = ()


@dataclass(frozen=True)
class EmailScenario:
    case_id: str
    raw_email: str
    expected_risk: str
    required_terms: tuple[str, ...] = ()


def file_scenarios() -> tuple[FileScenario, ...]:
    # Use synthetic bytes so no external files are needed for harness runs.
    return (
        FileScenario(
            case_id="file_media_safe",
            filename="family_photo.jpg",
            content=b"\xff\xd8\xff\xdbsynthetic-jpeg-data",
            expected_risk="safe",
            required_terms=("looks safe",),
        ),
        FileScenario(
            case_id="file_double_ext_danger",
            filename="invoice.pdf.exe",
            content=b"MZfakepe",
            expected_risk="danger",
            required_terms=("trick", "dangerous"),
        ),
        FileScenario(
            case_id="file_archive_caution",
            filename="statement.zip",
            content=b"PK\x03\x04fakezip",
            expected_risk="caution",
            required_terms=("archive",),
        ),
    )


def url_scenarios() -> tuple[UrlScenario, ...]:
    # Keep URLs offline-friendly: these should not require external API keys.
    return (
        UrlScenario(
            case_id="url_https_safe",
            raw_url="https://notes.example",
            expected_risk="safe",
            required_terms=("looks okay",),
        ),
        UrlScenario(
            case_id="url_keyword_danger",
            raw_url="http://secure-check.example/verify-account",
            expected_risk="danger",
            required_terms=("suspicious",),
        ),
        UrlScenario(
            case_id="url_ip_caution",
            raw_url="http://127.0.0.1/account",
            expected_risk="caution",
            required_terms=("raw number",),
        ),
    )


def email_scenarios() -> tuple[EmailScenario, ...]:
    # Raw messages are kept small and deterministic.
    return (
        EmailScenario(
            case_id="email_safe_plain",
            raw_email=(
                "From: Alice Example <alice@example.com>\n"
                "To: Bob Example <bob@example.com>\n"
                "Subject: Lunch plans\n"
                "Date: Tue, 03 Mar 2026 10:00:00 -0500\n"
                "Message-ID: <safe-1@example.com>\n"
                "Content-Type: text/plain; charset=utf-8\n"
                "\n"
                "Hi Bob,\n"
                "Are we still on for lunch tomorrow?\n"
            ),
            expected_risk="safe",
            required_terms=("no obvious warning",),
        ),
        EmailScenario(
            case_id="email_phish_danger",
            raw_email=(
                "From: PayPal Security <alerts@gmail.com>\n"
                "To: user@example.com\n"
                "Subject: Urgent action required: verify your account now\n"
                "Date: Tue, 03 Mar 2026 10:05:00 -0500\n"
                "Message-ID: <danger-1@example.com>\n"
                "Content-Type: text/plain; charset=utf-8\n"
                "\n"
                "Your account is suspended.\n"
                "Click immediately: http://secure-paypal-login.example/verify\n"
            ),
            expected_risk="danger",
            required_terms=("phishing", "suspicious links"),
        ),
        EmailScenario(
            case_id="email_reply_to_caution",
            raw_email=(
                "From: Billing Team <billing@shop.example>\n"
                "Reply-To: payments@other.example\n"
                "To: user@example.com\n"
                "Subject: Monthly statement available\n"
                "Date: Tue, 03 Mar 2026 10:10:00 -0500\n"
                "Message-ID: <caution-1@example.com>\n"
                "Content-Type: text/plain; charset=utf-8\n"
                "\n"
                "Your monthly statement is available for review.\n"
            ),
            expected_risk="caution",
            required_terms=("reply address differs",),
        ),
    )


def materialize_file_scenarios(workdir: Path) -> list[tuple[FileScenario, Path]]:
    """Write synthetic file scenarios to disk and return concrete paths."""
    paths: list[tuple[FileScenario, Path]] = []
    for scenario in file_scenarios():
        path = workdir / scenario.filename
        path.write_bytes(scenario.content)
        paths.append((scenario, path))
    return paths

