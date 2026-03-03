"""
verdict.py - Normalize findings into a consistent verdict payload.

This module is intentionally small and self-contained so we can reuse the same
scoring behavior for file scans, URL scans, and future provider plugins.
"""

from __future__ import annotations

# Risk labels are string-based so they can be serialized directly in history.
RISK_SAFE = "safe"
RISK_CAUTION = "caution"
RISK_DANGER = "danger"

_SCORE_BY_FINDING_RISK = {
    RISK_SAFE:    5,   # "clean evidence" — low but non-trivial
    RISK_CAUTION: 14,
    RISK_DANGER:  36,
}


def build_verdict(findings: list[dict], initial_risk: str = RISK_SAFE) -> dict:
    """Build a consistent verdict dict from raw findings.

    Why this exists:
    - `overall_risk` alone is coarse.
    - A numeric score + confidence helps users and future APIs reason about risk.
    - We keep this deterministic (no ML), which makes behavior easy to explain.
    """
    score = 0
    counts = {
        RISK_SAFE: 0,
        RISK_CAUTION: 0,
        RISK_DANGER: 0,
    }
    signal_titles: list[str] = []

    for finding in findings:
        risk = str(finding.get("risk", RISK_CAUTION)).lower()
        if risk not in _SCORE_BY_FINDING_RISK:
            risk = RISK_CAUTION
        score += _SCORE_BY_FINDING_RISK[risk]
        counts[risk] += 1

        title = str(finding.get("title", "")).strip()
        if title and title not in signal_titles:
            signal_titles.append(title)

    # Floors prevent the numeric score from contradicting the rule-based label.
    # e.g. an overall_risk of "danger" must never produce a score below 70.
    # We deliberately do NOT apply a floor for safe scans: those scores should
    # be as low as the evidence warrants, reflecting how clean the item looks.
    if initial_risk == RISK_DANGER:
        score = max(score, 75)
    elif initial_risk == RISK_CAUTION:
        score = max(score, 40)

    score = max(0, min(100, score))
    overall_risk = _risk_from_score(score)
    confidence = _confidence_from_evidence(score, counts)
    summary = _summary_for_risk(overall_risk)

    return {
        "overall_risk": overall_risk,
        "risk_score": score,
        "confidence": confidence,
        "verdict_summary": summary,
        "signal_titles": signal_titles[:5],
    }


def coerce_verdict_fields(scan_result: dict) -> dict:
    """Return verdict fields for a scan result, generating them if missing.

    This exists for backward compatibility:
    - Older history entries won't have `risk_score` / `confidence` / `verdict_summary`.
    - UI and messaging should still show a reasonable report for those entries.
    """
    overall_risk = str(scan_result.get("overall_risk", RISK_CAUTION)).lower()
    existing_score = scan_result.get("risk_score")
    existing_conf = scan_result.get("confidence")
    existing_summary = scan_result.get("verdict_summary")
    existing_titles = scan_result.get("signal_titles")

    if (
        overall_risk in {RISK_SAFE, RISK_CAUTION, RISK_DANGER}
        and isinstance(existing_score, int)
        and isinstance(existing_conf, str)
        and isinstance(existing_summary, str)
        and isinstance(existing_titles, list)
    ):
        return {
            "overall_risk": overall_risk,
            "risk_score": existing_score,
            "confidence": existing_conf,
            "verdict_summary": existing_summary,
            "signal_titles": existing_titles,
        }

    findings = scan_result.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    generated = build_verdict(findings=findings, initial_risk=overall_risk)

    # Keep the stored severity as canonical for history; we only backfill the
    # explainability fields.
    generated["overall_risk"] = overall_risk
    return generated


def _risk_from_score(score: int) -> str:
    if score >= 70:
        return RISK_DANGER
    if score >= 35:
        return RISK_CAUTION
    return RISK_SAFE


def _confidence_from_evidence(score: int, counts: dict) -> str:
    # Confidence describes how strong the evidence is, not how "safe" something
    # is. High confidence can happen for safe or dangerous outcomes.
    if score >= 85 or counts[RISK_DANGER] >= 2:
        return "high"
    if score >= 50 or counts[RISK_DANGER] == 1 or counts[RISK_CAUTION] >= 2:
        return "medium"
    return "low"


def _summary_for_risk(risk: str) -> str:
    if risk == RISK_DANGER:
        return "High risk: avoid opening this until a trusted person verifies it."
    if risk == RISK_CAUTION:
        return "Caution: this has warning signs, so verify before opening."
    return "No strong warning signs found, but keep normal online safety habits."
