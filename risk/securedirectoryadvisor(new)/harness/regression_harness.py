"""Deterministic regression harness for core analyzers.

Usage:
    python -m harness.regression_harness
"""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from modules.analyzer import analyze_file, analyze_url
from modules.email_analyzer import analyze_email_message
from harness.scenarios import email_scenarios, materialize_file_scenarios, url_scenarios

RISK_ORDER = {"safe": 0, "caution": 1, "danger": 2}
REQUIRED_FIELDS = (
    "type",
    "overall_risk",
    "risk_score",
    "confidence",
    "verdict_summary",
    "signal_titles",
    "risk_report",
    "findings",
    "scanned_at",
)


@dataclass
class CaseResult:
    case_id: str
    passed: bool
    observed_risk: str
    expected_risk: str
    detail: str


def _contains_all_terms(result: dict, required_terms: tuple[str, ...]) -> bool:
    if not required_terms:
        return True
    # Search across titles and details so assertions remain readable.
    titles = [str(t) for t in result.get("signal_titles", [])]
    findings = result.get("findings", []) or []
    finding_text = " ".join(
        f"{f.get('title', '')} {f.get('detail', '')}" for f in findings if isinstance(f, dict)
    )
    haystack = (" ".join(titles) + " " + finding_text).lower()
    return all(term.lower() in haystack for term in required_terms)


def _validate_contract(result: dict) -> tuple[bool, str]:
    missing = [field for field in REQUIRED_FIELDS if field not in result]
    if missing:
        return False, f"missing contract fields: {missing}"

    risk = str(result.get("overall_risk", "")).lower()
    if risk not in RISK_ORDER:
        return False, f"invalid risk value: {risk!r}"

    score = result.get("risk_score")
    if not isinstance(score, int) or not (0 <= score <= 100):
        return False, f"invalid risk_score: {score!r}"

    confidence = str(result.get("confidence", "")).lower()
    if confidence not in {"low", "medium", "high"}:
        return False, f"invalid confidence: {confidence!r}"

    report = result.get("risk_report", {})
    if not isinstance(report, dict) or not str(report.get("text", "")).strip():
        return False, "missing risk_report.text"

    findings = result.get("findings")
    if not isinstance(findings, list) or not findings:
        return False, "findings must be a non-empty list"

    return True, "ok"


def _assert_expected_risk(observed: str, expected: str) -> tuple[bool, str]:
    observed_key = observed.lower().strip()
    expected_key = expected.lower().strip()
    if observed_key == expected_key:
        return True, "risk matched exactly"
    return (
        False,
        f"risk mismatch (expected={expected_key}, observed={observed_key})",
    )


def run_regressions() -> dict:
    case_results: list[CaseResult] = []

    with tempfile.TemporaryDirectory(prefix="sda-regression-") as tmp:
        tmpdir = Path(tmp)

        # File scenarios
        for scenario, path in materialize_file_scenarios(tmpdir):
            result = analyze_file(str(path), vt_api_key="")
            ok_contract, contract_detail = _validate_contract(result)
            ok_risk, risk_detail = _assert_expected_risk(result["overall_risk"], scenario.expected_risk)
            ok_terms = _contains_all_terms(result, scenario.required_terms)
            passed = ok_contract and ok_risk and ok_terms
            detail = "; ".join(
                part
                for part in (
                    contract_detail if not ok_contract else "",
                    risk_detail if not ok_risk else "",
                    "missing required terms" if not ok_terms else "",
                )
                if part
            ) or "ok"
            case_results.append(
                CaseResult(
                    case_id=scenario.case_id,
                    passed=passed,
                    observed_risk=result["overall_risk"],
                    expected_risk=scenario.expected_risk,
                    detail=detail,
                )
            )

        # URL scenarios
        for scenario in url_scenarios():
            result = analyze_url(scenario.raw_url, gsb_api_key="")
            ok_contract, contract_detail = _validate_contract(result)
            ok_risk, risk_detail = _assert_expected_risk(result["overall_risk"], scenario.expected_risk)
            ok_terms = _contains_all_terms(result, scenario.required_terms)
            passed = ok_contract and ok_risk and ok_terms
            detail = "; ".join(
                part
                for part in (
                    contract_detail if not ok_contract else "",
                    risk_detail if not ok_risk else "",
                    "missing required terms" if not ok_terms else "",
                )
                if part
            ) or "ok"
            case_results.append(
                CaseResult(
                    case_id=scenario.case_id,
                    passed=passed,
                    observed_risk=result["overall_risk"],
                    expected_risk=scenario.expected_risk,
                    detail=detail,
                )
            )

        # Email scenarios
        for scenario in email_scenarios():
            result = analyze_email_message(
                scenario.raw_email,
                gsb_api_key="",
                vt_api_key="",
            )
            ok_contract, contract_detail = _validate_contract(result)
            ok_risk, risk_detail = _assert_expected_risk(result["overall_risk"], scenario.expected_risk)
            ok_terms = _contains_all_terms(result, scenario.required_terms)
            passed = ok_contract and ok_risk and ok_terms
            detail = "; ".join(
                part
                for part in (
                    contract_detail if not ok_contract else "",
                    risk_detail if not ok_risk else "",
                    "missing required terms" if not ok_terms else "",
                )
                if part
            ) or "ok"
            case_results.append(
                CaseResult(
                    case_id=scenario.case_id,
                    passed=passed,
                    observed_risk=result["overall_risk"],
                    expected_risk=scenario.expected_risk,
                    detail=detail,
                )
            )

    passed_count = sum(1 for c in case_results if c.passed)
    failed_count = len(case_results) - passed_count
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(case_results),
            "passed": passed_count,
            "failed": failed_count,
        },
        "cases": [asdict(case) for case in case_results],
    }
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic analyzer regressions.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("harness") / "regression_report.json",
    )
    args = parser.parse_args()

    payload = run_regressions()
    output_path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Regression report written: {output_path}")
    print(
        f"Total: {payload['summary']['total']} | "
        f"Passed: {payload['summary']['passed']} | "
        f"Failed: {payload['summary']['failed']}"
    )
    for case in payload["cases"]:
        status = "PASS" if case["passed"] else "FAIL"
        print(
            f"[{status}] {case['case_id']} "
            f"(expected={case['expected_risk']}, observed={case['observed_risk']})"
        )
        if not case["passed"]:
            print(f"       {case['detail']}")

    return 0 if payload["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
