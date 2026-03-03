# Secure Directory Advisor - Roadmap

## Phase 1 (Current sprint: 1-2 weeks)

Goal: Improve trust and reliability without changing runtime stack.

- Add deterministic verdict metadata (`risk_score`, `confidence`, summary).
- Add shareable risk report aligned to common NIST/ISO principles.
- Surface score/confidence in UI and history.
- Document architecture, API contract, and scoring model.
- Stabilize shutdown, file monitoring, and config persistence.

Exit criteria:

- All scan paths return a consistent verdict payload.
- UI displays score/confidence for every result.
- Report view/copy is available from results and history.
- `py_compile` passes for all modules.

## Phase 2 (4-6 weeks)

Goal: Stronger detection quality and better performance.

- Add pluggable provider adapter interface.
- Add local signature engine integration (e.g., ClamAV/YARA).
- Introduce richer artifact analysis:
  - archive recursion limits
  - macro/script markers
  - file magic type validation
- Add benchmark datasets and regression checks for false positives.

Exit criteria:

- Provider failures are isolated and retried.
- Quality metrics tracked for each release.

## Phase 3 (6-10 weeks)

Goal: Production-grade architecture for broader deployment.

- Migrate to modern desktop shell (Tauri/Electron) with dedicated scan backend.
- Add optional cloud control-plane for policy and telemetry.
- Implement signed updates, stronger security hardening, and audit logging.
- Add localization pipeline and accessibility QA.

Exit criteria:

- Stable update pipeline.
- Policy-driven deployment.
- Measurable detection improvements release-over-release.
