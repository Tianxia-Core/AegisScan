# Changelog

## [2.0.0] - 2026-11-12

### Added
- Completed all **8 security domains** (`secrets`, `injection`, `dependencies`, `auth_acl`, `cryptography`, `ai_prompt_safety`, `supply_chain_cicd`, `infrastructure_headers`) in Python (`scanners/`).
- Added zero-dependency concurrent Go static CLI (`cmd/aegis-scan`) with table/JSON output and `--fail-under` CI gating.
- Published Ed25519-signed multi-platform executables (`linux-x86_64`, `linux-aarch64`, `windows-x86_64.exe`, `android-aarch64`), `SHA256SUMS`, and CycloneDX `SBOM.cdx.json`.
- Added Python & Go unit test suites and GitHub Actions CI matrix.
