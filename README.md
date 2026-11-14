<p align="center">
  <img src="./brand-kit/01-logos/lockups-and-social/dual-lockup-rxm-x-tianxiaos.svg" alt="RASA-X-MACHINA · tianxiaOS" width="680"/>
</p>

# AegisScan

[![CI](https://github.com/Tianxia-Core/AegisScan/actions/workflows/ci.yml/badge.svg)](https://github.com/Tianxia-Core/AegisScan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v2.0.0-00d4aa)](https://github.com/Tianxia-Core/AegisScan/releases/tag/v2.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=flat-square)](LICENSE)

**AegisScan** is a zero-dependency, MIT-licensed security audit toolkit that scores any software repository on a **0–100 scale across 8 weighted security domains**. It ships in **two complete, zero-dependency implementations**:

1. **Static Native CLI (`cmd/aegis-scan`)** — Compiled with Go (`CGO_ENABLED=0`) for sub-second concurrent directory scanning across Linux (`x86_64`, `aarch64`), Windows (`x86_64.exe`), and Android (`aarch64`).
2. **Pure Python Stdlib Suite (`full_audit.py` / `score_calculator.py` / `scanners/`)** — Extensible per-domain Python scanners requiring only the Python 3.10+ standard library.

---

## The 8 Security Domains

| # | Domain Key | Weight | Python Scanner | Coverage |
| :---: | :--- | ---: | :--- | :--- |
| 1 | `secrets` | **20%** | `scanners/secrets_scanner.py` | API keys, cloud IAM tokens, Stripe/GitHub PATs, PEM private keys, inline DB credentials, entropy analysis |
| 2 | `injection` | **15%** | `scanners/injection_scanner.py` | SQL string formatting, `eval`/`exec`, `shell=True` command injection, unsafe deserialization, XSS, SSRF |
| 3 | `dependencies` | **10%** | `scanners/dependency_scanner.py` | Unpinned `requirements.txt` / wildcard `package.json`, HTTP package sources, lockfile hygiene |
| 4 | `auth_acl` | **15%** | `scanners/auth_acl_scanner.py` | Unverified JWTs / `alg: none`, hardcoded admin bypasses, `0777` file modes, wildcard CORS |
| 5 | `cryptography` | **15%** | `scanners/cryptography_scanner.py` | MD5/SHA-1 misuse, ECB block cipher mode, disabled TLS verification, legacy TLS 1.0/1.1, weak PRNGs |
| 6 | `ai_prompt_safety` | **10%** | `scanners/ai_prompt_safety_scanner.py` | Raw user interpolation in `system` prompts, LLM output piped to `eval`/shell sinks, `trust_remote_code=True` |
| 7 | `supply_chain_cicd` | **10%** | `scanners/supply_chain_cicd_scanner.py` | GitHub Actions `${{ ... }}` expression injection, `@master` unpinned actions, `curl \| bash`, `:latest` images |
| 8 | `infrastructure_headers` | **5%** | `scanners/infrastructure_headers_scanner.py` | Production `DEBUG=True`, `privileged: true` containers, insecure cookies, `0.0.0.0/0` SSH/RDP ingress |

---

## Quick Start

### Option A: Self-Contained Native Binary (`aegis-scan`)

```bash
# Formatted 8-domain security table
./aegis-scan-v2.0.0-linux-x86_64 --target /path/to/repo

# Machine-readable JSON report + CI gate (exit 1 if score < 90)
./aegis-scan-v2.0.0-linux-x86_64 --target /path/to/repo --json --fail-under 90
```

### Option B: Python Stdlib Suite

```bash
python3 full_audit.py --target /path/to/repo
python3 full_audit.py --target /path/to/repo --output markdown --report-file AUDIT_REPORT.md
python3 score_calculator.py --target /path/to/repo --output json --fail-under 90
```

---

## Release Signature Verification (Ed25519)

All official binaries in [Releases](https://github.com/Tianxia-Core/AegisScan/releases/tag/v2.0.0) are signed with Ed25519 and accompanied by `SHA256SUMS` and CycloneDX 1.5 `SBOM.cdx.json`:

```bash
sha256sum -c SHA256SUMS
openssl pkeyutl -verify -pubin -inkey RELEASE_SIGNING_KEY.pub.pem \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

## License

MIT License — see [LICENSE](LICENSE). Maintained by **RASA-X-MACHINA** *(Proposed Estonian Deep-Tech Entity — Tallinn, Estonia)*.
