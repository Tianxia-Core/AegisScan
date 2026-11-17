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

<!-- BUILD_LAW_SHOWCASE_START -->

---

## 🌍 In Plain English — What `AegisScan` Is & Why It Matters (Layman's Guide)

- **The Everyday Problem:** Most security scanners take 20 minutes to configure, require cloud accounts, and completely miss modern AI threats like hidden prompt-injection characters or leaked agent tokens.
- **How It Works (Without the Jargon):** `AegisScan` is a single, zero-dependency binary (`MIT`) that scans any repository across **8 security domains**—leaked secrets, command injection, weak cryptography, broken permissions, CI supply-chain risks, and AI prompt-injection payloads—in milliseconds.
- **Why It Is Different:** Zero cloud uploads, zero external dependencies, and full alignment with **[Build Law](https://github.com/Tianxia-Core/Build-Law)** zero-trust static verification.
- **How It Benefits You:** Developers and CISOs catch credential leaks and AI vulnerabilities on their laptop before `git push`—for `$0` and with 100% code privacy.
- **How to Install & Use It in 60 Seconds:** Download the signed binary from Releases or compile in 2 seconds with `go build ./cmd/...`, then run `aegis-scan .`.

---

## 🏛️ Governed by [`Build Law`](https://github.com/Tianxia-Core/Build-Law) — Engineering Philosophy & Stakeholder Pathways

This repository is a live production showcase of **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)**—the open-source (`MIT`) **4-Pillar, 14-Gate Constitutional Engineering & `5.0×–8.8×` Token-Efficiency Standard** created by **[Collins Takem](https://rasaxmachina.com/collins)** (**RASA-X-MACHINA**):
- **Developers & AI Builders:** Drop **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)** into Claude Code, Cursor, OpenCode, VS Code (`.vsix`), GitHub Copilot, Windsurf, Cline, Aider, or any chat LLM in 60 seconds.
- **CTOs & B2B Engineering Leaders:** Need similar `Rust`/`Go`/`Nix`/Security/FinOps rigor applied to your infrastructure? Scope a fixed-price **72-Hour `VRTTI` Architecture Sprint** at **[vrtti.rasaxmachina.com](https://vrtti.rasaxmachina.com)**.
- **Investors, Researchers, Press & Executive Hiring Committees:** Inspect our cryptographic release proofs across **[`@Tianxia-Core`](https://github.com/Tianxia-Core)**, press assets at **[rasaxmachina.com/press](https://rasaxmachina.com/press)**, and founder dossier at **[rasaxmachina.com/collins](https://rasaxmachina.com/collins)**.

<!-- BUILD_LAW_SHOWCASE_END -->

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
