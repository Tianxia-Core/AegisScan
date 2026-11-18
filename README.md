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

## 🏛️ Governed by [`Build Law`](https://github.com/Tianxia-Core/Build-Law) — Clean-Room Public Edition & Stakeholder Pathways

This repository ships as a **`PUBLIC_CLEANROOM_SEED` Edition** under **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)**—containing zero pre-populated personal data, zero embedded secrets, and deterministic `init-clean` bootstrapping (`nimbus2 init-clean` / `build-law init-clean`) so every adopter starts with a fresh, sovereign workspace of their own:
- **Developers & AI Builders:** Combine **[`FC-Estimator`](https://github.com/Tianxia-Core/FC-Estimator)** (`95%` accurate pre-build sizing), **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)** (`5.0×–8.8×` token efficiency across 20+ IDEs/agents), and **[`nimbus²`](https://github.com/Tianxia-Core/nimbus2)** (`nimbus2 ship` + `$0.00` 14-Gate PR review).
- **CTOs & B2B Engineering Leaders:** Need similar `Rust`/`Go`/`Nix`/Security/FinOps rigor applied to your infrastructure? Scope a fixed-price **72-Hour `VRTTI` Architecture Sprint** at **[vrtti.rasaxmachina.com](https://vrtti.rasaxmachina.com)**.
- **Investors, Researchers, Press & Executive Hiring Committees:** Inspect cryptographic release proofs across **[`@Tianxia-Core`](https://github.com/Tianxia-Core)**, press assets in **[`@Tianxia-Presence/brand-kit`](https://github.com/Tianxia-Presence/brand-kit)**, commercial suites in **[`@Tianxia-Revenues`](https://github.com/Tianxia-Revenues)**, and founder dossier at **[rasaxmachina.com/collins](https://rasaxmachina.com/collins)**.

### 🔗 Composable Sovereign Stack — Works Natively With (`@Tianxia-Core` · `@Tianxia-Presence` · `@Tianxia-Revenues`)

Every tool in the **RASA-X-MACHINA** ecosystem is standalone (`0` lock-in bloat), yet designed to compose seamlessly across pre-build sizing, IDE governance, polyglot compilation, security custody, and autonomous operations:

| Lifecycle Layer | Companion Tool(s) | How They Work Together |
| :--- | :--- | :--- |
| **Pre-Build Sizing & FinOps** | **[`FC-Estimator`](https://github.com/Tianxia-Core/FC-Estimator)** (`MIT`) | Sizes `ceil(FC / 8)` microservice bounds, active build minutes (`95.0%` accuracy) & `8.8×` EUR token savings before coding. |
| **Constitutional Governance** | **[`Build Law`](https://github.com/Tianxia-Core/Build-Law)** (`MIT`) | Embeds the 4-Pillar, 14-Gate rules & `< 5 ms` `$0.00` static verifier across Claude, Cursor, VS Code, OpenCode & MCP. |
| **Executive Build, PR & Proxy Manager** | **[`nimbus²`](https://github.com/Tianxia-Core/nimbus2)** (`MPL-2.0`) | Runs `nimbus2 ship`, `$0.00` 14-Gate `review-diff`, `init-clean` zero-PII seeding & high-concurrency TLS 1.3 proxy routing. |
| **Polyglot Wire Contracts** | **[`Jivascriptocle`](https://github.com/Tianxia-Core/Jivascriptocle)** (`Apache-2.0`) | Compiles single `.jiva` contracts into synchronized `Rust`, `Zig`, `OCaml`, `TypeScript`, `Nix` & compact `TOON` schemas. |
| **DevSecOps & Secret Enclave** *(Current Repo)* | **[`AegisScan`](https://github.com/Tianxia-Core/AegisScan)** & **[`AetherVault`](https://github.com/Tianxia-Core/AetherVault)** (`MIT`) | 8-domain static supply-chain/prompt-injection scanner paired with `AES-256-GCM` `chmod 0600` runtime secret custody. |
| **Sovereign OS, Firewall & Mesh** | **[`TianxiaOS`](https://github.com/Tianxia-Core/TianxiaOS)** · **[`Faery-Fortress`](https://github.com/Tianxia-Core/Faery-Fortress)** · **[`tianxia-mobile`](https://github.com/Tianxia-Core/tianxia-mobile)** | Declarative NixOS operating substrate, `< 4 µs` `AF_XDP` + Rosenpass post-quantum firewall & signed Android ARM64 mesh node. |
| **Intelligence, Ledger & Logistics** | **[`Ndimmorwyn`](https://github.com/Tianxia-Core/Ndimmorwyn)** · **[`Tetraledger`](https://github.com/Tianxia-Core/Tetraledger)** · **[`MURUA`](https://github.com/Tianxia-Core/MURUA)** · **[`Scour`](https://github.com/Tianxia-Core/Scour)** | Constructal `-79.6%` LLM router + `EjAwen` CRM, 4-way Merkle/`x402` settlement, Bayesian postal telemetry & live signal radar. |
| **Press Assets & B2B Sprints** | **[`@Tianxia-Presence/brand-kit`](https://github.com/Tianxia-Presence/brand-kit)** & **[`@Tianxia-Revenues`](https://github.com/Tianxia-Revenues)** | Official vector identity/design tokens (`WCAG 2.2 AA`) and fixed-scope **72h `VRTTI` Architecture Sprints** at [rasaxmachina.com](https://rasaxmachina.com). |

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
