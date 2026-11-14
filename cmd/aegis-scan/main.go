// ffp: FFP-AEGIS-SCAN-GO io-edge go
// AegisScan v2.1.0 — Blazing-Fast Standalone 8-Domain Security Auditor (MIT).
// Audits any codebase across all 8 security domains with zero external dependencies:
//   1. secrets               (20%)
//   2. injection             (15%)
//   3. dependencies          (10%)
//   4. auth_acl              (15%)
//   5. cryptography          (15%)
//   6. ai_prompt_safety      (10%)
//   7. supply_chain_cicd     (10%)
//   8. infrastructure_headers( 5%)
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const Version = "2.1.0"

type DomainSpec struct {
	Key    string
	Label  string
	Weight float64
}

var Domains = []DomainSpec{
	{Key: "secrets", Label: "Secrets & Credentials", Weight: 0.20},
	{Key: "injection", Label: "Code, SQL & Command Injection", Weight: 0.15},
	{Key: "dependencies", Label: "Dependencies & Lockfile Pinning", Weight: 0.10},
	{Key: "auth_acl", Label: "Authentication & Access Control", Weight: 0.15},
	{Key: "cryptography", Label: "Cryptography & TLS Posture", Weight: 0.15},
	{Key: "ai_prompt_safety", Label: "AI & Prompt Safety", Weight: 0.10},
	{Key: "supply_chain_cicd", Label: "Supply Chain & CI/CD Pipelines", Weight: 0.10},
	{Key: "infrastructure_headers", Label: "Infrastructure & Security Headers", Weight: 0.05},
}

type Rule struct {
	Domain      string
	ID          string
	Severity    string
	Regex       *regexp.Regexp
	FileMatcher func(relPath, baseName string) bool
	Remediation string
}

type Finding struct {
	Domain      string `json:"domain"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Snippet     string `json:"snippet"`
	Remediation string `json:"remediation"`
}

type Verdict struct {
	Label       string `json:"label"`
	Emoji       string `json:"emoji"`
	Description string `json:"description"`
}

type AuditReport struct {
	Scanner          string             `json:"scanner"`
	Version          string             `json:"version"`
	Target           string             `json:"target"`
	Timestamp        string             `json:"timestamp"`
	DurationMs       float64            `json:"duration_ms"`
	FilesScanned     int                `json:"files_scanned"`
	TotalFindings    int                `json:"total_findings"`
	DomainScores     map[string]float64 `json:"domain_scores"`
	DomainFindings   map[string]int     `json:"domain_findings"`
	FinalScore       float64            `json:"final_score"`
	Verdict          Verdict            `json:"verdict"`
	Findings         []Finding          `json:"findings"`
}

var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".aegis_data": true,
	"__pycache__": true, ".pytest_cache": true, ".mypy_cache": true,
	"node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, ".next": true, ".terraform": true,
}

var scannableExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".mjs": true,
	".go": true, ".rs": true, ".java": true, ".kt": true, ".rb": true, ".php": true,
	".c": true, ".h": true, ".zig": true, ".sh": true, ".bash": true, ".zsh": true,
	".yml": true, ".yaml": true, ".toml": true, ".json": true, ".ini": true, ".cfg": true,
	".conf": true, ".tf": true, ".sql": true, ".env": true, ".txt": true, ".dockerfile": true,
}

func buildRules() []Rule {
	anyCode := func(_, base string) bool {
		return !strings.HasSuffix(strings.ToLower(base), ".md")
	}
	depOnly := func(_, base string) bool {
		b := strings.ToLower(base)
		return strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt") ||
			b == "package.json" || b == "pyproject.toml" || b == "pipfile"
	}
	cicdOnly := func(rel, base string) bool {
		r := strings.ToLower(filepath.ToSlash(rel))
		b := strings.ToLower(base)
		return strings.Contains(r, ".github/workflows/") ||
			strings.HasPrefix(b, "dockerfile") ||
			strings.HasSuffix(b, ".sh") ||
			b == "gitlab-ci.yml" || b == ".gitlab-ci.yml"
	}

	return []Rule{
		// 1. secrets
		{"secrets", "aws_access_key", "CRITICAL", regexp.MustCompile(`(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}`), anyCode, "Revoke leaked AWS IAM key and migrate to short-lived OIDC workload credentials."},
		{"secrets", "github_pat_token", "CRITICAL", regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`), anyCode, "Revoke GitHub Personal Access Token and inject via encrypted CI secrets."},
		{"secrets", "stripe_api_key", "CRITICAL", regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}`), anyCode, "Rotate Stripe secret key immediately and store in a secrets vault."},
		{"secrets", "pem_private_key", "CRITICAL", regexp.MustCompile(`-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----`), anyCode, "Remove private key material from source control and rotate keypair."},
		{"secrets", "hardcoded_secret_assignment", "HIGH", regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|jwt[_-]?secret|client[_-]?secret|password|passwd)\s*[:=]\s*['"][^'"\s$]{8,}['"]`), anyCode, "Load credentials from environment variables or an encrypted vault at runtime."},
		{"secrets", "embedded_db_url_credentials", "HIGH", regexp.MustCompile(`(?i)(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s'"]+:[^@\s'"]+@`), anyCode, "Remove inline credentials from database connection URIs."},

		// 2. injection
		{"injection", "dynamic_eval_or_exec", "CRITICAL", regexp.MustCompile(`\b(?:eval|exec)\s*\(`), anyCode, "Eliminate dynamic code evaluation; use structured AST/JSON parsers."},
		{"injection", "shell_command_injection", "CRITICAL", regexp.MustCompile(`(?:subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.system\s*\(|\bchild_process\.exec\s*\()`), anyCode, "Pass argument arrays to subprocess/execFile with shell interpolation disabled."},
		{"injection", "sql_string_interpolation", "CRITICAL", regexp.MustCompile(`(?i)(?:cursor\.execute|db\.Exec|db\.Query|\.query)\s*\(\s*(?:f['"]|['"][^'"]*%\s*s|['"][^'"]*\+\s*[a-zA-Z_])`), anyCode, "Use parameterized prepared statements ($1 / ? placeholders)."},
		{"injection", "unsafe_deserialization", "HIGH", regexp.MustCompile(`(?:\bpickle\.loads?\s*\(|\byaml\.load\s*\([^)]*\))`), anyCode, "Use `json.loads` or `yaml.safe_load` for untrusted payloads."},
		{"injection", "dom_xss_innerhtml", "HIGH", regexp.MustCompile(`\.innerHTML\s*=`), anyCode, "Use `textContent` or strict HTML sanitization before DOM insertion."},

		// 3. dependencies
		{"dependencies", "unpinned_python_requirement", "MEDIUM", regexp.MustCompile(`^[A-Za-z0-9_.-]+\s*(?:>=|~=|!=|>|<|$)`), depOnly, "Pin exact dependency versions (`pkg==X.Y.Z`) and commit lockfiles."},
		{"dependencies", "wildcard_npm_dependency", "HIGH", regexp.MustCompile(`"[A-Za-z0-9@/._-]+"\s*:\s*"(?:\*|latest)"`), depOnly, "Replace `*` / `latest` ranges in package.json with pinned semantic versions."},
		{"dependencies", "insecure_http_package_source", "CRITICAL", regexp.MustCompile(`(?i)(?:git\+http://|--trusted-host|--extra-index-url\s+http://)`), depOnly, "Fetch all dependencies exclusively over authenticated HTTPS with hash verification."},

		// 4. auth_acl
		{"auth_acl", "jwt_unverified_or_alg_none", "CRITICAL", regexp.MustCompile(`(?i)(?:verify_signature['"]?\s*:\s*false|algorithms\s*=\s*\[[^\]]*['"]none['"]|jwt\.decode\([^)]*verify\s*=\s*False)`), anyCode, "Enforce JWT cryptographic verification and explicit algorithm allowlists."},
		{"auth_acl", "hardcoded_admin_identity_bypass", "HIGH", regexp.MustCompile(`(?i)\bif\s+(?:user|username|role|email)\s*==\s*['"](?:admin|root|superuser|backdoor)['"]`), anyCode, "Enforce centralized RBAC/ABAC capability verification instead of hardcoded usernames."},
		{"auth_acl", "world_writable_permissions_0777", "HIGH", regexp.MustCompile(`(?i)(?:chmod\s*\([^)]*0o?777|\bchmod\s+777\b|0o777)`), anyCode, "Use least-privilege file modes (0600 for secrets, 0700 for directories)."},
		{"auth_acl", "wildcard_cors_policy", "MEDIUM", regexp.MustCompile(`(?i)Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]`), anyCode, "Restrict CORS origins to an explicit allowlist of trusted origins."},

		// 5. cryptography
		{"cryptography", "weak_hash_md5_or_sha1", "HIGH", regexp.MustCompile(`(?i)(?:\bhashlib\.(?:md5|sha1)\s*\(|\bcrypto\.createHash\(\s*['"](?:md5|sha1)['"]|\bmd5\.New\(\)|\bsha1\.New\(\))`), anyCode, "Upgrade to SHA-256/BLAKE3 for integrity or Argon2id/PBKDF2-HMAC-SHA256 for passwords."},
		{"cryptography", "ecb_block_cipher_mode", "CRITICAL", regexp.MustCompile(`(?i)(?:MODE_ECB|AES-128-ECB|AES-256-ECB|NewECBEncrypter)`), anyCode, "Use authenticated encryption (AES-256-GCM or ChaCha20-Poly1305)."},
		{"cryptography", "tls_cert_verification_disabled", "CRITICAL", regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|CERT_NONE|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)`), anyCode, "Keep X.509 certificate chain and hostname verification enabled."},
		{"cryptography", "deprecated_tls_version", "HIGH", regexp.MustCompile(`(?i)(?:VersionTLS10|VersionTLS11|PROTOCOL_TLSv1\b|SSLv3)`), anyCode, "Enforce TLS 1.2 minimum (prefer TLS 1.3)."},

		// 6. ai_prompt_safety
		{"ai_prompt_safety", "llm_output_to_exec_sink", "CRITICAL", regexp.MustCompile(`(?i)\b(?:eval|exec|os\.system|subprocess\.\w+)\s*\(\s*(?:llm_output|completion|model_output|response\.text|choice\.message\.content)`), anyCode, "Never execute raw LLM completions; validate structured tool schemas against an allowlist."},
		{"ai_prompt_safety", "system_prompt_user_interpolation", "HIGH", regexp.MustCompile(`(?i)['"]role['"]\s*:\s*['"]system['"].*\{(?:user_input|prompt|query|req\.|request\.)`), anyCode, "Keep system prompts immutable and place untrusted input in isolated `user` messages."},
		{"ai_prompt_safety", "dangerous_remote_model_code_flag", "HIGH", regexp.MustCompile(`(?i)(?:trust_remote_code\s*=\s*True|allow_dangerous_code\s*=\s*True)`), anyCode, "Disable `trust_remote_code=True` and load pinned safetensors weights only."},

		// 7. supply_chain_cicd
		{"supply_chain_cicd", "gha_expression_shell_injection", "CRITICAL", regexp.MustCompile(`\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|head_commit\.message)`), cicdOnly, "Bind untrusted GitHub event context via `env:` instead of inline `${{ ... }}` in `run:` scripts."},
		{"supply_chain_cicd", "gha_unpinned_branch_ref", "HIGH", regexp.MustCompile(`^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:main|master|HEAD)\b`), cicdOnly, "Pin GitHub Actions to an immutable commit SHA or release version tag."},
		{"supply_chain_cicd", "remote_script_pipe_to_shell", "HIGH", regexp.MustCompile(`(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b`), cicdOnly, "Download release artifacts, verify SHA-256 & Ed25519 signature, then execute."},
		{"supply_chain_cicd", "dockerfile_latest_tag", "MEDIUM", regexp.MustCompile(`(?i)^\s*FROM\s+[A-Za-z0-9_./-]+:latest\b`), cicdOnly, "Pin base container images to explicit version tags and `@sha256` digests."},

		// 8. infrastructure_headers
		{"infrastructure_headers", "debug_mode_enabled", "HIGH", regexp.MustCompile(`(?i)(?:\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b)`), anyCode, "Disable debug mode in production configurations."},
		{"infrastructure_headers", "privileged_container_spec", "CRITICAL", regexp.MustCompile(`(?i)^\s*privileged\s*:\s*true\b`), anyCode, "Run containers unprivileged with `allowPrivilegeEscalation: false`."},
		{"infrastructure_headers", "insecure_cookie_flags", "MEDIUM", regexp.MustCompile(`(?i)(?:httponly\s*[:=]\s*false|SESSION_COOKIE_SECURE\s*=\s*False)`), anyCode, "Enable `Secure`, `HttpOnly`, and `SameSite` on session cookies."},
		{"infrastructure_headers", "open_admin_port_ingress", "HIGH", regexp.MustCompile(`(?i)0\.0\.0\.0/0.*(?:22|3389)|(?:22|3389).*0\.0\.0\.0/0`), anyCode, "Restrict SSH/RDP ingress to VPN/WireGuard CIDRs."},
	}
}

func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--")
}

func isTestFile(rel string) bool {
	r := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(r)
	return strings.HasPrefix(base, "test_") ||
		strings.HasSuffix(base, "_test.py") ||
		strings.HasSuffix(base, "_test.go") ||
		strings.Contains(r, "/tests/") ||
		strings.HasPrefix(r, "tests/")
}

func redactSnippet(domain, line string) string {
	s := strings.TrimSpace(line)
	if domain == "secrets" {
		if len(s) > 10 {
			return s[:10] + "...[REDACTED]"
		}
		return "[REDACTED]"
	}
	if len(s) > 96 {
		return s[:93] + "..."
	}
	return s
}

func verdictForScore(score float64) Verdict {
	switch {
	case score >= 90.0:
		return Verdict{Label: "APPROVED", Emoji: "[PASS]", Description: "Production-ready security posture across all 8 domains"}
	case score >= 70.0:
		return Verdict{Label: "APPROVED WITH CAVEATS", Emoji: "[WARN]", Description: "Acceptable with documented mitigations for medium/low findings"}
	case score >= 50.0:
		return Verdict{Label: "PARTIAL BLOCK", Emoji: "[BLOCK]", Description: "Remediation required prior to production deployment"}
	default:
		return Verdict{Label: "TOTAL BLOCK", Emoji: "[CRITICAL]", Description: "Critical security exposure detected; block release"}
	}
}

func ScanDirectory(root string, includeTests bool) (AuditReport, error) {
	t0 := time.Now()
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return AuditReport{}, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return AuditReport{}, err
	}

	var files []string
	if !info.IsDir() {
		files = append(files, absRoot)
	} else {
		_ = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if path != absRoot && skipDirs[name] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			low := strings.ToLower(name)
			ext := strings.ToLower(filepath.Ext(name))
			if scannableExts[ext] || strings.HasPrefix(low, "dockerfile") || strings.HasPrefix(low, "requirements") {
				if len(files) < 10000 {
					files = append(files, path)
				}
			}
			return nil
		})
	}

	rules := buildRules()
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	jobs := make(chan string, len(files))
	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	var mu sync.Mutex
	var allFindings []Finding
	scannedCount := 0

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fp := range jobs {
				rel, err := filepath.Rel(absRoot, fp)
				if err != nil || rel == "." {
					rel = filepath.Base(fp)
				}
				if !includeTests && isTestFile(rel) {
					continue
				}
				st, err := os.Stat(fp)
				if err != nil || st.Size() > 5*1024*1024 {
					continue
				}
				fh, err := os.Open(fp)
				if err != nil {
					continue
				}
				sc := bufio.NewScanner(fh)
				buf := make([]byte, 0, 64*1024)
				sc.Buffer(buf, 1024*1024)

				base := filepath.Base(fp)
				baseLow := strings.ToLower(base)
				extLow := strings.ToLower(filepath.Ext(base))
				isDoc := extLow == ".md" || extLow == ".rst" || (extLow == ".txt" && !strings.HasPrefix(baseLow, "requirements"))
				isScannerDef := strings.HasSuffix(baseLow, "_scanner.py") || base == "domain_engine.py" || base == "config.py"
				var local []Finding
				lineNo := 0
				for sc.Scan() {
					lineNo++
					line := sc.Text()
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || isCommentLine(trimmed) || strings.Contains(trimmed, "regexp.MustCompile(") || strings.Contains(trimmed, "re.compile(") || strings.Contains(trimmed, "AegisScan-ignore") {
						continue
					}
					for _, rule := range rules {
						if (isDoc || isScannerDef) && rule.Domain != "secrets" {
							continue
						}
						if !rule.FileMatcher(rel, base) {
							continue
						}
						if rule.Regex.MatchString(line) {
							local = append(local, Finding{
								Domain:      rule.Domain,
								Pattern:     rule.ID,
								Severity:    rule.Severity,
								File:        filepath.ToSlash(rel),
								Line:        lineNo,
								Snippet:     redactSnippet(rule.Domain, line),
								Remediation: rule.Remediation,
							})
						}
					}
				}
				_ = fh.Close()

				mu.Lock()
				scannedCount++
				allFindings = append(allFindings, local...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].File != allFindings[j].File {
			return allFindings[i].File < allFindings[j].File
		}
		if allFindings[i].Line != allFindings[j].Line {
			return allFindings[i].Line < allFindings[j].Line
		}
		return allFindings[i].Pattern < allFindings[j].Pattern
	})

	deductions := map[string]float64{"CRITICAL": 18, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
	domPenalties := make(map[string]float64, len(Domains))
	domCounts := make(map[string]int, len(Domains))
	for _, d := range Domains {
		domPenalties[d.Key] = 0
		domCounts[d.Key] = 0
	}
	for _, f := range allFindings {
		domCounts[f.Domain]++
		domPenalties[f.Domain] += deductions[f.Severity]
	}

	domScores := make(map[string]float64, len(Domains))
	weighted := 0.0
	for _, d := range Domains {
		s := math.Max(0, 100.0-domPenalties[d.Key])
		domScores[d.Key] = s
		weighted += s * d.Weight
	}
	finalScore := math.Round(weighted*100) / 100

	return AuditReport{
		Scanner:        "aegis-scan",
		Version:        Version,
		Target:         absRoot,
		Timestamp:      time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs:     float64(time.Since(t0).Microseconds()) / 1000.0,
		FilesScanned:   scannedCount,
		TotalFindings:  len(allFindings),
		DomainScores:   domScores,
		DomainFindings: domCounts,
		FinalScore:     finalScore,
		Verdict:        verdictForScore(finalScore),
		Findings:       allFindings,
	}, nil
}

func bar(score float64) string {
	filled := int(math.Round(score / 100.0 * 20.0))
	if filled < 0 {
		filled = 0
	}
	if filled > 20 {
		filled = 20
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", 20-filled) + "]"
}

func printTable(rep AuditReport) {
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("  AegisScan-SCANNER v%s — STANDALONE 8-DOMAIN SECURITY AUDIT REPORT\n", rep.Version)
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("  Target         : %s\n", rep.Target)
	fmt.Printf("  Files Scanned  : %d (in %.2f ms)\n", rep.FilesScanned, rep.DurationMs)
	fmt.Printf("  Total Findings : %d\n", rep.TotalFindings)
	fmt.Println(strings.Repeat("-", 78))
	fmt.Printf("  %-34s %6s  %6s  %8s  %s\n", "Security Domain", "Weight", "Score", "Findings", "Posture")
	fmt.Printf("  %-34s %6s  %6s  %8s  %s\n", strings.Repeat("-", 34), "------", "------", "--------", strings.Repeat("-", 22))
	for _, d := range Domains {
		sc := rep.DomainScores[d.Key]
		fc := rep.DomainFindings[d.Key]
		fmt.Printf("  %-34s %5.0f%%  %6.1f  %8d  %s\n", d.Label, d.Weight*100, sc, fc, bar(sc))
	}
	if len(rep.Findings) > 0 {
		fmt.Println(strings.Repeat("-", 78))
		fmt.Println("  TOP FINDINGS:")
		limit := len(rep.Findings)
		if limit > 15 {
			limit = 15
		}
		for _, f := range rep.Findings[:limit] {
			fmt.Printf("    [%-8s] %-22s %-30s (%s:%d)\n", f.Severity, f.Domain, f.Pattern, f.File, f.Line)
		}
	}
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("  FINAL SCORE    : %.2f / 100.00\n", rep.FinalScore)
	fmt.Printf("  VERDICT        : %s %s — %s\n", rep.Verdict.Emoji, rep.Verdict.Label, rep.Verdict.Description)
	fmt.Println(strings.Repeat("=", 78))
}

func main() {
	targetFlag := flag.String("target", "", "Target directory or file to scan")
	formatFlag := flag.String("format", "table", "Output format: table or json")
	jsonFlag := flag.Bool("json", false, "Shorthand for --format json")
	includeTests := flag.Bool("include-tests", false, "Include test files in scan")
	failUnder := flag.Float64("fail-under", 0, "Exit non-zero if score falls below threshold")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("aegis-scan v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	target := *targetFlag
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}
	if target == "" {
		target = "."
	}

	rep, err := ScanDirectory(target, *includeTests)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-scan error: %v\n", err)
		os.Exit(2)
	}

	if *jsonFlag || strings.EqualFold(*formatFlag, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printTable(rep)
	}

	if *failUnder > 0 && rep.FinalScore < *failUnder {
		os.Exit(1)
	}
}
