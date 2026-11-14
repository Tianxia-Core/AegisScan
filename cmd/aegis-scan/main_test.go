// ffp: FFP-AEGIS-SCAN-GO-TEST io-edge go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanDirectoryScores100(t *testing.T) {
	dir := t.TempDir()
	cleanSrc := "package sample\n\nfunc Add(a, b int) int { return a + b }\n"
	if err := os.WriteFile(filepath.Join(dir, "math.go"), []byte(cleanSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := ScanDirectory(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FinalScore != 100.0 || rep.TotalFindings != 0 {
		t.Fatalf("expected 100.0 score on clean code, got %.2f (%+v)", rep.FinalScore, rep.Findings)
	}
}

func TestAllEightDomainsDetectFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Construct synthetic tokens dynamically so static scanners never flag this test source
	fakePat := "gh" + "p_" + strings.Repeat("Z", 38)
	appPy := strings.Join([]string{
		"TOKEN = '" + fakePat + "'",
		"eval(user_code)",
		"if username == 'admin': pass",
		"digest = hashlib.md5(b'abc')",
		"eval(llm_output)",
		"DEBUG = True",
	}, "\n") + "\n"

	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(appPy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests>=2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wf := "steps:\n  - uses: example/action@master\n"
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "bad.yml"), []byte(wf), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := ScanDirectory(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range Domains {
		if rep.DomainFindings[d.Key] < 1 {
			t.Errorf("expected domain %q to detect at least 1 finding, got 0", d.Key)
		}
		if rep.DomainScores[d.Key] >= 100.0 {
			t.Errorf("expected domain %q score < 100, got %.1f", d.Key, rep.DomainScores[d.Key])
		}
	}
	if rep.FinalScore >= 90.0 {
		t.Fatalf("expected vulnerable fixture to score < 90, got %.2f", rep.FinalScore)
	}
}
