package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

const grypeReportJSON = `{
  "distro": {"name": "alpine", "version": "3.21.0"},
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-0001",
        "severity": "High",
        "description": "openssl: something bad",
        "fix": {"versions": ["3.1.4", "3.2.0"]},
        "cvss": [
          {"source": "redhat", "metrics": {"baseScore": 5.5}},
          {"source": "nvd@2.0", "metrics": {"baseScore": 9.8}}
        ]
      },
      "artifact": {
        "name": "openssl", "version": "3.1.0", "type": "apk",
        "locations": [{"path": "/lib/apk/db/installed"}]
      }
    },
    {
      "vulnerability": {"id": "CVE-2024-0002", "severity": "Negligible", "cvss": []},
      "artifact": {"name": "busybox", "version": "1.36", "type": "apk"}
    }
  ]
}`

func TestParseGrypeReadsWhatTheScannerReported(t *testing.T) {
	result, err := ParseGrype("node:22-alpine", []byte(grypeReportJSON), "2026-01-01T00:00:00+00:00")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.Scanner != "grype" {
		t.Fatalf("scanner: %q", result.Scanner)
	}
	if result.OSFamily != "alpine" || result.OSVersion != "3.21.0" {
		t.Fatalf("distro vem do bloco `distro`, veio %q/%q", result.OSFamily, result.OSVersion)
	}
	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("esperados 2 achados, vieram %d", len(result.Vulnerabilities))
	}

	first := result.Vulnerabilities[0]
	if first.Severity != "HIGH" {
		t.Errorf("severidade: %q", first.Severity)
	}
	if first.FixedVersion != "3.1.4" {
		t.Errorf("a primeira versão corrigida é a que vale: %q", first.FixedVersion)
	}
	if first.Target != "/lib/apk/db/installed" {
		t.Errorf("target: %q", first.Target)
	}
}

func TestNegligibleBecomesLowBecauseTheDomainHasNoFifthLevel(t *testing.T) {
	result, _ := ParseGrype("x", []byte(grypeReportJSON), "t")
	if got := result.Vulnerabilities[1].Severity; got != "LOW" {
		t.Fatalf("Negligible tem de virar LOW, veio %q", got)
	}
}

func TestTheNVDScoreWinsOverAVendorScore(t *testing.T) {
	// Não é `max()`: NVD tem precedência declarada, e um max entre bases
	// diferentes produz um número que nenhuma delas publicou.
	result, _ := ParseGrype("x", []byte(grypeReportJSON), "t")
	v := result.Vulnerabilities[0]
	if v.CVSSScore != 9.8 || !strings.Contains(v.CVSSSource, "nvd") {
		t.Fatalf("esperado nvd/9.8, veio %q/%v", v.CVSSSource, v.CVSSScore)
	}
}

func TestANullMetricsBlockReadsAsUnscored(t *testing.T) {
	// O Grype emite `"metrics": null` para advisory sem vetor CVSS. Isso
	// tem de ler como "sem pontuação", não derrubar o scan inteiro.
	raw := `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High",
		"cvss":[{"source":"alpine","metrics":null}]},"artifact":{"name":"p"}}]}`
	result, err := ParseGrype("x", []byte(raw), "t")
	if err != nil {
		t.Fatalf("um metrics nulo derrubou a leitura: %v", err)
	}
	if result.Vulnerabilities[0].CVSSScore != 0 {
		t.Fatalf("score: %v", result.Vulnerabilities[0].CVSSScore)
	}
}

func TestNoFixMeansNoFixedVersion(t *testing.T) {
	raw := `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High","fix":{"versions":[]}},
		"artifact":{"name":"p"}}]}`
	result, _ := ParseGrype("x", []byte(raw), "t")
	if result.Vulnerabilities[0].FixedVersion != "" {
		t.Fatal("uma lista de correções vazia não é uma correção")
	}
}

func TestAnEmptyGrypeReportIsAScanWithNoFindings(t *testing.T) {
	result, err := ParseGrype("x", []byte(`{"matches":[]}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != protocol.StatusOK || len(result.Vulnerabilities) != 0 {
		t.Fatalf("veio %s com %d achados", result.Status, len(result.Vulnerabilities))
	}
}

func TestUnparseableGrypeOutputIsAnError(t *testing.T) {
	if _, err := ParseGrype("x", []byte("{nope"), "t"); err == nil {
		t.Fatal("JSON quebrado tem de virar erro")
	}
}

func newGrypeScanner(t *testing.T, path string) *Scanner {
	t.Helper()
	return NewScanner(protocol.Request{
		Scanner:        "grype",
		ScannerPath:    path,
		TimeoutSeconds: 10,
		SkipDBUpdate:   true,
		Env:            map[string]string{"GRYPE_DB_AUTO_UPDATE": "false"},
	}, defaultTestMaxOutput)
}

func TestTheGrypeCommandLineIsGrypesAndNotTrivys(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	scanner := fakeScanner(t, fmt.Sprintf(
		"echo \"$@\" > %s\ncat <<'R'\n{\"matches\":[]}\nR\n", argvFile))

	newGrypeScanner(t, scanner).Scan(context.Background(), "node:22", "/some/cache")

	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	line := string(argv)
	if !strings.Contains(line, "-o json") {
		t.Errorf("argv do grype: %q", line)
	}
	// O Grype não tem `--cache-dir` nem as flags de DB do Trivy: passá-las
	// faria o binário recusar a linha inteira.
	for _, forbidden := range []string{"--cache-dir", "--skip-db-update", "image"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("%q não pertence ao argv do grype: %q", forbidden, line)
		}
	}
}

func TestTheEnvironmentReachesTheScannerWithoutReplacingIt(t *testing.T) {
	// O Grype desliga a atualização automática por variável de ambiente, e
	// não por flag. Trocar o ambiente inteiro por essa variável tiraria
	// PATH, HOME e as de proxy do processo -- e o scan pararia por outro
	// motivo.
	out := filepath.Join(t.TempDir(), "env")
	scanner := fakeScanner(t, fmt.Sprintf(
		"echo \"$GRYPE_DB_AUTO_UPDATE|$PATH\" > %s\ncat <<'R'\n{\"matches\":[]}\nR\n", out))

	newGrypeScanner(t, scanner).Scan(context.Background(), "node:22", "")

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	value, path, _ := strings.Cut(strings.TrimSpace(string(data)), "|")
	if value != "false" {
		t.Errorf("GRYPE_DB_AUTO_UPDATE: %q", value)
	}
	if path == "" {
		t.Error("o ambiente herdado foi substituído em vez de somado")
	}
}

func TestAFailedGrypeScanNamesGrype(t *testing.T) {
	scanner := fakeScanner(t, "echo 'UNAUTHORIZED: authentication required' >&2\nexit 1\n")
	result := newGrypeScanner(t, scanner).Scan(context.Background(), "node:22", "")

	if result.Scanner != "grype" {
		t.Fatalf("um resultado do grype dizia ser do %q", result.Scanner)
	}
	if result.ErrorKind != protocol.KindAuthRequired {
		t.Fatalf("classificação: %s", result.ErrorKind)
	}
}

func TestGrypeIsNotSerializedForLackOfCacheDirs(t *testing.T) {
	// Serializá-lo por falta de `--cache-dir` seria aplicar a ele o remédio
	// de uma doença que ele não tem: o lock BoltDB é do Trivy.
	grype := NewScanner(protocol.Request{Scanner: "grype", TimeoutSeconds: 1}, 1024)
	if got := NewOrchestrator(grype, 8, nil).Workers(); got != 8 {
		t.Fatalf("grype com 8 workers e nenhum cache dir virou %d", got)
	}

	trivy := NewScanner(protocol.Request{Scanner: "trivy", TimeoutSeconds: 1}, 1024)
	if got := NewOrchestrator(trivy, 8, nil).Workers(); got != 1 {
		t.Fatalf("trivy sem cache dir tem de serializar, veio %d", got)
	}
}
