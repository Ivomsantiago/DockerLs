package scan

import (
	"strings"
	"testing"
)

const trivyReportJSON = `{
  "Metadata": {"OS": {"Family": "alpine", "Name": "3.21.0"}},
  "Results": [
    {
      "Target": "node:22-alpine (alpine 3.21.0)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0001",
          "Severity": "CRITICAL",
          "SeveritySource": "nvd",
          "PkgName": "openssl",
          "InstalledVersion": "3.1.0",
          "FixedVersion": "3.1.4",
          "Title": "openssl: something bad",
          "PublishedDate": "2024-01-02T00:00:00Z",
          "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 7.5}}
        }
      ]
    },
    {
      "Target": "/usr/local/lib/node_modules/npm/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "node-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0002",
          "Severity": "definitely-not-a-severity",
          "PkgName": "cross-spawn",
          "InstalledVersion": "7.0.3"
        }
      ]
    }
  ]
}`

func TestParseTrivyReadsWhatTheScannerReported(t *testing.T) {
	result, err := ParseTrivy("node:22-alpine", []byte(trivyReportJSON), "2026-01-01T00:00:00+00:00")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.Status != "OK" || result.ErrorKind != "NONE" {
		t.Fatalf("um relatório legível é um scan OK, veio %s/%s", result.Status, result.ErrorKind)
	}
	if result.OSFamily != "alpine" || result.OSVersion != "3.21.0" {
		t.Fatalf("distro base vem do Metadata.OS, veio %q/%q", result.OSFamily, result.OSVersion)
	}
	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("esperados 2 achados, vieram %d", len(result.Vulnerabilities))
	}

	first := result.Vulnerabilities[0]
	if first.PackageType != "os-pkgs" {
		t.Errorf("Class tem precedência sobre Type: %q", first.PackageType)
	}
	if first.CVSSScore != 9.8 || first.CVSSSource != "nvd" {
		t.Errorf("o score tem de vir da base que definiu a severidade: %v/%q",
			first.CVSSScore, first.CVSSSource)
	}
}

func TestAnUnknownSeverityBecomesUNKNOWNAndNotTheRawString(t *testing.T) {
	result, err := ParseTrivy("x", []byte(trivyReportJSON), "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Vulnerabilities[1].Severity; got != "UNKNOWN" {
		t.Fatalf("severidade desconhecida tem de virar UNKNOWN, veio %q", got)
	}
}

func TestTheCVSSSourceFollowsTheSeveritySource(t *testing.T) {
	// O caso que produzia `CRITICAL ... 7.5`: severidade vinda do vendor
	// da distro, número vindo do NVD. Se a fonte da severidade pontua, é
	// o número dela que vale.
	raw := `{"Results":[{"Vulnerabilities":[{
		"VulnerabilityID":"CVE-1","Severity":"HIGH","SeveritySource":"redhat",
		"CVSS":{"nvd":{"V3Score":9.8},"redhat":{"V3Score":7.5}}}]}]}`
	result, err := ParseTrivy("x", []byte(raw), "t")
	if err != nil {
		t.Fatal(err)
	}
	v := result.Vulnerabilities[0]
	if v.CVSSSource != "redhat" || v.CVSSScore != 7.5 {
		t.Fatalf("esperado redhat/7.5, veio %q/%v", v.CVSSSource, v.CVSSScore)
	}
}

func TestAV4ScoreWinsOverV3InTheSameEntry(t *testing.T) {
	raw := `{"Results":[{"Vulnerabilities":[{
		"VulnerabilityID":"CVE-1","Severity":"HIGH",
		"CVSS":{"nvd":{"V4Score":8.1,"V3Score":9.8}}}]}]}`
	result, err := ParseTrivy("x", []byte(raw), "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Vulnerabilities[0].CVSSScore; got != 8.1 {
		t.Fatalf("V4 tem precedência sobre V3, veio %v", got)
	}
}

func TestASourceWithoutAScoreFallsThroughInsteadOfReportingZero(t *testing.T) {
	// Debian, Alpine e Ubuntu classificam sem pontuar. Reportar 0.0 com a
	// fonte deles diria "esta base pontuou zero", que é falso.
	raw := `{"Results":[{"Vulnerabilities":[{
		"VulnerabilityID":"CVE-1","Severity":"HIGH","SeveritySource":"debian",
		"CVSS":{"debian":{},"nvd":{"V3Score":9.8}}}]}]}`
	result, err := ParseTrivy("x", []byte(raw), "t")
	if err != nil {
		t.Fatal(err)
	}
	v := result.Vulnerabilities[0]
	if v.CVSSSource != "nvd" || v.CVSSScore != 9.8 {
		t.Fatalf("esperado nvd/9.8, veio %q/%v", v.CVSSSource, v.CVSSScore)
	}
}

func TestNoCVSSBlockMeansNoScoreAndNoSource(t *testing.T) {
	raw := `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"LOW"}]}]}`
	result, err := ParseTrivy("x", []byte(raw), "t")
	if err != nil {
		t.Fatal(err)
	}
	v := result.Vulnerabilities[0]
	if v.CVSSScore != 0 || v.CVSSSource != "" {
		t.Fatalf("sem bloco CVSS não há número nem fonte, veio %v/%q", v.CVSSScore, v.CVSSSource)
	}
}

func TestTheSourceChoiceIsStableAcrossRuns(t *testing.T) {
	// Iterar um map em Go é deliberadamente aleatório. Sem ordenação, o
	// mesmo relatório produziria fontes diferentes entre dois runs.
	raw := `{"Results":[{"Vulnerabilities":[{
		"VulnerabilityID":"CVE-1","Severity":"HIGH",
		"CVSS":{"zzz":{"V3Score":1.0},"aaa":{"V3Score":2.0},"mmm":{"V3Score":3.0}}}]}]}`
	var first string
	for i := 0; i < 50; i++ {
		result, err := ParseTrivy("x", []byte(raw), "t")
		if err != nil {
			t.Fatal(err)
		}
		source := result.Vulnerabilities[0].CVSSSource
		if i == 0 {
			first = source
			continue
		}
		if source != first {
			t.Fatalf("fonte instável entre runs: %q depois %q", first, source)
		}
	}
}

func TestTheTitleIsTruncatedWithoutBreakingUTF8(t *testing.T) {
	long := strings.Repeat("á", 300) // 600 bytes
	raw := `{"Results":[{"Vulnerabilities":[{
		"VulnerabilityID":"CVE-1","Severity":"LOW","Title":"` + long + `"}]}]}`
	result, err := ParseTrivy("x", []byte(raw), "t")
	if err != nil {
		t.Fatal(err)
	}
	got := result.Vulnerabilities[0].Description
	if len(got) > maxDescriptionBytes {
		t.Fatalf("descrição passou do teto: %d bytes", len(got))
	}
	if strings.ContainsRune(got, '�') {
		t.Fatal("corte no meio de um caractere UTF-8")
	}
}

func TestUnparseableJSONIsAnError(t *testing.T) {
	if _, err := ParseTrivy("x", []byte("{not json"), "t"); err == nil {
		t.Fatal("JSON quebrado tem de virar erro, não um scan vazio")
	}
}

func TestAnEmptyReportIsAScanWithNoFindings(t *testing.T) {
	// Um scan que rodou e não achou nada é diferente de um que não rodou:
	// o primeiro é OK com lista vazia, e é o único que pode ser pontuado.
	result, err := ParseTrivy("x", []byte(`{"Results":[]}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "OK" || len(result.Vulnerabilities) != 0 {
		t.Fatalf("esperado OK sem achados, veio %s com %d",
			result.Status, len(result.Vulnerabilities))
	}
}
