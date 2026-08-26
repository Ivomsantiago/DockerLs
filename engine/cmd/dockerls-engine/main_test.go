package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

func fakeTrivy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAVersionMismatchIsRefusedBeforeAnyFieldIsUsed(t *testing.T) {
	// É assim que um contrato entre linguagens apodrece em silêncio: um
	// binário antigo lendo campos que mudaram de sentido.
	_, err := readRequest(strings.NewReader(`{"version": 999, "scanner": "trivy"}`))
	if err == nil || !strings.Contains(err.Error(), "protocol version mismatch") {
		t.Fatalf("esperada recusa por versão, veio %v", err)
	}
}

func TestTheEngineDoesNotResolvePATHItself(t *testing.T) {
	// Quem decide qual binário roda é o lado que já tem política sobre
	// isso; aceitar um nome para resolver aqui abriria a porta que
	// `utils/executables.py` fecha.
	body := fmt.Sprintf(`{"version": %d, "scanner": "trivy", "timeout_seconds": 5}`, protocol.Version)
	_, err := readRequest(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "scanner_path") {
		t.Fatalf("esperada recusa por scanner_path ausente, veio %v", err)
	}
}

func TestAnUnsupportedScannerIsRefused(t *testing.T) {
	body := fmt.Sprintf(`{"version": %d, "scanner": "grype", "scanner_path": "/x", "timeout_seconds": 5}`, protocol.Version)
	if _, err := readRequest(strings.NewReader(body)); err == nil {
		t.Fatal("esta engine só dirige o trivy")
	}
}

func TestANonPositiveTimeoutIsRefused(t *testing.T) {
	body := fmt.Sprintf(`{"version": %d, "scanner": "trivy", "scanner_path": "/x", "timeout_seconds": 0}`, protocol.Version)
	if _, err := readRequest(strings.NewReader(body)); err == nil {
		t.Fatal("um timeout de zero mataria todo scan na largada")
	}
}

func TestAnOversizedRequestIsRefusedInsteadOfBuffered(t *testing.T) {
	huge := strings.NewReader(strings.Repeat("a", int(maxRequestBytes)+10))
	if _, err := readRequest(huge); err == nil {
		t.Fatal("um stdin que não termina não pode virar memória sem limite")
	}
}

func TestGarbageOnStdinIsAFatalErrorInJSONAndNotAPanic(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), strings.NewReader("{{{"), &out)
	if err == nil {
		t.Fatal("esperado erro")
	}
}

func TestARunEndToEnd(t *testing.T) {
	report := `{"Metadata":{"OS":{"Family":"alpine","Name":"3.21"}},"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","Severity":"HIGH","SeveritySource":"nvd","PkgName":"openssl","FixedVersion":"3.1.4","CVSS":{"nvd":{"V3Score":7.5}}}]}]}`
	trivy := fakeTrivy(t, "cat <<'EOF'\n"+report+"\nEOF\n")

	request, err := json.Marshal(protocol.Request{
		Version:        protocol.Version,
		Scanner:        "trivy",
		ScannerPath:    trivy,
		Workers:        2,
		TimeoutSeconds: 10,
		CacheDirs:      []string{t.TempDir(), t.TempDir()},
		Targets: []protocol.Target{
			{Reference: "node:22", DedupKey: "sha256:aaa"},
			{Reference: "node:lts", DedupKey: "sha256:aaa"},
			{Reference: "node:20", DedupKey: "sha256:bbb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(request), &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	var response protocol.Response
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("a saída não é o documento contratado: %v\n%s", err, out.String())
	}
	if response.Version != protocol.Version {
		t.Fatalf("versão na resposta: %d", response.Version)
	}
	if response.FatalError != "" {
		t.Fatalf("erro fatal: %s", response.FatalError)
	}
	if len(response.Results) != 3 {
		t.Fatalf("três alvos, %d resultados", len(response.Results))
	}
	if response.Metrics.ScansPerformed != 2 {
		t.Fatalf("dois digests, %d scans", response.Metrics.ScansPerformed)
	}
	if response.Metrics.DuplicatesCollapsed != 1 {
		t.Fatalf("um alvo colapsado, %d", response.Metrics.DuplicatesCollapsed)
	}
	for _, r := range response.Results {
		if r.Status != protocol.StatusOK {
			t.Fatalf("%s: %s/%s", r.ImageReference, r.Status, r.ErrorMessage)
		}
		if len(r.Vulnerabilities) != 1 || r.Vulnerabilities[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("%s: achados %+v", r.ImageReference, r.Vulnerabilities)
		}
		if r.OSFamily != "alpine" {
			t.Fatalf("%s: distro %q", r.ImageReference, r.OSFamily)
		}
	}
}

func TestAFailingTargetDoesNotBringDownTheRun(t *testing.T) {
	// Uma imagem que não pôde ser medida é uma medição ausente, não uma
	// quebra do run: as outras continuam valendo.
	report := `{"Results":[]}`
	trivy := fakeTrivy(t, fmt.Sprintf(
		"case \"$*\" in *broken*) echo 'UNAUTHORIZED: authentication required' >&2; exit 1;; esac\ncat <<'EOF'\n%s\nEOF\n", report))

	request, _ := json.Marshal(protocol.Request{
		Version:        protocol.Version,
		Scanner:        "trivy",
		ScannerPath:    trivy,
		Workers:        2,
		TimeoutSeconds: 10,
		CacheDirs:      []string{t.TempDir(), t.TempDir()},
		Targets: []protocol.Target{
			{Reference: "good:1"},
			{Reference: "broken:1"},
			{Reference: "good:2"},
		},
	})

	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(request), &out); err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Results[0].Status != protocol.StatusOK || response.Results[2].Status != protocol.StatusOK {
		t.Fatal("um alvo com falha derrubou os vizinhos")
	}
	if response.Results[1].ErrorKind != protocol.KindAuthRequired {
		t.Fatalf("classificação do alvo com falha: %s", response.Results[1].ErrorKind)
	}
}
