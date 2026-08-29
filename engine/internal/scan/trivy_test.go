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

func newTestScanner(t *testing.T, path string, timeoutSeconds float64, rawDir string) *Scanner {
	t.Helper()
	return NewScanner(protocol.Request{
		ScannerPath:    path,
		TimeoutSeconds: timeoutSeconds,
		RawDir:         rawDir,
	}, defaultTestMaxOutput)
}

func TestAFailedScanIsAResultAndNeverAnEmptyFindingList(t *testing.T) {
	// A distinção que sustenta o projeto inteiro: uma imagem que não pôde
	// ser medida não é uma imagem limpa.
	scanner := fakeScanner(t, "echo 'MANIFEST_UNKNOWN: manifest unknown' >&2\nexit 1\n")
	result := newTestScanner(t, scanner, 10, "").Scan(context.Background(), "node:nope", "")

	if result.Status != protocol.StatusError {
		t.Fatalf("esperado ERROR, veio %s", result.Status)
	}
	if result.ErrorKind != protocol.KindNotFound {
		t.Fatalf("stderr classificado como %s", result.ErrorKind)
	}
	if !strings.Contains(result.ErrorMessage, "manifest unknown") {
		t.Fatalf("a mensagem completa se perdeu: %q", result.ErrorMessage)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Fatal("um scan que falhou não tem achados")
	}
}

func TestAScanThatWritesNothingIsInvalidOutput(t *testing.T) {
	scanner := fakeScanner(t, "exit 0\n")
	result := newTestScanner(t, scanner, 10, "").Scan(context.Background(), "node:22", "")
	if result.ErrorKind != protocol.KindInvalidOutput {
		t.Fatalf("saída vazia com código 0 é INVALID_OUTPUT, veio %s", result.ErrorKind)
	}
}

func TestUnparseableOutputIsInvalidOutputAndNotACrash(t *testing.T) {
	scanner := fakeScanner(t, "echo 'not json at all'\n")
	result := newTestScanner(t, scanner, 10, "").Scan(context.Background(), "node:22", "")
	if result.Status != protocol.StatusError || result.ErrorKind != protocol.KindInvalidOutput {
		t.Fatalf("veio %s/%s", result.Status, result.ErrorKind)
	}
}

func TestAMissingBinaryIsReportedAsScannerMissing(t *testing.T) {
	result := newTestScanner(t, "/nonexistent/trivy", 10, "").Scan(context.Background(), "node:22", "")
	if result.ErrorKind != protocol.KindScannerMissing {
		t.Fatalf("esperado SCANNER_MISSING, veio %s (%s)", result.ErrorKind, result.ErrorMessage)
	}
}

func TestAScanThatOverrunsItsTimeoutIsTIMEOUTAndTheProcessIsKilled(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "survivor")
	// O filho tenta escrever bem depois do timeout. Se o arquivo existir
	// no fim, ele sobreviveu -- que era exatamente o vazamento do
	// `wait_for` do Python: cancelava o await, não o processo.
	scanner := fakeScanner(t, fmt.Sprintf("sleep 5\ntouch %s\n", marker))

	result := newTestScanner(t, scanner, 0.3, "").Scan(context.Background(), "node:22", "")

	if result.Status != protocol.StatusTimeout || result.ErrorKind != protocol.KindTimeout {
		t.Fatalf("veio %s/%s", result.Status, result.ErrorKind)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("o scanner sobreviveu ao próprio timeout")
	}
}

func TestOutputBeyondTheCeilingIsRefusedInsteadOfAccumulated(t *testing.T) {
	// Saída sem limite não é medição: o documento nunca foi lido inteiro,
	// então não há o que interpretar.
	scanner := fakeScanner(t, "head -c 200000 /dev/zero | tr '\\0' 'a'\n")
	s := NewScanner(protocol.Request{ScannerPath: scanner, TimeoutSeconds: 10}, 1024)
	result := s.Scan(context.Background(), "node:22", "")
	if result.ErrorKind != protocol.KindInvalidOutput {
		t.Fatalf("esperado INVALID_OUTPUT, veio %s (%s)", result.ErrorKind, result.ErrorMessage)
	}
}

func TestAReferenceTheEngineCannotVouchForNeverReachesArgv(t *testing.T) {
	// Segunda tranca. A CLI já sanitiza e já aplica a política de rede;
	// isto recusa o que só chegaria aqui vindo de outro chamador.
	marker := filepath.Join(t.TempDir(), "ran")
	scanner := fakeScanner(t, fmt.Sprintf("touch %s\n", marker))
	s := newTestScanner(t, scanner, 10, "")

	for _, bad := range []string{
		"node:22; rm -rf /",
		"node:22 --config /etc/evil",
		"--config=/etc/evil",
		"node\n:22",
		"node:22\x00",
		"",
		strings.Repeat("a", 600),
	} {
		result := s.Scan(context.Background(), bad, "")
		if result.Status != protocol.StatusError {
			t.Errorf("%q passou pela validação", bad)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("o binário chegou a ser invocado para uma referência recusada")
	}
}

func TestAWellFormedReferenceIsAccepted(t *testing.T) {
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	s := newTestScanner(t, scanner, 10, "")
	for _, good := range []string{
		"node:22-alpine",
		"registry.internal:5000/team/app:1.2.3",
		"gcr.io/distroless/nodejs22-debian12",
		"node@sha256:" + strings.Repeat("a", 64),
	} {
		if result := s.Scan(context.Background(), good, ""); result.Status != protocol.StatusOK {
			t.Errorf("%q recusada: %s (%s)", good, result.ErrorKind, result.ErrorMessage)
		}
	}
}

func TestSkipDBUpdateAlsoSkipsTheJavaDB(t *testing.T) {
	// A DB de Java é baixada separadamente. Sem o par, cada worker ainda
	// saía para a rede buscá-la -- a corrida que o pool de cache existe
	// para eliminar.
	argvFile := filepath.Join(t.TempDir(), "argv")
	scanner := fakeScanner(t, fmt.Sprintf("echo \"$@\" > %s\ncat <<'EOF'\n%s\nEOF\n", argvFile, okReport))
	s := NewScanner(protocol.Request{
		ScannerPath:    scanner,
		TimeoutSeconds: 10,
		SkipDBUpdate:   true,
	}, defaultTestMaxOutput)

	s.Scan(context.Background(), "node:22", "")

	data, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(data)
	for _, flag := range []string{"--skip-db-update", "--skip-java-db-update"} {
		if !strings.Contains(argv, flag) {
			t.Errorf("%s ausente em %q", flag, argv)
		}
	}
}

func TestTheRawJSONIsKeptForThePythonSideToRedactAndArchive(t *testing.T) {
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	rawDir := t.TempDir()
	result := newTestScanner(t, scanner, 10, rawDir).Scan(context.Background(), "node:22", "")

	if result.RawPath == "" {
		t.Fatal("nenhuma evidência guardada")
	}
	data, err := os.ReadFile(result.RawPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "alpine") {
		t.Fatalf("a evidência não é a saída do scanner: %q", string(data))
	}
	info, err := os.Stat(result.RawPath)
	if err != nil {
		t.Fatal(err)
	}
	// 0600 porque o JSON cru pode conter o eco de um pull autenticado, e
	// é justamente por isso que o Python o redige antes de arquivar.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("evidência com permissão %v", perm)
	}
}

func TestWithoutARawDirNothingIsWrittenToDisk(t *testing.T) {
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	result := newTestScanner(t, scanner, 10, "").Scan(context.Background(), "node:22", "")
	if result.RawPath != "" {
		t.Fatalf("evidência gravada sem ninguém pedir: %q", result.RawPath)
	}
}

func TestACancelledContextStopsTheScanInFlight(t *testing.T) {
	scanner := fakeScanner(t, "sleep 5\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := newTestScanner(t, scanner, 10, "").Scan(ctx, "node:22", "")
	if result.Status == protocol.StatusOK {
		t.Fatal("um scan cancelado não é um scan bem-sucedido")
	}
}
