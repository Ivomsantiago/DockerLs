package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// fakeScanner escreve um script que se passa pelo Trivy. Um duplo em Go
// não serviria: o que está sob teste aqui é a execução de um processo
// externo, com argv, códigos de saída e streams reais.
func fakeScanner(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-trivy")
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestOrchestrator(t *testing.T, scannerPath string, workers int, cacheDirs []string) *Orchestrator {
	t.Helper()
	req := protocol.Request{
		Scanner:        "trivy",
		ScannerPath:    scannerPath,
		Workers:        workers,
		TimeoutSeconds: 10,
	}
	return NewOrchestrator(NewScanner(req, defaultTestMaxOutput), workers, cacheDirs)
}

const defaultTestMaxOutput = 8 * 1024 * 1024

const okReport = `{"Metadata":{"OS":{"Family":"alpine","Name":"3.21"}},"Results":[]}`

func TestTagsSharingADigestAreScannedOnce(t *testing.T) {
	// A economia real do pipeline: `node:22`, `node:22.14` e `node:lts`
	// costumam ser o mesmo manifesto, e medir os três é pagar três vezes
	// pela mesma resposta.
	counter := filepath.Join(t.TempDir(), "calls")
	scanner := fakeScanner(t, fmt.Sprintf("echo x >> %s\ncat <<'EOF'\n%s\nEOF\n", counter, okReport))

	o := newTestOrchestrator(t, scanner, 4, []string{t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()})
	results, metrics := o.Run(context.Background(), []protocol.Target{
		{Reference: "node:22", DedupKey: "sha256:aaa"},
		{Reference: "node:22.14", DedupKey: "sha256:aaa"},
		{Reference: "node:lts", DedupKey: "sha256:aaa"},
		{Reference: "node:20", DedupKey: "sha256:bbb"},
	})

	if metrics.ScansPerformed != 2 {
		t.Fatalf("dois digests, dois scans; vieram %d", metrics.ScansPerformed)
	}
	if metrics.DuplicatesCollapsed != 2 {
		t.Fatalf("dois alvos colapsados, veio %d", metrics.DuplicatesCollapsed)
	}
	if len(results) != 4 {
		t.Fatalf("todo alvo recebe resultado, vieram %d", len(results))
	}
	data, _ := os.ReadFile(counter)
	if got := strings.Count(string(data), "x"); got != 2 {
		t.Fatalf("o binário foi chamado %d vezes, esperadas 2", got)
	}
}

func TestEveryTargetKeepsItsOwnReference(t *testing.T) {
	// Os irmãos compartilham o manifesto, mas o usuário pediu por *aquele*
	// nome e é ele que tem de aparecer no relatório.
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	o := newTestOrchestrator(t, scanner, 2, []string{t.TempDir(), t.TempDir()})
	targets := []protocol.Target{
		{Reference: "node:22", DedupKey: "sha256:aaa"},
		{Reference: "node:lts", DedupKey: "sha256:aaa"},
	}
	results, _ := o.Run(context.Background(), targets)
	for i, r := range results {
		if r.ImageReference != targets[i].Reference {
			t.Errorf("resultado %d veio como %q, esperado %q", i, r.ImageReference, targets[i].Reference)
		}
	}
	if results[0].FromDedup == results[1].FromDedup {
		t.Fatal("exatamente um dos dois foi servido pelo irmão")
	}
}

func TestTargetsWithoutADigestAreNeverCollapsedTogether(t *testing.T) {
	// Chave vazia como chave comum faria imagens diferentes
	// compartilharem uma medição -- o pior resultado possível aqui.
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	o := newTestOrchestrator(t, scanner, 2, nil)
	_, metrics := o.Run(context.Background(), []protocol.Target{
		{Reference: "alpine:3.21"},
		{Reference: "debian:12"},
	})
	if metrics.ScansPerformed != 2 || metrics.DuplicatesCollapsed != 0 {
		t.Fatalf("sem digest cada referência responde por si: %d scans, %d colapsados",
			metrics.ScansPerformed, metrics.DuplicatesCollapsed)
	}
}

func TestResultsComeBackInTheOrderTheyWereAsked(t *testing.T) {
	// O ranking é do Python; saída em ordem de chegada tornaria o
	// resultado dependente do escalonador.
	scanner := fakeScanner(t, "cat <<'EOF'\n"+okReport+"\nEOF\n")
	o := newTestOrchestrator(t, scanner, 8, []string{t.TempDir(), t.TempDir(), t.TempDir()})
	targets := make([]protocol.Target, 30)
	for i := range targets {
		targets[i] = protocol.Target{Reference: fmt.Sprintf("img:%d", i)}
	}
	results, _ := o.Run(context.Background(), targets)
	for i, r := range results {
		if want := fmt.Sprintf("img:%d", i); r.ImageReference != want {
			t.Fatalf("posição %d trouxe %q", i, r.ImageReference)
		}
	}
}

func TestNoMoreScansRunAtOnceThanThereAreWorkers(t *testing.T) {
	// O Trivy toma lock exclusivo no cache: sem teto, paralelismo vira
	// contenção e os perdedores estouram o timeout.
	dir := t.TempDir()
	scanner := fakeScanner(t, fmt.Sprintf(
		"f=$(mktemp %s/live.XXXXXX)\nsleep 0.2\nrm -f $f\ncat <<'EOF'\n%s\nEOF\n", dir, okReport))

	// Três slots de cache, porque é o isolamento que autoriza o
	// paralelismo: sem `--cache-dir` distinto o Trivy serializa no lock.
	o := newTestOrchestrator(t, scanner, 3, []string{t.TempDir(), t.TempDir(), t.TempDir()})

	var peak int
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			entries, _ := os.ReadDir(dir)
			mu.Lock()
			if len(entries) > peak {
				peak = len(entries)
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	targets := make([]protocol.Target, 12)
	for i := range targets {
		targets[i] = protocol.Target{Reference: fmt.Sprintf("img:%d", i)}
	}
	o.Run(context.Background(), targets)
	close(done)

	mu.Lock()
	defer mu.Unlock()
	if peak > 3 {
		t.Fatalf("%d scans simultâneos com --workers 3", peak)
	}
	if peak < 2 {
		t.Fatalf("nenhum paralelismo observado (pico %d), o pool não está soltando", peak)
	}
}

func TestWorkersNeverExceedTheCacheSlots(t *testing.T) {
	o := NewOrchestrator(nil, 10, []string{"/a", "/b"})
	if o.Workers() != 2 {
		t.Fatalf("mais workers que slots volta à contenção: %d", o.Workers())
	}
	if o.CacheSlots() != 2 {
		t.Fatalf("slots: %d", o.CacheSlots())
	}
}

func TestWithoutCacheDirsThereIsNoParallelism(t *testing.T) {
	// Sem isolamento, paralelismo é contenção -- então não há
	// paralelismo, e a métrica tem de dizer isso em vez de reportar oito
	// workers que na prática se enfileiram num lock.
	o := NewOrchestrator(nil, 8, nil)
	if o.CacheSlots() != 1 || o.Workers() != 1 {
		t.Fatalf("slots=%d workers=%d", o.CacheSlots(), o.Workers())
	}
}

func TestZeroWorkersIsNormalisedRatherThanDeadlocking(t *testing.T) {
	if got := NewOrchestrator(nil, 0, nil).Workers(); got != 1 {
		t.Fatalf("um pool de tamanho zero não é configuração, é deadlock: %d", got)
	}
}

func TestEachScanGetsACacheDirAndTheyAreRotated(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "dirs")
	scanner := fakeScanner(t, fmt.Sprintf(
		"while [ $# -gt 0 ]; do if [ \"$1\" = \"--cache-dir\" ]; then echo \"$2\" >> %s; fi; shift; done\ncat <<'EOF'\n%s\nEOF\n",
		seen, okReport))

	dirs := []string{t.TempDir(), t.TempDir()}
	o := newTestOrchestrator(t, scanner, 2, dirs)
	targets := make([]protocol.Target, 6)
	for i := range targets {
		targets[i] = protocol.Target{Reference: fmt.Sprintf("img:%d", i)}
	}
	o.Run(context.Background(), targets)

	data, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 6 {
		t.Fatalf("todo scan recebe --cache-dir, vieram %d", len(lines))
	}
	used := map[string]bool{}
	for _, l := range lines {
		used[l] = true
	}
	if len(used) != 2 {
		t.Fatalf("os dois slots têm de entrar em rodízio, usados %d", len(used))
	}
}

func TestOutputSurvivesHighConcurrency(t *testing.T) {
	// Regressão. A primeira versão lia de `StdoutPipe` numa goroutine
	// paralela a `cmd.Wait()`, e `Wait` fecha esses pipes assim que vê o
	// processo sair: sob concorrência o lado perdedor da corrida recebia
	// saída truncada, e três em cada trinta scans voltavam como "Trivy
	// produced no output" -- uma imagem perfeitamente medida reportada
	// como não medida.
	//
	// O relatório aqui é grande de propósito: a corrida só aparecia
	// quando a saída não cabia de uma vez no buffer do pipe.
	filler := strings.Repeat("x", 400)
	var vulns []string
	for i := 0; i < 400; i++ {
		vulns = append(vulns, fmt.Sprintf(
			`{"VulnerabilityID":"CVE-2024-%04d","Severity":"HIGH","Title":"%s"}`, i, filler))
	}
	report := `{"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[` +
		strings.Join(vulns, ",") + `]}]}`
	scanner := fakeScanner(t, "cat <<'REPORT'\n"+report+"\nREPORT\n")

	dirs := make([]string, 20)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	o := newTestOrchestrator(t, scanner, 20, dirs)

	targets := make([]protocol.Target, 60)
	for i := range targets {
		targets[i] = protocol.Target{Reference: fmt.Sprintf("img:%d", i)}
	}

	results, _ := o.Run(context.Background(), targets)

	for i, r := range results {
		if r.Status != protocol.StatusOK {
			t.Fatalf("alvo %d: %s/%s (%s)", i, r.Status, r.ErrorKind, r.ErrorMessage)
		}
		if len(r.Vulnerabilities) != 400 {
			t.Fatalf("alvo %d: saída truncada, %d achados de 400", i, len(r.Vulnerabilities))
		}
	}
}
