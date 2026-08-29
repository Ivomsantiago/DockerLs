package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// referencePattern é a segunda tranca. A CLI já passa a referência por
// `sanitize_image_name` e pela política de rede antes de chegar aqui, e
// esta engine não reimplementa nenhuma das duas -- reimplementar um
// controle de segurança é criar uma cópia para divergir da original.
//
// O que este padrão faz é recusar o que nunca deveria ter atravessado a
// fronteira: se a requisição vier de um chamador que não é aquela CLI, uma
// referência com espaço, aspa, `$`, `;` ou byte de controle morre aqui em
// vez de virar argv de um binário.
var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$`)

// Scanner mede uma imagem com o Trivy ou com o Grype.
//
// Os dois entram pelo mesmo caminho porque tudo em volta do scan é igual:
// timeout, teto de saída, morte do grupo de processos, evidência crua,
// classificação do stderr. O que difere -- o argv e a forma do JSON -- fica
// isolado em `argv()` e no parser, que é exatamente o tamanho da diferença.
type Scanner struct {
	name           string
	path           string
	timeout        time.Duration
	skipDBUpdate   bool
	maxOutputBytes int64
	rawDir         string
	env            map[string]string
}

// NewScanner monta o scanner a partir da requisição já validada.
func NewScanner(req protocol.Request, maxOutputBytes int64) *Scanner {
	return &Scanner{
		name:           req.Scanner,
		path:           req.ScannerPath,
		timeout:        time.Duration(req.TimeoutSeconds * float64(time.Second)),
		skipDBUpdate:   req.SkipDBUpdate,
		maxOutputBytes: maxOutputBytes,
		rawDir:         req.RawDir,
		env:            req.Env,
	}
}

// argv monta a linha de comando do scanner escolhido.
func (s *Scanner) argv(reference, cacheDir string) []string {
	if s.name == "grype" {
		// O Grype não tem `--cache-dir`: a base dele mora num diretório
		// único, e o que desliga a atualização automática são variáveis de
		// ambiente, não flags.
		return []string{s.path, reference, "-o", "json", "--quiet"}
	}

	argv := []string{
		s.path,
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--quiet",
	}
	if cacheDir != "" {
		argv = append(argv, "--cache-dir", cacheDir)
	}
	if s.skipDBUpdate {
		// A DB de Java é baixada separadamente da principal. Sem este par,
		// o `--download-db-only` do aquecimento cobria só metade: cada
		// worker ainda saía para a rede buscar a java-db, que é a corrida
		// que o pool de cache existe para eliminar.
		argv = append(argv, "--skip-db-update", "--skip-java-db-update")
	}
	return append(argv, reference)
}

// parse escolhe o leitor conforme o scanner que produziu o documento.
func (s *Scanner) parse(reference string, raw []byte, timestamp string) (protocol.Result, error) {
	if s.name == "grype" {
		return ParseGrype(reference, raw, timestamp)
	}
	return ParseTrivy(reference, raw, timestamp)
}

// Scan mede uma imagem e devolve sempre um Result -- nunca um erro.
//
// Uma falha de scan é um resultado com Status ERROR, e não uma exceção
// que aborta o run: a imagem que não pôde ser medida é uma medição
// ausente, e o pipeline inteiro já trata ausência de medição como não
// verificado em vez de limpo.
func (s *Scanner) Scan(ctx context.Context, reference, cacheDir string) protocol.Result {
	timestamp := nowISO()

	if !referencePattern.MatchString(reference) {
		return failure(s.name, reference, timestamp, protocol.StatusError,
			protocol.KindInvalidOutput,
			"reference rejected by the engine: not a well-formed image reference")
	}

	run := runCapture(ctx, s.argv(reference, cacheDir), s.timeout, s.maxOutputBytes, s.env)

	switch {
	case run.timedOut:
		return failure(s.name, reference, timestamp, protocol.StatusTimeout,
			protocol.KindTimeout, fmt.Sprintf("Scan exceeded %gs timeout", s.timeout.Seconds()))

	case errors.Is(run.err, ErrOutputTooLarge):
		return failure(s.name, reference, timestamp, protocol.StatusError,
			protocol.KindInvalidOutput, ErrOutputTooLarge.Error())

	case run.err != nil:
		if errors.Is(run.err, os.ErrNotExist) || errors.Is(run.err, os.ErrPermission) {
			return failure(s.name, reference, timestamp, protocol.StatusError,
				protocol.KindScannerMissing, run.err.Error())
		}
		return failure(s.name, reference, timestamp, protocol.StatusError,
			ClassifyScannerError(run.err.Error()), run.err.Error())

	case run.exitCode != 0:
		// O Trivy escreve os próprios diagnósticos em stderr; eles vão
		// para o log e para o resumo do run, nunca crus no terminal.
		message := truncate(string(run.stderr), 500)
		return failure(s.name, reference, timestamp, protocol.StatusError,
			ClassifyScannerError(message), message)

	case len(run.stdout) == 0:
		return failure(s.name, reference, timestamp, protocol.StatusError,
			protocol.KindInvalidOutput, s.name+" produced no output")
	}

	result, err := s.parse(reference, run.stdout, timestamp)
	if err != nil {
		var syntax *json.SyntaxError
		detail := err.Error()
		if errors.As(err, &syntax) {
			detail = fmt.Sprintf("%s (offset %d)", err.Error(), syntax.Offset)
		}
		return failure(s.name, reference, timestamp, protocol.StatusError,
			protocol.KindInvalidOutput, detail)
	}

	result.RawPath = s.persistRaw(reference, run.stdout)
	return result
}

// persistRaw guarda o JSON cru para o Python redigir e arquivar.
//
// Melhor esforço, exatamente como o EvidenceStore: evidência é apoio de
// auditoria, e nunca motivo para reprovar um scan que aconteceu.
func (s *Scanner) persistRaw(reference string, raw []byte) string {
	if s.rawDir == "" {
		return ""
	}
	if err := os.MkdirAll(s.rawDir, 0o700); err != nil {
		return ""
	}
	f, err := os.CreateTemp(s.rawDir, "scan-*.json")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(raw); err != nil {
		_ = os.Remove(f.Name())
		return ""
	}
	// 0600: o JSON cru é o documento que pode conter o eco de um pull
	// autenticado, e é justamente por isso que o Python o redige antes de
	// arquivar. Até lá ele não é legível por mais ninguém na máquina.
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		return ""
	}
	return filepath.Clean(f.Name())
}

func failure(scanner, reference, timestamp, status, kind, message string) protocol.Result {
	return protocol.Result{
		ImageReference:  reference,
		Scanner:         scanner,
		Vulnerabilities: []protocol.Vulnerability{},
		ScanTimestamp:   timestamp,
		Status:          status,
		ErrorMessage:    message,
		ErrorKind:       kind,
	}
}

// nowISO devolve o instante no mesmo formato que `datetime.now(tz=UTC).isoformat()`
// produz do lado Python, para que os dois caminhos gravem o mesmo carimbo.
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
}
