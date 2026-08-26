// Package protocol define o contrato entre a CLI Python e a engine Go.
//
// Um documento JSON entra por stdin, um documento JSON sai por stdout, e o
// processo termina. Sem daemon, sem porta, sem socket: uma engine que
// escuta em algum lugar seria superfície de ataque nova para resolver um
// problema que uma execução por run já resolve. O ganho vem de haver *uma*
// travessia de processo por run em vez de uma por scan.
//
// O campo Version é verificado dos dois lados. Um binário de outra versão
// recusa com mensagem em vez de interpretar campos que mudaram de sentido
// -- que é como um contrato entre linguagens apodrece em silêncio.
package protocol

// Version é a versão do contrato. Incrementar sempre que o sentido de um
// campo mudar (renomear, remover, ou alterar a unidade de um número).
const Version = 1

// Target é uma imagem a medir.
type Target struct {
	// Reference é o que vai para o scanner, exatamente como recebido. A
	// engine não normaliza nem completa: a CLI já sanitizou e já submeteu
	// a referência à política de rede, e reimplementar qualquer das duas
	// aqui criaria uma segunda cópia de um controle de segurança para
	// divergir da primeira.
	Reference string `json:"reference"`

	// DedupKey junta as referências que compartilham o mesmo manifesto
	// (o digest, quando conhecido). Alvos com a mesma chave são medidos
	// uma vez e o resultado é compartilhado -- é o mesmo comportamento do
	// pipeline Python, e é de onde vem a maior economia real: `node:22`,
	// `node:22.14` e `node:lts` costumam ser o mesmo digest.
	//
	// Vazio significa "único": cada alvo é medido por si.
	DedupKey string `json:"dedup_key"`
}

// Request é o documento que a CLI escreve no stdin da engine.
type Request struct {
	Version int    `json:"version"`
	Scanner string `json:"scanner"`

	// ScannerPath é o caminho absoluto do executável, resolvido pela CLI.
	// A engine não procura em PATH: quem decide qual binário roda é o lado
	// que já tem a política sobre isso (`utils/executables.py`), e aceitar
	// um nome para resolver aqui abriria a porta que aquele módulo fecha.
	ScannerPath string `json:"scanner_path"`

	Targets []Target `json:"targets"`

	// Workers é o teto de scans simultâneos. <= 0 vira 1.
	Workers int `json:"workers"`

	// TimeoutSeconds limita cada scan individualmente, não o run inteiro.
	TimeoutSeconds float64 `json:"timeout_seconds"`

	// SkipDBUpdate repassa `--skip-db-update --skip-java-db-update`, para
	// quando a CLI já aqueceu a base de vulnerabilidades.
	SkipDBUpdate bool `json:"skip_db_update"`

	// CacheDirs são os diretórios de cache isolados, um por slot, criados
	// e ligados pela CLI (`TrivyCachePool`). A engine só os reveza: o
	// Trivy toma um lock exclusivo no cache, e N scans num diretório só
	// serializam no lock até estourar timeout.
	//
	// Vazio significa "sem --cache-dir", e a engine então trabalha com um
	// único slot: sem isolamento, paralelismo seria contenção.
	CacheDirs []string `json:"cache_dirs"`

	// MaxOutputBytes é o teto do que um scanner pode escrever num stream
	// antes do scan ser abandonado. 0 usa o padrão da engine.
	MaxOutputBytes int64 `json:"max_output_bytes"`

	// RawDir, quando preenchido, é onde a engine deposita o JSON cru de
	// cada scan, e o caminho volta em Result.RawPath. A redação de
	// segredos e a gravação definitiva continuam no Python: `redact()` é
	// um controle de segurança, e uma segunda implementação dele aqui
	// seria uma segunda a divergir.
	RawDir string `json:"raw_dir"`
}

// Vulnerability espelha `dockerls.domain.entities.vulnerability`.
//
// Só os campos que o scanner mede. Enriquecimento (KEV, EPSS, Exploit-DB)
// é do Python, e os tristates que o carregam ficam de fora de propósito:
// um campo com default `false` cruzando a fronteira viraria "consultado e
// negativo", que é exatamente a confusão que o Tristate existe para
// impedir.
type Vulnerability struct {
	CVEID            string  `json:"cve_id"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score"`
	CVSSSource       string  `json:"cvss_source"`
	PackageType      string  `json:"package_type"`
	Target           string  `json:"target"`
	PackageName      string  `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	Description      string  `json:"description"`
	PublishedDate    string  `json:"published_date"`
}

// Result espelha `dockerls.domain.entities.scan_result.ScanResult`.
type Result struct {
	ImageReference  string          `json:"image_reference"`
	Scanner         string          `json:"scanner"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScanTimestamp   string          `json:"scan_timestamp"`
	Status          string          `json:"status"`
	ErrorMessage    string          `json:"error_message"`
	ErrorKind       string          `json:"error_kind"`
	OSFamily        string          `json:"os_family"`
	OSVersion       string          `json:"os_version"`

	// RawPath é o arquivo temporário com o JSON cru, quando RawDir foi
	// pedido. O Python lê, redige e move para a evidência.
	RawPath string `json:"raw_path"`

	// FromDedup marca um resultado servido pelo digest de um irmão. A CLI
	// usa isto para não contar como scan o que não foi scan.
	FromDedup bool `json:"from_dedup"`
}

// Metrics é o que o run mediu de si mesmo.
type Metrics struct {
	TargetsReceived     int     `json:"targets_received"`
	UniqueKeys          int     `json:"unique_keys"`
	DuplicatesCollapsed int     `json:"duplicates_collapsed"`
	ScansPerformed      int     `json:"scans_performed"`
	Workers             int     `json:"workers"`
	CacheSlots          int     `json:"cache_slots"`
	WallSeconds         float64 `json:"wall_seconds"`
}

// Response é o documento que a engine escreve no stdout.
type Response struct {
	Version int      `json:"version"`
	Results []Result `json:"results"`
	Metrics Metrics  `json:"metrics"`

	// FatalError é preenchido quando o run inteiro não pôde acontecer
	// (requisição ilegível, versão incompatível). Uma falha de *um* scan
	// nunca vem aqui: ela é um Result com Status ERROR, porque um alvo que
	// falhou é uma medição ausente e não uma quebra do run.
	FatalError string `json:"fatal_error,omitempty"`
}

// Status e ErrorKind, com os mesmos valores dos StrEnum do domínio Python.
const (
	StatusOK    = "OK"
	StatusError = "ERROR"

	StatusTimeout = "TIMEOUT"

	KindNone           = "NONE"
	KindDBInitFailed   = "DB_INIT_FAILED"
	KindTimeout        = "TIMEOUT"
	KindAuthRequired   = "AUTH_REQUIRED"
	KindNotFound       = "NOT_FOUND"
	KindRateLimited    = "RATE_LIMITED"
	KindInvalidOutput  = "INVALID_OUTPUT"
	KindScannerMissing = "SCANNER_MISSING"
	KindUnknown        = "UNKNOWN"
)
