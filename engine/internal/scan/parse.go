package scan

import (
	"encoding/json"
	"strings"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// trivyReport é só a parte do documento do Trivy que este projeto lê.
// Decodificar em struct em vez de map[string]any não é estética: um
// relatório de imagem ruidosa passa de 10MB, e o map aloca uma interface e
// um string por chave de cada achado.
type trivyReport struct {
	Results []struct {
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string               `json:"VulnerabilityID"`
			Severity         string               `json:"Severity"`
			SeveritySource   string               `json:"SeveritySource"`
			PkgName          string               `json:"PkgName"`
			InstalledVersion string               `json:"InstalledVersion"`
			FixedVersion     string               `json:"FixedVersion"`
			Title            string               `json:"Title"`
			PublishedDate    string               `json:"PublishedDate"`
			CVSS             map[string]trivyCVSS `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
}

type trivyCVSS struct {
	V4Score *float64 `json:"V4Score"`
	V3Score *float64 `json:"V3Score"`
}

var knownSeverities = map[string]string{
	"CRITICAL": "CRITICAL",
	"HIGH":     "HIGH",
	"MEDIUM":   "MEDIUM",
	"LOW":      "LOW",
	"UNKNOWN":  "UNKNOWN",
}

// cvssSourcePriority é o desempate quando a base que definiu a severidade
// não publica CVSS -- Debian, Alpine e Ubuntu classificam sem pontuar. NVD
// primeiro por ser a canônica; o resto é determinístico só para que o mesmo
// achado produza sempre o mesmo número.
var cvssSourcePriority = []string{"nvd", "redhat", "ghsa", "amazon", "photon", "oracle-oval"}

// maxDescriptionBytes espelha o `[:200]` do parser Python.
const maxDescriptionBytes = 200

// ParseTrivy converte o relatório do Trivy no resultado do domínio.
func ParseTrivy(imageRef string, raw []byte, timestamp string) (protocol.Result, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return protocol.Result{}, err
	}

	// Uma alocação só para todos os achados: contar antes é uma passada
	// barata sobre slices já decodificados, e evita o crescimento
	// geométrico do append num relatório com milhares de linhas.
	total := 0
	for _, r := range report.Results {
		total += len(r.Vulnerabilities)
	}
	vulns := make([]protocol.Vulnerability, 0, total)

	for _, result := range report.Results {
		// `Class` distingue pacote de SO ("alpine", "debian") de pacote de
		// linguagem ("node-pkg", "python-pkg"); `Target` diz onde ele mora.
		pkgType := result.Class
		if pkgType == "" {
			pkgType = result.Type
		}
		for _, v := range result.Vulnerabilities {
			severity, ok := knownSeverities[strings.ToUpper(v.Severity)]
			if !ok {
				severity = "UNKNOWN"
			}
			score, source := extractCVSS(v.CVSS, v.SeveritySource)
			vulns = append(vulns, protocol.Vulnerability{
				CVEID:            v.VulnerabilityID,
				Severity:         severity,
				CVSSScore:        score,
				CVSSSource:       source,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Description:      truncate(v.Title, maxDescriptionBytes),
				PublishedDate:    v.PublishedDate,
				PackageType:      pkgType,
				Target:           result.Target,
			})
		}
	}

	return protocol.Result{
		ImageReference:  imageRef,
		Scanner:         "trivy",
		Vulnerabilities: vulns,
		ScanTimestamp:   timestamp,
		Status:          protocol.StatusOK,
		ErrorKind:       protocol.KindNone,
		OSFamily:        report.Metadata.OS.Family,
		OSVersion:       report.Metadata.OS.Name,
	}, nil
}

// extractCVSS devolve (score, fonte), preferindo a base que definiu a
// severidade.
//
// O Trivy define `Severity` pela fonte em `SeveritySource` -- em geral o
// vendor da distro -- enquanto o bloco `CVSS` traz o score de várias bases
// ao mesmo tempo. Pegar a severidade de uma e o número de outra produzia
// linhas como `CRITICAL ... 7.5`, que pelo CVSS v3 é contradição (CRITICAL
// começa em 9.0). Não era erro de conta: eram duas bases diferentes
// exibidas como se fossem uma.
func extractCVSS(cvss map[string]trivyCVSS, severitySource string) (float64, string) {
	if len(cvss) == 0 {
		return 0, ""
	}

	seen := make(map[string]bool, len(cvss)+len(cvssSourcePriority)+1)
	candidates := make([]string, 0, len(cvss)+len(cvssSourcePriority))

	if s := strings.ToLower(trimSpace(severitySource)); s != "" {
		candidates = append(candidates, s)
		seen[s] = true
	}
	for _, s := range cvssSourcePriority {
		if !seen[s] {
			candidates = append(candidates, s)
			seen[s] = true
		}
	}
	// As chaves restantes entram em ordem determinística: iterar um map do
	// Go é deliberadamente aleatório, e sem ordenar aqui o mesmo relatório
	// produziria fontes diferentes entre dois runs.
	rest := make([]string, 0, len(cvss))
	for k := range cvss {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	candidates = append(candidates, rest...)

	for _, source := range candidates {
		entry, ok := cvss[source]
		if !ok {
			continue
		}
		if entry.V4Score != nil {
			return *entry.V4Score, source
		}
		if entry.V3Score != nil {
			return *entry.V3Score, source
		}
	}
	return 0, ""
}
