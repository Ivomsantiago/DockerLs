package scan

import (
	"encoding/json"
	"strings"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// As formas abaixo são só a parte do JSON do Grype que este projeto lê.
// Tipos nomeados em vez de anônimos porque `grypeCVSS` recebe um deles: uma
// struct anônima na assinatura de uma função é ilegível e impossível de
// reusar.

type grypeFix struct {
	Versions []string `json:"versions"`
}

type grypeMetrics struct {
	BaseScore *float64 `json:"baseScore"`
}

type grypeCVSSEntry struct {
	Source string `json:"source"`
	// Ponteiro de propósito: o Grype emite `"metrics": null` para advisory
	// sem vetor CVSS, e isso tem de ler como "sem pontuação".
	Metrics *grypeMetrics `json:"metrics"`
}

type grypeVulnerability struct {
	ID          string           `json:"id"`
	Severity    string           `json:"severity"`
	Description string           `json:"description"`
	Fix         grypeFix         `json:"fix"`
	CVSS        []grypeCVSSEntry `json:"cvss"`
}

type grypeLocation struct {
	Path string `json:"path"`
}

type grypeArtifact struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      string          `json:"type"`
	Locations []grypeLocation `json:"locations"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
	Distro  grypeDistro  `json:"distro"`
}

// ParseGrype converte o relatório do Grype no resultado do domínio.
//
// Porte de `dockerls/integrations/grype/scanner.py`, com as duas
// normalizações que fazem os dois scanners caberem no mesmo modelo:
// `Negligible` vira LOW (a escala do domínio não tem um quinto nível), e o
// bloco `distro` vira `os_family`/`os_version` -- o mesmo fato que o Trivy
// reporta sob `Metadata.OS`, escrito de outro jeito.
func ParseGrype(imageRef string, raw []byte, timestamp string) (protocol.Result, error) {
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return protocol.Result{}, err
	}

	vulns := make([]protocol.Vulnerability, 0, len(report.Matches))
	for _, match := range report.Matches {
		v := match.Vulnerability
		severity := strings.ToUpper(v.Severity)
		if severity == "NEGLIGIBLE" {
			severity = "LOW"
		}
		if _, ok := knownSeverities[severity]; !ok {
			severity = "UNKNOWN"
		}

		fixed := ""
		if len(v.Fix.Versions) > 0 {
			fixed = v.Fix.Versions[0]
		}
		target := ""
		if len(match.Artifact.Locations) > 0 {
			target = match.Artifact.Locations[0].Path
		}
		score, source := grypeCVSS(v.CVSS)

		vulns = append(vulns, protocol.Vulnerability{
			CVEID:            v.ID,
			Severity:         severity,
			CVSSScore:        score,
			CVSSSource:       source,
			PackageName:      match.Artifact.Name,
			InstalledVersion: match.Artifact.Version,
			FixedVersion:     fixed,
			Description:      truncate(v.Description, maxDescriptionBytes),
			PackageType:      match.Artifact.Type,
			Target:           target,
		})
	}

	return protocol.Result{
		ImageReference:  imageRef,
		Scanner:         "grype",
		Vulnerabilities: vulns,
		ScanTimestamp:   timestamp,
		Status:          protocol.StatusOK,
		ErrorKind:       protocol.KindNone,
		OSFamily:        report.Distro.Name,
		OSVersion:       report.Distro.Version,
	}, nil
}

// grypeCVSS escolhe o score de forma determinística: NVD primeiro, depois a
// primeira base disponível.
//
// Um `max()` entre bases diferentes -- que é o que uma implementação
// ingênua faz -- mistura pontuações de advisories distintos e produz um
// número que nenhuma base publicou.
func grypeCVSS(entries []grypeCVSSEntry) (float64, string) {
	if len(entries) == 0 {
		return 0, ""
	}
	base := func(e grypeCVSSEntry) float64 {
		if e.Metrics == nil || e.Metrics.BaseScore == nil {
			return 0
		}
		return *e.Metrics.BaseScore
	}
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Source), "nvd") {
			source := entry.Source
			if source == "" {
				source = "nvd"
			}
			return base(entry), source
		}
	}
	return base(entries[0]), entries[0].Source
}
