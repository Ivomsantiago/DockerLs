package scan

import (
	"regexp"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// Porte de `dockerls/integrations/scan_errors.py`. A ordem importa: a
// primeira regra que casa vence, então as causas específicas vêm antes das
// genéricas ("db error" aparece dentro de mensagens que também dizem
// "failed to download").
//
// Este é o único trecho de lógica do Python reescrito aqui, e é de
// propósito: classificar exige o stderr, o stderr só existe dentro da
// engine, e mandá-lo de volta para o Python classificar custaria uma
// travessia por falha. `TestClassifyMatchesPython` (ver o teste Python
// correspondente) trava as duas implementações contra a mesma tabela de
// casos.
var classificationRules = []struct {
	kind    string
	pattern *regexp.Regexp
}{
	{protocol.KindRateLimited, regexp.MustCompile(`(?i)rate limit|too many requests|429|toomanyrequests`)},
	{protocol.KindAuthRequired, regexp.MustCompile(`(?i)unauthorized|authentication required|forbidden|401|403|denied: requested access`)},
	{protocol.KindNotFound, regexp.MustCompile(`(?i)manifest unknown|not found|no such image|repository does not exist|name unknown|could not find the image|unable to find the specified image`)},
	{protocol.KindDBInitFailed, regexp.MustCompile(`(?i)db error|database error|init error|failed to download (?:vulnerability )?db|failed to initialize|unable to open database|bad database|db\.metadata|cache may be in use|database is locked|failed to open db`)},
	{protocol.KindTimeout, regexp.MustCompile(`(?i)timeout|timed out|deadline exceeded|context deadline`)},
}

// ClassifyScannerError mapeia o stderr do scanner numa causa estável.
func ClassifyScannerError(message string) string {
	text := trimSpace(message)
	if text == "" {
		return protocol.KindUnknown
	}
	for _, rule := range classificationRules {
		if rule.pattern.MatchString(text) {
			return rule.kind
		}
	}
	return protocol.KindUnknown
}
