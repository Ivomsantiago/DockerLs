package scan

import (
	"sort"
	"strings"
)

func trimSpace(s string) string { return strings.TrimSpace(s) }

// truncate corta em n *bytes*, mas nunca no meio de um caractere UTF-8:
// meia sequência vira U+FFFD no JSON e a mensagem passa a mentir sobre o
// que o scanner escreveu.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8Start diz se o byte inicia um caractere (ASCII ou byte líder).
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func sortStrings(s []string) { sort.Strings(s) }
