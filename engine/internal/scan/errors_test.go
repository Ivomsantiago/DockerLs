package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A tabela vive em `testdata/error_classification.json` e é lida também
// pelo teste Python. As duas implementações têm de concordar caso a caso:
// uma classificação que diverge entre os caminhos faria a mesma falha
// aparecer com causas diferentes conforme a engine estivesse instalada ou
// não -- e a causa de uma falha não pode depender de qual binário a mediu.
func TestClassifyScannerError(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "error_classification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases []struct {
			Message string `json:"message"`
			Kind    string `json:"kind"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("tabela vazia: o guard não estaria guardando nada")
	}
	for _, c := range table.Cases {
		if got := ClassifyScannerError(c.Message); got != c.Kind {
			t.Errorf("%q -> %s, esperado %s", c.Message, got, c.Kind)
		}
	}
}

func TestTheFirstMatchingRuleWins(t *testing.T) {
	// "cache may be in use by another process: timeout" casa tanto a regra
	// de DB quanto a de timeout. A de DB vem antes porque é a causa: o
	// timeout é o sintoma do lock disputado.
	if got := ClassifyScannerError("cache may be in use by another process: timeout"); got != "DB_INIT_FAILED" {
		t.Fatalf("esperada a causa e não o sintoma, veio %s", got)
	}
}
