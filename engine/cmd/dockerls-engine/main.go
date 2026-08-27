// Command dockerls-engine mede um lote de imagens com o Trivy.
//
// Um documento JSON entra por stdin, um documento JSON sai por stdout. A
// CLI Python continua decidindo *o que* medir, aplicando a política de
// rede e pontuando o resultado; esta engine faz a parte que é puro
// paralelismo de processo -- e é a parte onde o Go rende: goroutines no
// lugar de um pool de processos, e uma travessia de fronteira por run em
// vez de uma por scan.
//
// A engine não decide política. Referências chegam já sanitizadas e já
// aprovadas pelo HostGuard; ela não resolve PATH, não lê configuração, não
// abre socket, não escuta em porta nenhuma, e nunca invoca um shell.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
	"github.com/Ivomsantiago/dockerls/engine/internal/scan"
)

// defaultMaxOutputBytes espelha `MAX_OUTPUT_BYTES` do runner Python: bem
// acima de qualquer JSON real do Trivy (uma imagem muito ruidosa produz
// alguns MiB) e bem abaixo do que colocaria a máquina sob pressão.
const defaultMaxOutputBytes int64 = 256 * 1024 * 1024

// maxRequestBytes limita o próprio documento de entrada. Um lote de mil
// referências não passa de algumas centenas de KiB; o teto existe para que
// um stdin que nunca fecha não vire consumo de memória sem limite.
const maxRequestBytes int64 = 32 * 1024 * 1024

func main() {
	printVersion := flag.Bool("version", false, "print the protocol version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("dockerls-engine protocol %d\n", protocol.Version)
		return
	}

	// Sem core dumps. Um scanner que falha um pull autenticado tem, na
	// memória, o token que usou; um SIGSEGV com core dump ligado o
	// escreveria num arquivo que ninguém redige. Os filhos herdam o
	// limite do processo que os cria, então basta baixá-lo aqui.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})

	// Ctrl-C tem de derrubar os scanners junto: o cancelamento do
	// contexto chega ao runner, que mata o grupo de processos de cada
	// scan em voo.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		// Falha fatal também sai como JSON: o chamador é um programa, e um
		// texto solto no stdout seria um documento ilegível em vez de um
		// erro legível.
		_ = json.NewEncoder(os.Stdout).Encode(protocol.Response{
			Version:    protocol.Version,
			FatalError: err.Error(),
		})
		fmt.Fprintln(os.Stderr, "dockerls-engine:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, in io.Reader, out io.Writer) error {
	req, err := readRequest(in)
	if err != nil {
		return err
	}

	maxOutput := req.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = defaultMaxOutputBytes
	}

	scanner := scan.NewScanner(req, maxOutput)
	orchestrator := scan.NewOrchestrator(scanner, req.Workers, req.CacheDirs)
	results, metrics := orchestrator.Run(ctx, req.Targets)

	// Sem indentação: o documento pode ter dezenas de milhares de achados,
	// e quem lê do outro lado é um parser.
	return json.NewEncoder(out).Encode(protocol.Response{
		Version: protocol.Version,
		Results: results,
		Metrics: metrics,
	})
}

func readRequest(in io.Reader) (protocol.Request, error) {
	var req protocol.Request

	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return req, fmt.Errorf("could not read the request: %w", err)
	}
	if int64(len(raw)) > maxRequestBytes {
		return req, errors.New("request exceeded the size limit")
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, fmt.Errorf("request is not valid JSON: %w", err)
	}

	// A verificação de versão vem antes de qualquer uso dos campos: um
	// binário de outra versão interpretando campos que mudaram de sentido
	// é como um contrato entre linguagens apodrece em silêncio.
	if req.Version != protocol.Version {
		return req, fmt.Errorf(
			"protocol version mismatch: the caller speaks %d, this engine speaks %d",
			req.Version, protocol.Version)
	}
	if req.Scanner != "trivy" && req.Scanner != "grype" {
		return req, fmt.Errorf(
			"unsupported scanner %q: this engine drives trivy and grype", req.Scanner)
	}
	if req.ScannerPath == "" {
		return req, errors.New("scanner_path is required: the engine does not resolve PATH itself")
	}
	if req.TimeoutSeconds <= 0 {
		return req, errors.New("timeout_seconds must be positive")
	}
	return req, nil
}
