// Command bench-fanout mede, e não estima, se um pool de goroutines resolve
// digest + config OCI mais rápido do que o `asyncio.gather` + `Semaphore`
// que o Python já usa em `RegistryInspector`/`recommend_images.py`.
//
// A pergunta que motiva isto: a engine Go corta ~2,7ms/imagem de overhead
// de orquestração de *scan* (ver engine/README.md), o que é irrelevante
// perto dos 1,2-2,5s que o Trivy gasta por imagem. Resolução de digest e
// leitura de config são diferentes -- são elas mesmas round-trips de rede,
// não um subprocesso que já é Go por baixo -- então valem uma medição
// própria em vez de herdar a conclusão do scan por analogia.
//
// Os dois lados batem no mesmo servidor, na mesma máquina, com a mesma
// latência artificial por requisição: só assim a comparação é sobre a
// linguagem que orquestra o fan-out, e não sobre qual lado tem uma rede
// mais rápida.
//
//	go run ./cmd/bench-fanout -serve -latency-ms 40 &
//	go run ./cmd/bench-fanout -targets 300 -workers 16
//	python3 benchmarks/bench_fanout_python.py --targets 300 --workers 16
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	serve := flag.Bool("serve", false, "run the mock registry server instead of the client")
	addr := flag.String("addr", "127.0.0.1:8991", "server address (client dials it, server binds it)")
	latencyMs := flag.Int("latency-ms", 40, "artificial per-request latency, in milliseconds")
	targets := flag.Int("targets", 200, "number of distinct image targets to fan out over")
	workers := flag.Int("workers", 16, "bounded worker pool / semaphore size")
	flag.Parse()

	if *serve {
		runServer(*addr, time.Duration(*latencyMs)*time.Millisecond)
		return
	}
	runClient(*addr, *targets, *workers)
}

// runServer simula o par de round-trips que `RegistryInspector` faz por
// imagem: um HEAD (ou GET raso) no manifesto para o digest, e um GET no
// blob de config. A latência é injetada, não real -- o objetivo é medir o
// overhead de orquestração de cada lado, não a rede desta máquina.
func runServer(addr string, latency time.Duration) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(latency)
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write([]byte(`{"config":{"digest":"sha256:` + strings.Repeat("b", 64) + `"}}`))
		case strings.Contains(r.URL.Path, "/blobs/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
			_, _ = w.Write([]byte(`{"config":{"User":"10001","ExposedPorts":{"8080/tcp":{}},"Entrypoint":["/app"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	fmt.Fprintf(os.Stderr, "bench-fanout: serving on %s (latency=%s)\n", addr, latency)
	if err := http.ListenAndServe(addr, mux); err != nil { //nolint:gosec // ferramenta de benchmark local, não produção
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

// runClient reproduz exatamente o padrão de `_pin_digests`: um semáforo
// limitando a `workers` requisições concorrentes, um HEAD de manifesto
// seguido de um GET de blob por alvo -- só que com goroutines no lugar de
// `asyncio.gather`.
func runClient(addr string, targets, workers int) {
	client := &http.Client{Timeout: 30 * time.Second}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var requests int64
	var mu sync.Mutex

	start := time.Now()
	for i := 0; i < targets; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			repo := "bench/repo-" + strconv.Itoa(i)
			n := fetch(client, "http://"+addr+"/v2/"+repo+"/manifests/tag")
			n += fetch(client, "http://"+addr+"/v2/"+repo+"/blobs/sha256:"+strconv.Itoa(i))
			mu.Lock()
			requests += n
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("go-goroutines targets=%d workers=%d requests=%d elapsed=%s\n",
		targets, workers, requests, elapsed)
}

func fetch(client *http.Client, url string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return 1
}
