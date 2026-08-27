package scan

import (
	"context"
	"sync"
	"time"

	"github.com/Ivomsantiago/dockerls/engine/internal/protocol"
)

// Orchestrator mede uma lista de alvos com paralelismo limitado.
//
// Três invariantes, e são as mesmas do pipeline Python que ele substitui:
//
//   - alvos que compartilham DedupKey são medidos **uma vez**. `node:22`,
//     `node:22.14` e `node:lts` costumam ser o mesmo digest, e medir os
//     três é pagar três vezes pela mesma resposta;
//   - no máximo Workers scans simultâneos, cada um com seu diretório de
//     cache. O Trivy toma lock exclusivo no cache: sem isolamento,
//     paralelismo vira contenção e os perdedores estouram o timeout;
//   - a ordem da saída é a ordem da entrada. O ranking é do Python, e uma
//     saída em ordem de chegada tornaria o resultado dependente do
//     escalonador.
type Orchestrator struct {
	scanner   *Scanner
	workers   int
	cacheDirs []string
	// serialize diz se a falta de diretórios isolados obriga a rodar um
	// scan por vez. Vale para o Trivy e não vale para o Grype -- ver
	// `NewOrchestrator`.
	serialize bool
}

// NewOrchestrator normaliza os limites: um pool de tamanho zero não é uma
// configuração, é um deadlock.
func NewOrchestrator(scanner *Scanner, workers int, cacheDirs []string) *Orchestrator {
	if workers < 1 {
		workers = 1
	}

	// O teto do Trivy é o número de slots de cache, e uma lista vazia não é
	// exceção: sem `--cache-dir` todos os scans compartilham o cache padrão,
	// que é um lock BoltDB exclusivo -- rodar dois em paralelo ali não é
	// paralelismo, é a contenção que faz o perdedor estourar o timeout.
	//
	// O Grype não tem esse lock e não aceita `--cache-dir`: serializá-lo
	// por falta de diretórios seria aplicar a ele o remédio de uma doença
	// que ele não tem, e transformar `--workers 8` em 1 sem dizer nada.
	serialize := scanner == nil || scanner.name != "grype"
	if serialize {
		slots := len(cacheDirs)
		if slots == 0 {
			slots = 1
		}
		if workers > slots {
			workers = slots
		}
	}
	return &Orchestrator{
		scanner:   scanner,
		workers:   workers,
		cacheDirs: cacheDirs,
		serialize: serialize,
	}
}

// Workers é o paralelismo efetivo depois da normalização.
func (o *Orchestrator) Workers() int { return o.workers }

// CacheSlots é quantos diretórios isolados estão em rodízio.
func (o *Orchestrator) CacheSlots() int {
	if len(o.cacheDirs) == 0 {
		// Sem diretórios, há um "slot" nominal (o cache padrão do
		// scanner). Para o Trivy ele é o gargalo; para o Grype é só um
		// lugar, e o paralelismo é o de workers.
		if o.serialize {
			return 1
		}
		return o.workers
	}
	return len(o.cacheDirs)
}

// entry é o resultado compartilhado por todos os alvos de uma DedupKey.
type entry struct {
	once   sync.Once
	result protocol.Result
}

// Run mede todos os alvos e devolve os resultados na ordem recebida.
func (o *Orchestrator) Run(ctx context.Context, targets []protocol.Target) ([]protocol.Result, protocol.Metrics) {
	started := time.Now()

	// Um slot de cache por worker, em rodízio por canal. Canal e não
	// mutex porque o que se quer aqui é bloquear até haver slot livre,
	// que é exatamente o que uma leitura de canal vazio faz.
	slots := make(chan string, max(1, o.CacheSlots()))
	if len(o.cacheDirs) == 0 {
		// Um "slot" vazio por worker: o valor é a string vazia (nenhum
		// `--cache-dir`), e o que ele controla é só quantos scans podem
		// estar em voo.
		for range o.CacheSlots() {
			slots <- ""
		}
	} else {
		for _, dir := range o.cacheDirs {
			slots <- dir
		}
	}

	entries := make(map[string]*entry)
	keys := make([]string, len(targets))
	for i, t := range targets {
		key := t.DedupKey
		if key == "" {
			// Sem digest conhecido cada referência responde por si; usar
			// "" como chave comum faria imagens diferentes compartilharem
			// uma medição.
			key = "\x00ref:" + t.Reference
		}
		keys[i] = key
		if _, ok := entries[key]; !ok {
			entries[key] = &entry{}
		}
	}

	var (
		mu             sync.Mutex
		scansPerformed int
	)

	results := make([]protocol.Result, len(targets))
	scanned := make([]bool, len(targets))

	sem := make(chan struct{}, o.workers)
	var wg sync.WaitGroup

	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := entries[keys[i]]
			// `once` é o single-flight: os irmãos do mesmo digest ficam
			// parados aqui até o primeiro terminar, e então leem o
			// resultado dele em vez de disparar um scan próprio.
			e.once.Do(func() {
				sem <- struct{}{}
				defer func() { <-sem }()

				dir := <-slots
				defer func() { slots <- dir }()

				e.result = o.scanner.Scan(ctx, targets[i].Reference, dir)

				mu.Lock()
				scansPerformed++
				scanned[i] = true
				mu.Unlock()
			})

			r := e.result
			// A referência é a do alvo, não a de quem foi medido: os dois
			// compartilham o manifesto, mas o usuário pediu por *este*
			// nome e é ele que tem de aparecer no relatório.
			r.ImageReference = targets[i].Reference
			r.FromDedup = !scanned[i]
			if r.FromDedup {
				// A evidência pertence ao scan que realmente aconteceu.
				// Repetir o caminho aqui faria dois resultados apontarem
				// para o mesmo arquivo, e o Python o consome (lê, redige,
				// remove) uma vez só.
				r.RawPath = ""
			}
			results[i] = r
		}(i)
	}
	wg.Wait()

	unique := len(entries)
	return results, protocol.Metrics{
		TargetsReceived:     len(targets),
		UniqueKeys:          unique,
		DuplicatesCollapsed: len(targets) - unique,
		ScansPerformed:      scansPerformed,
		Workers:             o.workers,
		CacheSlots:          o.CacheSlots(),
		WallSeconds:         time.Since(started).Seconds(),
	}
}
