# dockerls-engine

Orquestração de scans em Go, dirigida pela CLI Python.

## O que ela é

Um binário que recebe um lote de referências de imagem por stdin (JSON),
dispara o Trivy sobre elas com paralelismo limitado e rodízio de diretório
de cache, e devolve um documento JSON pelo stdout. Uma execução por run,
não uma por scan.

    echo '{"version":1,"scanner":"trivy","scanner_path":"/usr/bin/trivy",
           "workers":8,"timeout_seconds":300,
           "cache_dirs":["/tmp/a","/tmp/b"],
           "targets":[{"reference":"node:22-alpine","dedup_key":"sha256:..."}]}' \
      | dockerls-engine

## O que ela **não** é

Nada de política mora aqui, e isso é deliberado:

* **`HostGuard` e `sanitize_image_name` continuam no Python**, aplicados
  antes de a requisição existir. Uma referência recusada nunca chega ao
  binário Go: ela vira `ERROR/BLOCKED_BY_POLICY` do lado de lá, pelo mesmo
  caminho de sempre. Reimplementar um controle de segurança em outra
  linguagem é criar uma segunda cópia dele para divergir da primeira;
* **a redação de segredos continua no Python.** A engine guarda o JSON cru
  em arquivo `0600` e devolve o caminho; é `redact()` -- o mesmo do sink de
  log -- que decide o que vai para a evidência definitiva;
* **a pontuação continua no Python.** Score, tier, EOL, KEV, EPSS,
  Exploit-DB e ranking não passam por aqui.

A engine também não resolve `PATH` (o caminho do scanner vem pronto na
requisição), não lê configuração, não abre socket, não escuta em porta
nenhuma, e nunca invoca um shell.

## Ela é opcional

`pip install dockerls` não instala este binário, e o pipeline Python
continua sendo o caminho completo. Qualquer falha deste lado -- binário
ausente, versão de protocolo diferente, timeout, saída ilegível -- faz a
CLI cair de volta no caminho Python sem que o comando falhe.

    make engine        # compila para engine/bin/dockerls-engine
    make engine-test   # go test -race ./...
    make engine-lint   # gofmt + go vet

A CLI procura o binário em `$DOCKERLS_ENGINE_PATH`, depois em
`engine/bin/dockerls-engine`, depois no `PATH`.

## Quanto isso rende (medido, e não estimado)

Com um scanner falso, 60 alvos, 8 workers, melhor de 3 nesta máquina:

| cenário                          | Python | Go engine |
|----------------------------------|--------|-----------|
| scanner instantâneo (só overhead)| 230ms  | **67ms**  |
| scanner de 50ms                  | 485ms  | 459ms     |
| scanner de 1200ms (32 alvos)     | 4,87s  | 4,85s     |

A leitura honesta dessas três linhas: a engine corta ~3,4x o **overhead de
orquestração** -- criar e colher N processos, revezar cache, coordenar o
dedup por digest --, que é de cerca de 2,7ms por imagem. Ela não corta nada
do scan em si, porque o scan é o Trivy, o Trivy já é Go, e ele custa
1,2-2,5s por imagem.

Numa `recommend` real de 100 tags, isso é ~0,3s economizados num run de
2 a 4 minutos. **O que domina o relógio não é a linguagem: é o número de
scans.** Quem quiser o run mais rápido mexe em `max_tags` e no que decide
quais candidatas merecem ser medidas, não no que orquestra a medição.

## Dependências

Nenhuma. O módulo é stdlib puro, e é por isso que não existe `go.sum` --
uma engine que participa de um caminho de segurança não herda árvore de
terceiros.

## Contrato

`internal/protocol` é o contrato, e `protocol.Version` é verificado dos
dois lados antes de qualquer campo ser usado. Incrementar sempre que o
sentido de um campo mudar.

A classificação do stderr do scanner existe nas duas linguagens
(`errors.go` aqui, `scan_errors.py` lá), porque classificar exige o stderr
e o stderr só existe onde o processo foi criado. As duas são travadas
contra a mesma tabela em `internal/scan/testdata/error_classification.json`,
lida tanto pelo teste Go quanto pelo Python: a causa de uma falha não pode
depender de qual binário a mediu.
