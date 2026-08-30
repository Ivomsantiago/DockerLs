# Referência completa do DockerLs

> Este é o manual de referência: todos os comandos, o algoritmo de pontuação,
> arquitetura, configuração e detalhes finos. Para uma introdução rápida,
> veja o [README](../README.md).

**Consultor de segurança de imagens Docker dirigido por evidência.** O DockerLs
descobre, normaliza, verifica, escaneia, valida cruzado e ranqueia imagens de
múltiplos ecossistemas confiáveis para identificar a escolha mais segura para
produção -- e explica por quê.

Segurança aqui não é ausência de achados. É uma conclusão sustentada por
evidência verificável: quando a evidência não basta, a ferramenta prefere dizer
**"não foi possível determinar"** a dizer "está seguro".

A pergunta que ele responde não é *"quantas CVEs esta imagem tem?"*, e sim:

> Dado um runtime desejado, qual é a melhor alternativa para produção
> considerando vulnerabilidades, exploração real, EOL, hardening, superfície de
> ataque, manutenção, proveniência, compatibilidade e **confiança dos dados**?

```
DESCOBRIR -> NORMALIZAR -> VERIFICAR -> ESCANEAR -> VALIDAR CRUZADO
   -> HARDENING -> SUPERFÍCIE DE ATAQUE -> CICLO DE VIDA -> PROVENIÊNCIA
   -> RISCO -> RANQUEAR -> RECOMENDAR -> EXPLICAR
```

**Nenhum fornecedor é autoridade.** Docker Hub, Chainguard, Distroless, Docker
Hardened Images, Trivy e Grype são *fontes de dados*. Uma imagem publicada como
"hardened" não é uma imagem segura até que o DockerLs a resolva por digest, a
escaneie e concorde. O veredito é sempre do DockerLs.

---

## Por que o DockerLs?

Um scanner responde *"quantas CVEs esta imagem tem?"*. Essa quase nunca é a
pergunta que você precisa responder. As perguntas reais são *"qual imagem eu
deveria usar?"* e *"o que eu faço com o que foi encontrado?"* — e é sobre elas
que o DockerLs foi construído.

| | Scanner comum | DockerLs |
|---|---|---|
| Escopo | uma imagem que você já escolheu | **todas as tags candidatas**, ranqueadas |
| Fontes | um registry | Docker Hub + Chainguard + Distroless + **Docker Hardened Images**, no mesmo pipeline |
| Identidade | a tag que você digitou | **digest do manifesto**, resolvido antes do scan -- uma tag se move, um digest não |
| Configuração | fora do escopo | **Hardening Score** medido no config OCI da imagem publicada (não root, portas, entrypoint) |
| Superfície | confundida com tamanho | **Attack Surface Score** próprio: shell, gerenciador de pacotes, ferramentas de debug, privilégio |
| Metadados do fornecedor | aceitos como fato | tratados como *declaração*; contradições com o que foi medido viram achado |
| Qualidade da evidência | invisível | **Confidence** (`HIGH`/`MEDIUM`/`LOW`/`UNVERIFIED`) em cada linha |
| Falha de scan | vira "0 vulnerabilidades" | vira `UNVERIFIED`, com causa classificada e sem pontuação |
| Dado ausente | vira `false` | vira `unknown`, e `unknown` nunca credita nem penaliza |
| Veredito de produção | espalhado pelo código | uma política central, com códigos de bloqueio estáveis |
| Reprodutibilidade | nenhuma | versão do DockerLs e do scanner, digest e fingerprint no manifesto |
| Confiança | a palavra de um scanner | **validação cruzada** com um segundo scanner; divergência material é sinalizada, não escondida |
| EOL | fora do escopo | penaliza no score, e uma base EOL nunca é `production ready` |
| Exploração real | só severidade | CISA KEV + EPSS pesam no score |
| Falha técnica | vira "0 vulnerabilidades" | vira **`Unverified`**, com causa classificada e exit code de erro |
| Correção | lista de CVEs | plano de remediação com versões corrigidas **vindas do scanner** |
| Prova | um número | caminho do JSON bruto de cada scan + manifesto por execução |

O princípio que organiza tudo isso: **uma imagem que não pôde ser medida nunca é
apresentada como uma imagem segura.** Um scan que falhou, expirou ou saiu pela
metade manda a tag para a seção `Unverified` — ela não recebe pontuação, não
recebe nível e não entra na recomendação.

---

## Índice

- [Por que o DockerLs?](#por-que-o-dockerls)
- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Comandos](#comandos)
- [Exit codes](#exit-codes)
- [**Do zero à imagem em produção**](#do-zero-à-imagem-em-produção) — percurso completo com saídas reais
- [Por que falha de scan não é segurança](#por-que-falha-de-scan-não-é-segurança)
- [Segurança de rede](#segurança-de-rede)
- [Fontes de imagens (multi-source)](#fontes-de-imagens-multi-source)
- [Como a recomendação funciona](#como-a-recomendação-funciona)
- [Algoritmo de pontuação](#algoritmo-de-pontuação)
- [Hardening Score](#hardening-score)
- [Attack Surface Score](#attack-surface-score)
- [Confiança (Confidence)](#confiança-confidence)
- [Recomendações por digest](#recomendações-por-digest)
- [Níveis de segurança](#níveis-de-segurança)
- [Modo alternativo](#modo-alternativo)
- [Performance](#performance)
- [Evidências e reprodutibilidade](#evidências-e-reprodutibilidade)
- [Arquitetura](#arquitetura)
- [Configuração](#configuração)
- [Uso com Docker](#uso-com-docker)
- [Desenvolvimento](#desenvolvimento)
- [CI/CD](#cicd)
- [Modelo de segurança](#modelo-de-segurança)
- [Solução de problemas](#solução-de-problemas)
- [Perguntas frequentes](#perguntas-frequentes)
- [Licença](#licença)

---

## Comandos em resumo

| Comando | O que faz | Exit codes |
|---|---|---|
| [`search`](#search) | Lista as tags disponíveis de uma imagem | `0` / `1` |
| [`recommend`](#recommend) | Ranqueia as tags mais seguras e recomenda uma | `0` `1` `2` `3` |
| [`advisor`](#advisor) | Plano de correção completo para a melhor imagem (e migração, se você passar uma tag) | `0` / `1` |
| [`alternatives`](#alternatives) | Alternativas mais seguras para a imagem que você já roda, com trade-offs | `0` `1` `2` |
| [`analyze`](#analyze) | Análise profunda de uma tag: CVEs, CVSS, origem, correção | `0` `1` `2` |
| [`compare`](#compare) | Compara duas ou mais imagens lado a lado | `0` `1` `2` `3` |
| [`sbom`](#sbom) | Gera SBOM (CycloneDX ou SPDX) via Trivy | `0` / `1` |
| [`export`](#export) | Exporta o relatório em JSON/CSV/HTML/Markdown/SARIF | `0` / `1` |
| [`analyze-dockerfile`](#analyze-dockerfile) | Valida um Dockerfile contra regras de hardening | `0` `1` `2` |
| [`controls`](#controls) | Mostra os controles publicados (CIS, NIST, OWASP) por trás de cada regra | `0` / `1` |
| [`base`](#base) | Confere as bases do Dockerfile contra o registry e atualiza os digests | `0` `1` `2` |
| [`base-image`](#base-image) | Gera o Dockerfile de uma imagem base a partir de um menu de pacotes | `0` / `1` |
| [`build`](#build) | Valida, constrói, escaneia, atribui, publica e assina | `0` `1` `2` |
| [`fleet`](#fleet) | Varre uma árvore de repositórios e resume o estado dos Dockerfiles | `0` `1` `2` |
| [`policy`](#policy) | Mostra e valida a política declarada em `.dockerls-policy.yaml` | `0` / `1` |
| [`provenance`](#provenance) | Confere um documento de procedência e prepara a atestação | `0` `1` `2` |
| [`verify`](#verify) | Confere a assinatura de uma imagem com cosign | `0` `1` `2` |
| [`registry-audit`](#registry-audit) | O que o registry conta sobre uma imagem publicada | `0` `1` `2` |
| [`doctor`](#doctor) | Checa as dependências locais (scanners) | `0` / `1` |
| [`health`](#health) | Checa a conectividade com os serviços externos | `0` / `1` |
| [`cache`](#cache) | Inspeciona e limpa o cache de análises | `0` / `1` |
| [`login`](#login) / [`logout`](#logout) | Credenciais do Docker Hub no keyring do sistema | `0` / `1` |
| [`version`](#version) | Versão instalada | `0` |

---

## Instalação

### Pelo PyPI

```bash
pip install dockerls
```

### A partir do código-fonte

```bash
git clone https://github.com/Ivomsantiago/DockerLs.git
cd DockerLs
pip install .
```

### Com suporte a keyring (para armazenar credenciais)

```bash
pip install "dockerls[keyring]"
```

### Requisitos

| Requisito | Necessário para | Sem ele |
|---|---|---|
| **Python 3.11+** | tudo | nada roda |
| **Trivy** ([instalação](https://aquasecurity.github.io/trivy)) | qualquer comando que mede vulnerabilidade: `recommend`, `analyze`, `compare`, `advisor`, `alternatives`, `sbom`, e o scan do `build` | os resultados saem como **não verificados**, nunca como "limpo" |
| **Grype** ([instalação](https://github.com/anchore/grype)) | alternativa ao Trivy e segundo scanner na validação cruzada | funciona sem, mas a confiança não chega a `HIGH` por falta de corroboração |
| **daemon do Docker** | **apenas o `build`** — é ele que roda `docker build`, `docker tag` e `docker push` | `build` falha; todo o resto continua funcionando |
| **git** (opcional) | registro de supply chain: commit e estado da árvore | a procedência sai sem revisão, marcada como incompleta |
| **Go 1.24+** (opcional) | compilar a engine de orquestração (`make engine`) para acelerar runs grandes | dispensável — sem o binário, a CLI usa o caminho Python normalmente |

Confira tudo de uma vez:

```bash
dockerls doctor
```

**Sobre o `build` especificamente:** ele precisa de daemon Docker acessível e de
um scanner instalado **na máquina onde roda** — a imagem publicada por este
projeto não embute scanner (ver [Uso com Docker](#uso-com-docker)). Publicar
(`--push` / `--registry`) exige, além disso, estar autenticado no registry de
destino; a recusa nomeia o comando de login de cada provedor.

---

## Início rápido

```bash
# Encontrar a imagem Node.js mais segura
dockerls recommend node

# Analisar a fundo uma tag específica
dockerls analyze node:22-alpine

# Obter um plano completo de correção
dockerls advisor node

# Comparar duas imagens lado a lado
dockerls compare node:22-alpine node:22-bookworm-slim

# Exportar relatório em JSON
dockerls export node --format json --output report.json
```

---

## Comandos

### search

Busca tags disponíveis no Docker Hub. Não escaneia nada — é a forma barata de ver
o que existe antes de decidir o que medir.

```bash
dockerls search node
dockerls search python --limit 50
```

Saída real (`dockerls search node --limit 5`):

```
                               Tags for node
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Tag                 ┃ Size (MB) ┃ Architecture ┃ Last Updated ┃ Official ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ trixie-slim         │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
│ trixie              │     422.4 │ amd64        │ 2026-08-06   │   Yes    │
│ slim                │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
│ latest              │     422.4 │ amd64        │ 2026-08-06   │   Yes    │
│ current-trixie-slim │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
└─────────────────────┴───────────┴──────────────┴──────────────┴──────────┘

Total: 5 tags
```

**Como ler.** As tags saem ordenadas por `last_updated` (mais recentes primeiro),
que é a ordem em que o Docker Hub as devolve. `Size` e `Architecture` descrevem o
manifesto **amd64** quando ele existe, e o primeiro manifesto disponível caso
contrário. Repare que `trixie-slim`, `slim` e `current-trixie-slim` reportam o
mesmo tamanho: são apelidos do mesmo digest, e é exatamente essa redundância que
o `recommend` colapsa antes de escanear.

**Exit codes:** `0` com tags encontradas, `1` quando não há nenhuma tag ou a
referência é malformada.

### recommend

Recomenda as tags mais seguras com base no scan de vulnerabilidades.

```bash
dockerls recommend node
dockerls recommend node --max-medium 10          # afrouxa o padrão de 5
dockerls recommend nginx --workers 20
dockerls recommend node --format json
dockerls recommend node --fail-on high --no-color
```

`recommend` e `advisor` aceitam `--format json` (saída legível por máquina) e
`--no-color` (texto puro, sem códigos ANSI).

<a id="exit-codes-de-recommend"></a>
`recommend` termina com um código de saída que reflete o resultado, para servir
de portão em CI:

| Código de saída | Significado                                             |
|-----------------|---------------------------------------------------------|
| 0               | Encontrou imagem que atende ao baseline                  |
| 1               | Erro operacional: nenhuma tag encontrada, **nenhuma tag pôde ser escaneada**, configuração inválida, ou `--fail-on` violado |
| 2               | Nenhuma imagem no baseline, mas há alternativas ranqueadas |
| 3               | Tags foram escaneadas e nenhuma delas serve               |

A diferença entre `1` e `3` é deliberada e importa num portão de CI. `3` é um
**veredito**: as candidatas foram medidas e nenhuma passou. `1` é "não sei" —
inclui o caso em que tags foram descobertas mas nenhuma chegou a ser escaneada
(scanner ausente, banco de vulnerabilidades indisponível, rate limit). Um pipeline
que trata os dois como a mesma coisa não consegue distinguir uma infraestrutura
quebrada de um catálogo de imagens ruim.

`advisor` usa apenas `0` (produziu um plano) e `1` (não havia nada sobre o que
aconselhar): ele reporta uma única imagem, então "baseline" e "alternativa" não
são desfechos distinguíveis do ponto de vista dele.

**Quando nada atinge o baseline, o ranking sai mesmo assim**, marcado como
abaixo do alvo. O caminho alternativo filtrava por `critical_count == 0` -- de
novo parte do mesmo critério que o baseline acabara de rejeitar --, então com
toda tag candidata carregando um CRITICAL (o caso comum no Docker Hub) a
execução respondia `No suitable images found` e nada mais, descartando a
informação mais útil que produziu: qual das imagens ruins é a menos ruim. Para
afrouxar o alvo de verdade, use `--max-critical`, `--max-high` e `--max-medium`.

`--fail-on {critical,high,medium}` força o código de saída 1 se o melhor
resultado ainda carregar vulnerabilidades naquela severidade ou acima, mesmo em
modo alternativo -- útil para reprovar um job de CI diante de uma recomendação
alternativa que você não considera aceitável.

#### O que uma recomendação garante

Toda linha da tabela **Recommended Images** passou por três portões. Se uma tag
não passa nos três, ela é reportada à parte e nunca recebe pontuação:

1. **Scan comprovado.** O processo do scanner terminou limpo e o JSON dele foi
   interpretado. Um scan com falha, timeout ou parcial manda a tag para a seção
   `Unverified (technical error)` -- ela não recebe pontuação nem nível.
2. **Pontuação sem contestação.** Os melhores candidatos são reescaneados com o
   segundo scanner (Grype quando o Trivy é o principal, e vice-versa). Se os dois
   divergirem de forma relevante na contagem de CRITICAL/HIGH, a pontuação
   aparece como `!disputed` em vez de um número, com a discrepância logo abaixo.
3. **Tag confirmada no registry de origem.** Tags do Docker Hub são checadas
   contra a API do Hub (`GET /v2/repositories/<ns>/<repo>/tags/<tag>`); tags de
   fontes hardened são checadas contra a listagem do próprio registry. De um
   jeito ou de outro, a coluna `Tag` reflete uma resposta real do registry, nunca
   uma string montada.

A execução abre com duas linhas de resumo. A primeira diz **o que foi
encontrado**; a segunda, **quanto trabalho custou**:

```
OK 12/24 analyzed | X 12 skipped (technical error) | sources: Docker Hub, Chainguard, Distroless
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
log: ~/.local/state/dockerls/logs/dockerls_2026-08-06_13-36-15.log
```

A segunda linha existe porque `12/24 analyzed` não diz se aquilo custou 24 scans
ou 9. Aqui custou 9: doze tags foram colapsadas por apontarem para digests já
vistos, três vieram do cache, e apenas as nove restantes chegaram ao scanner. Os
mesmos números saem em `--format json`, sob a chave `metrics`.

Quando nada atinge o baseline, os critérios exatos são impressos em vez de apenas
o veredito:

```
No image meets the baseline.
Baseline: 0 Critical, 0 High, 5 Medium (and not EOL).
Showing the best candidates found -- all of them below target.
```

E quando **nada pôde ser medido**, a saída diz isso com todas as letras em vez de
fingir um veredito. Saída real, numa máquina sem scanner instalado
(`dockerls recommend node --limit 3 --no-hardened`):

```
OK 0/3 analyzed | X 3 skipped (technical error) | sources: Docker Hub
scans: 2 | deduped: 1 | workers: 10
log: ~/.local/state/dockerls/logs/dockerls_2026-08-16_19-09-16.log

No image could be scanned.
All 3 candidate(s) failed with: SCANNER_MISSING

Suggested action
  Install Trivy or Grype, then re-run. `dockerls doctor` checks for both.

This is a technical failure, not a security verdict: nothing was measured, so
nothing can be said about these images.

! Unverified (technical error)
  These tags were never scored -- no successful scan, no recommendation.
  Causes: SCANNER_MISSING x3
  node:trixie-slim  SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  node:trixie       SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  node:slim         SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  Run with --verbose for the full scanner output.
```

Isso termina em **`1`** (erro operacional), nunca em `3`. O código `3` significa
"procurei e não achei nada utilizável" — uma afirmação sobre as *imagens*, que um
portão de CI tem o direito de tratar como veredito. Aqui nada foi medido, e
reportar isso como veredito seria a única troca que uma ferramenta de segurança
não pode fazer.

Repare também em `deduped: 1`: das três tags, duas apontavam para o mesmo
manifesto, então foram feitos dois scans e não três.

#### Fontes de imagens

O Docker Hub é consultado junto com dois catálogos gratuitos e endurecidos
(hardened), e todas as tags passam pelo mesmo pipeline de scan -- uma imagem
hardened vence por vulnerabilidades medidas, não por reputação. A coluna `Source`
informa de onde veio cada linha.

| Fonte | Registry | Observações |
|-------|----------|-------------|
| Docker Hub | `docker.io` | Listagem completa de tags, com tamanhos e datas |
| Chainguard | `cgr.dev/chainguard/<imagem>` | O nível gratuito acompanha tags móveis (`latest`, `latest-dev`); versões fixadas são recurso pago |
| Distroless | `gcr.io/distroless/<imagem>` | O GCR informa datas de publicação e tamanhos, então essas tags são ordenadas da mais recente para a mais antiga |
| Docker Hardened Images | `dhi.io` | Catálogo público, registry privado: sem credencial os candidatos ficam `UNVERIFIED`. Opt-in via `--source dhi` |

Selecione as fontes com `--source <nome>` (repetível) ou `--all-sources`; veja
[Fontes de imagens](#fontes-de-imagens-multi-source) para a lista completa e o
detalhamento do DHI.

Assinaturas cosign, atestados, SBOMs, apelidos de arquitetura única e duplicatas
fixadas por commit são filtrados das listagens -- não são imagens que alguém
baixaria. Uma fonte inacessível é registrada em log e pulada; ela nunca derruba
uma busca que as outras fontes ainda conseguem responder. Use `--no-hardened`
para consultar apenas o Docker Hub.

#### Saída, logs e evidências

O terminal mostra apenas um indicador de progresso e os resultados. Todos os
diagnósticos -- inclusive o stderr do scanner -- vão para
`$XDG_STATE_HOME/dockerls/logs/dockerls_<timestamp>.log` quando
`XDG_STATE_HOME` estiver definido, ou para
`~/.local/state/dockerls/logs/dockerls_<timestamp>.log` por padrão; use
`--verbose` para espelhá-los também no stderr. Defina `DOCKERLS_LOG_DIR` para
mudar o diretório de log, inclusive se você quiser manter logs no diretório do
projeto.

Nenhum comando emite log de nível `INFO` no stderr em uso normal: o piso do sink
de console é `WARNING`, independente de `DOCKERLS_LOG_LEVEL` (que controla o
nível do **arquivo** de log). `--verbose` reabre o stderr no nível configurado —
`INFO` por padrão, `DEBUG` com `DOCKERLS_LOG_LEVEL=DEBUG`.

O JSON bruto de cada scan é gravado em
`$XDG_STATE_HOME/dockerls/scans/<imagem>_<tag>__<scanner>__<timestamp>.json`
quando `XDG_STATE_HOME` estiver definido, ou em
`~/.local/state/dockerls/scans/<imagem>_<tag>__<scanner>__<timestamp>.json` por
padrão. Isso evita que uma execução casual polua o repositório analisado com
evidências e logs. O bloco `Details` abaixo da tabela aponta cada imagem para
seus próprios arquivos:

```
Details
  1. node:trixie-slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=trixie-slim
     trivy:    ~/.local/state/dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json
     grype:    ~/.local/state/dockerls/scans/node_trixie-slim__grype__20260806T153119491147.json
  2. node:slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=slim
     trivy:    ~/.local/state/dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json  (shared digest)
```

`(shared digest)` marca evidências produzidas sob o nome de uma tag irmã: tags
que apontam para o mesmo digest de manifesto são escaneadas uma vez e compartilham
o resultado. Junto é gravado um manifesto por execução ligando cada pontuação
exibida à sua evidência. Defina `DOCKERLS_EVIDENCE_DIR` para mudar o diretório.

O indicador de progresso é renderizado no **stderr** e os resultados no
**stdout**, então `dockerls recommend node > out.txt` mantém o indicador no seu
terminal e grava resultados limpos no arquivo.

| Flag | Efeito |
|------|--------|
| `--verbose` / `-v` | Também imprime logs no stderr |
| `--no-progress` | Desativa o indicador de progresso |
| `--no-cross-validate` | Pula a validação com o segundo scanner (mais rápido) |
| `--no-hub-check` | Pula a verificação de tag no registry (uso offline) |
| `--source <nome>` | Consulta só as fontes indicadas (repetível) |
| `--all-sources` | Consulta todas as fontes, inclusive as opt-in (DHI) |
| `--no-hardened` | Consulta apenas o Docker Hub |

#### Concorrência de scans

O Trivy trava com exclusividade o diretório de cache dele, então scans paralelos
que compartilham um mesmo cache falham com `cache may be in use by another
process: timeout`. O DockerLs baixa o banco de vulnerabilidades uma única vez no
início, depois dá a cada worker concorrente o seu próprio diretório de cache com
o banco vinculado por hard link, e remove esses diretórios ao fim da execução. Se
o hard link não for possível, ele recorre a um único cache compartilhado e
serializa os scans -- mais lento, porém nunca em disputa de trava.
`DOCKERLS_TRIVY_CACHE_DIR` sobrescreve a raiz do cache.

O Grype verifica atualizações do banco de vulnerabilidades a *cada* invocação, o
que é uma ida à rede por imagem. Por isso a validação cruzada roda
`grype db update` uma vez para o lote e depois escaneia com
`GRYPE_DB_AUTO_UPDATE=false`, e as validações em si rodam concorrentemente
(`DOCKERLS_CROSS_VALIDATE_WORKERS`, padrão 5), já que são independentes. A suíte
de aceitação limita o comando inteiro a um orçamento de 30 segundos para cinco
imagens.

### advisor

Consultor de segurança completo, com passos de correção.

```bash
dockerls advisor node
dockerls advisor node --format json

# Passando uma TAG, o advisor também explica a migração a partir dela
dockerls advisor node:22-alpine
```

A saída inclui: melhor imagem atual, pontuação de segurança, detalhamento de
vulnerabilidades, pontuação de correção e um plano de correção passo a passo.

Quando o argumento traz uma tag (`node:22-alpine` em vez de `node`), essa tag é
tratada como a imagem que você roda **hoje**: ela é escaneada pelo mesmo
pipeline e o advisor acrescenta a seção `Migration`, com ganho de pontuação,
trade-offs e checklist. Um nome sem tag mantém o comportamento de sempre.

```
Migration
  CURRENT      node:22-alpine
  RECOMMENDED  node:22-bookworm-slim
  PIN TO       node@sha256:...

  SECURITY IMPROVEMENT  +18.7 points

WHY
  OK CRITICAL: 2 -> 0
  OK HIGH: 5 -> 0
  OK target runs as a non-root account by default
  OK attack surface: 70 -> 25 (lower is better)

TRADE-OFFS
  ! C library changes (musl -> glibc): prebuilt native modules, wheels and cgo
    binaries linked against the old one will not load and must be rebuilt
  ! package manager changes (apk -> apt): every install step in your Dockerfile
    needs rewriting, and package names differ between them

MIGRATION CHECKLIST
  1. rebuild your image against node@sha256:...
  2. rebuild every native dependency for glibc (clear prebuilt binaries first)
  3. run the unit test suite against the rebuilt image
  4. run the integration test suite against the rebuilt image
  5. re-scan the resulting image (`dockerls analyze <your-image>`)
  6. verify runtime behaviour under production-like load
  7. deploy to a canary before rolling out
```

Nada aqui afirma que a migração é compatível — e nada poderia. Nenhum scan
consegue dizer se a sua aplicação continua rodando; é para isso que o checklist
existe.

### alternatives

Alternativas mais seguras para a imagem que você **já roda**, com o custo de
trocar.

```bash
dockerls alternatives node:22
dockerls alternatives node:22 --all-sources
dockerls alternatives python:3.12 --format json
```

A diferença para o `recommend` é a linha de base: aqui existe uma imagem
concreta da qual você depende, e ela é **escaneada pelo mesmo pipeline** dos
candidatos — a comparação é entre duas medições, nunca entre uma medição e uma
reputação.

```
CURRENT
  node:22  Docker Hub
  score 55.0  tier D  C/H/M 2/5/12

RECOMMENDED ALTERNATIVES
┌───┬────────────────────────────┬──────────┬───────┬───────┬────────┬──────┐
│ # │ Image                      │ Source   │ Score │ Delta │ C/H/M  │ Conf │
├───┼────────────────────────────┼──────────┼───────┼───────┼────────┼──────┤
│ 1 │ node:22-bookworm-slim      │ Docker…  │  88.0 │ +33.0 │ 0/0/3  │ HIGH │
│ 2 │ cgr.dev/chainguard/node    │ Chaing…  │  86.5 │ +31.5 │ 0/0/0  │ MEDI │
└───┴────────────────────────────┴──────────┴───────┴───────┴────────┴──────┘
```

Os números acima são **ilustrativos**: nada é fixado no código, tudo sai do scan
da sua execução.

Três recusas deliberadas:

* se a imagem atual **não pôde ser escaneada**, o comando termina em `1` e diz
  isso — sem linha de base, não há melhoria a afirmar;
* candidatos `UNVERIFIED` nunca são oferecidos como alternativa;
* quando nada pontua melhor que o que você já roda, o comando **diz isso**.
  Ficar onde está é um resultado, não uma falha.

| Exit code | Significado |
|---|---|
| `0` | alternativas encontradas (ou a imagem atual já é a melhor) |
| `1` | falha técnica: a imagem atual não pôde ser medida |
| `2` | há alternativas, mas nenhuma atinge o baseline |

### sbom

Gera um inventário de software (SBOM) para uma imagem via Trivy.

```bash
dockerls sbom node:22-alpine --format cyclonedx
dockerls sbom node:22-alpine --format spdx --output node.spdx.json
```

### analyze

Análise profunda de uma tag específica.

```bash
dockerls analyze node:22-alpine
dockerls analyze node:22-alpine --wide

# Saída legível por máquina, para CI
dockerls analyze node:22-alpine --format json
dockerls analyze node:22-alpine --format sarif -o results.sarif

# Portão de CI: reprova se houver achado na severidade indicada ou acima
dockerls analyze node:22-alpine --fail-on critical

# Patch de Dockerfile derivado dos achados
dockerls analyze node:22-alpine --fix
dockerls analyze node:22-alpine --fix --output Dockerfile.hardened
```

**`--fix` emite um patch, não "o seu Dockerfile corrigido".** A ferramenta
analisa uma imagem publicada e nunca viu o seu Dockerfile -- não há como
recuperar um do outro. O que sai é um `FROM <imagem-analisada>` seguido das
camadas que os achados justificam: copie as linhas `RUN` para o seu build, ou
construa a partir daí. Cada camada sai de um dado concreto — o gerenciador de
pacotes vem da distro que o scanner reportou, e os pacotes de linguagem são
**pinados na versão corrigida** que o próprio scanner entregou, em vez de um
`upgrade` cego. Nada é inventado: uma distro que a ferramenta não reconhece não
gera camada nenhuma, e os achados sem correção publicada aparecem listados como
pendência em vez de sumirem. Quando as duas remediações do npm embutido se
aplicam, ambas saem no patch — uma ativa, a outra comentada, porque são
mutuamente exclusivas.

Mostra todas as CVEs encontradas, pontuações CVSS, pacotes afetados e
disponibilidade de correção.

**Ordenação por severidade, não por CVSS.** As linhas saem CRITICAL primeiro,
depois HIGH, e só dentro de cada faixa é que o CVSS decide. Ordenar apenas por
CVSS decrescente empurrava um CRITICAL de nota 7,5 para baixo de sete HIGH de
nota 8,6 -- o achado mais grave ficava escondido na sexta linha.

**A coluna `Src` diz de qual base veio o CVSS.** Severidade e pontuação podem
vir de bases diferentes: o Trivy classifica pela fonte em `SeveritySource` (em
geral o vendor da distro) enquanto o bloco `CVSS` traz números de várias bases.
É por isso que um `CRITICAL` podia aparecer ao lado de um `7.5` e parecer erro
de conta. Agora a pontuação vem da mesma base que definiu a severidade, com
recuo para o NVD quando aquela base não publica nota -- e a base é dita.

**A coluna `Origin` separa pacote de SO de pacote de linguagem.** É a diferença
entre `apk upgrade` (que não resolve nada) e remover o npm da imagem final:
todas as vulnerabilidades de `node:22-alpine` estão em
`/usr/local/lib/node_modules/npm/node_modules/`, isto é, nas dependências do
npm que a imagem embute. Quando esse é o caso, a saída sugere as duas
remediações concretas.

**Histórico entre execuções.** Cada `analyze` grava, no cache local, o digest
e as contagens de vulnerabilidade da referência pedida. Na próxima vez que
você rodar `analyze` contra a mesma referência, duas linhas extras podem
aparecer:

- `tag history:` -- a tag mudou de digest desde a última vez (nunca aparece
  para uma referência já fixada por digest, que não tem "tag" para mover);
- `vuln trend:` -- as contagens de CRITICAL/HIGH/MEDIUM/LOW mudaram desde o
  último scan desta referência, mesmo que o digest seja o mesmo -- a base do
  scanner aprende sobre CVEs novas para bytes que não mudaram.

Nenhuma das duas aparece na primeira vez que uma referência é analisada: não
há histórico ainda, e dizer "sem mudança" nesse caso afirmaria uma
estabilidade que não foi observada. O histórico é por processo/máquina (vive
no cache local, com TTL de um ano) -- não é compartilhado entre execuções em
máquinas diferentes.

**A coluna `Threat` diz se há exploração conhecida.** Dois sinais dividem a
célula porque respondem à mesma pergunta por ângulos diferentes -- e uma CVE
pode estar num e não no outro:

| Valor | Significado |
|---|---|
| `KEV` | a CISA observou exploração real desta CVE em produção |
| `EDB` | há exploit publicado no Exploit-DB, ainda não verificado |
| `EDB*` | há exploit publicado **e verificado** (alguém reproduziu) |
| `KEV+EDB` / `KEV+EDB*` | os dois |
| `No` | as fontes responderam e nenhuma lista esta CVE |
| `-` | nada foi consultado -- fonte fora do ar, ou `DOCKERLS_ENABLE_THREAT_INTEL=false` |

O `-` e o `No` **não** são a mesma coisa, e essa é a razão de a coluna existir
em três estados. Com a fonte indisponível, imprimir `No` afirmaria que não
existe exploit conhecido a partir de uma consulta que nunca aconteceu.

O Exploit-DB é consultado pelo `files_exploits.csv` que o próprio projeto
publica -- o mesmo arquivo que o `searchsploit` lê --, cacheado por 24h. Não há
scraping do site, e o match é **estritamente CVE-ID contra CVE-ID**: buscar por
nome de pacote produziria falsos positivos, porque um exploit de 2015 para uma
versão antiga de um pacote não diz nada sobre a CVE que o scanner achou nesta
imagem hoje. Os EDB-IDs saem linkados abaixo da tabela, e em `--format json`
como `exploitdb_status`, `exploitdb_ids` e `exploitdb_verified`.

Nesta versão a explorabilidade é **informação exibida, não fator de
pontuação**: o Security Score, o Tier e o Remediation Score não mudam por causa
dela.

O ID da CVE nunca é truncado: ele é a chave primária do achado, e `CVE-2026…`
não pode ser consultado em lugar nenhum. Num terminal estreito quem cede
largura são as colunas de pacote e versão. Use `--wide` para renderizar a
tabela na largura que ela pedir, sem truncar coluna alguma.

### compare

Comparação lado a lado de duas ou mais imagens.

```bash
dockerls compare node:22-alpine node:22-bookworm-slim
```

Uma imagem que não pôde ser escaneada **nunca** aparece na tabela com score
ou tier. Ela sai numa seção `Failed (not compared)` à parte, com a causa
classificada (`NOT_FOUND`, `AUTH_REQUIRED`, ...), e a comparação segue com
as que foram medidas. O motivo é o de sempre: um scan que não rodou produz
score `0.0` e tier `F` por construção, e imprimir esses valores numa linha
da tabela afirma que a imagem foi medida e foi mal -- que é precisamente a
substituição que esta ferramenta existe para não fazer.

| Exit code | Significado |
|---|---|
| `0` | comparação completa: toda imagem pedida foi escaneada |
| `1` | erro rígido: menos de duas imagens na linha de comando, ou nenhuma pôde ser escaneada |
| `2` | comparação parcial: duas ou mais foram escaneadas, uma ou mais falharam |
| `3` | dado insuficiente: só uma imagem pôde ser escaneada, não há o que comparar |

`2` é o código a observar num pipeline que exige comparação completa: ele
distingue "comparei tudo" de "comparei o que deu", coisa que o `0` anterior
não permitia -- a comparação parcial saía silenciosamente como sucesso.

### export

Exporta os resultados da análise.

```bash
dockerls export node --format json
dockerls export node --format csv --output report.csv
dockerls export node --format html --output report.html
dockerls export node --format markdown --output report.md
dockerls export node --format sarif --output report.sarif
```

O formato `sarif` produz SARIF 2.1.0, adequado para envio ao code scanning do
GitHub ou a outras ferramentas que entendem SARIF.

### login

Autentica no Docker Hub (aumenta os limites de requisição).

```bash
dockerls login
```

As credenciais são guardadas no keyring do sistema. Alternativamente, defina
variáveis de ambiente:

```bash
export DOCKERHUB_USERNAME=meuusuario
export DOCKERHUB_TOKEN=meutoken
```

### logout

Remove as credenciais armazenadas.

```bash
dockerls logout
```

### doctor

Verifica as dependências locais. É o pré-voo de um job de CI: rode antes de
escanear qualquer coisa.

```bash
dockerls doctor
```

Saída real, numa máquina sem scanner nenhum:

```
DockerLs System Check

  trivy (Primary vulnerability scanner)          Not found
  grype (Fallback scanner / cross-validation)    Not found
  httpx                                          Available
  keyring                                        Available

DockerLs cannot measure anything on this machine.

Cause
  No vulnerability scanner is installed (needs Trivy or Grype).

Suggested action
  Install Trivy:  https://aquasecurity.github.io/trivy
  or install Grype: https://github.com/anchore/grype

Without a scanner, `recommend`, `analyze` and `advisor` report every tag as
unverified rather than as safe.
```

**Como ler.** O requisito é *um* scanner, não o Trivy especificamente — o
`ScannerFactory` funciona só com o Grype. Com apenas um dos dois instalados o
comando passa (`0`) e avisa que a validação cruzada fica indisponível; sem
nenhum, reprova.

**Exit codes:** `0` quando dá para medir, `1` quando não dá. Ele **reprova de
verdade**: um `doctor` que imprime "faltam componentes" e sai `0` deixa o runner
passar no próprio pré-voo e falhar depois, dentro do scan, onde a causa é muito
menos óbvia.

#### `doctor --install`: preparar a máquina

O diagnóstico acima é read-only e continua sendo o que roda por padrão.
`--install` é a única coisa que escreve algo, e **nunca roda sem
consentimento**: ou alguém confirma no terminal, ou `--yes` é passado
explicitamente (para pipeline não-interativo). Sem TTY e sem `--yes`, a
resposta é não.

```bash
dockerls doctor --install                          # confirma antes
dockerls doctor --install --yes                    # CI
dockerls doctor --install --install-dir ~/bin      # destino próprio
```

**De onde vem cada ferramenta.** Só do release oficial do próprio projeto,
nunca de um mirror de terceiro:

| Ferramenta | Fonte |
|---|---|
| `trivy` | `https://github.com/aquasecurity/trivy/releases` |
| `grype` | `https://github.com/anchore/grype/releases` |

**O que ele faz, e o que deliberadamente não faz.** O padrão usual para
instalar essas ferramentas é `curl ... | sh`, e ele está fora de questão aqui:
não há como verificar a integridade de um script antes de executá-lo, e nem o
Trivy nem o Grype publicam checksum do próprio `install.sh` — o que eles
publicam é o checksum dos binários. Então este caminho faz o que aquele script
faria, verificando:

1. resolve a versão publicada mais recente pela API de releases do projeto;
2. baixa o arquivo compactado **e** o `checksums.txt` do mesmo release;
3. confere o SHA-256 antes de qualquer extração;
4. extrai **apenas** o binário, com `tarfile`/`zipfile` do Python, sem shell.

O SHA-256 publicado é toda a verificação. A assinatura cosign do release
**não** é conferida: o `CosignClient` deste projeto verifica assinatura de
*imagem*, e um release é um blob — o instalador tem o gancho (`verify_blob`),
e ainda não há implementação por trás dele. Anunciar a verificação seria um
controle de segurança que existe só no texto de ajuda.

**Nada baixado é executado**, e nenhum script de instalação é buscado ou
rodado. Um `.tar.gz` pode conter caminhos como `../../.ssh/authorized_keys`, e
é assim que uma extração ingênua vira escrita arbitrária: só o membro com o
nome exato do binário, na raiz do arquivo, é aceito.

**Privilégio.** O destino padrão é `~/.local/bin` (ou o equivalente sob
`%LOCALAPPDATA%` no Windows) — diretórios do próprio usuário, então a
instalação não pede sudo. Se você apontar `--install-dir` para um lugar que
exige privilégio, isso aparece **na confirmação**, antes do download, nunca de
surpresa no meio da execução.

**Plataformas.** Linux e Windows (e macOS, que sai de graça do mesmo
mecanismo), em amd64 e arm64. Uma plataforma sem artefato publicado falha com
mensagem em vez de tentar uma URL genérica.

Tudo acontece num diretório temporário que é removido ao fim, com sucesso ou
sem: um download interrompido não deixa meio binário ocupando espaço nem meio
binário no PATH. Uma ferramenta que falha não impede a outra de ser tentada, e
ao final o mesmo diagnóstico roda de novo — dizer "instalado" sem reconferir
seria reportar a intenção em vez do resultado.

### health

Verifica a conectividade com os serviços externos dos quais a ferramenta depende:
Docker Hub, Chainguard, Distroless, endoflife.date, CISA KEV e EPSS. Termina com
código 1 se algum estiver inacessível ou responder com erro, para servir de
portão em CI.

```bash
dockerls health
```

Saída real:

```
Service Health Check

  Docker Hub API          OK (200)
  Chainguard (cgr.dev)    OK (200)
  Distroless (gcr.io)     OK (200)
  endoflife.date          OK (200)
  CISA KEV                OK (200)
  EPSS (FIRST)            OK (200)

All services reachable.
```

Cada endpoint da lista é um serviço do qual a ferramenta realmente depende **e**
que responde 2xx quando saudável. Um serviço inacessível vira
`Unreachable: ConnectError` e a execução termina em `1`; os demais continuam
sendo checados, então uma indisponibilidade não esconde as outras.

**Exit codes:** `0` com tudo acessível, `1` com qualquer serviço degradado.

### cache

Inspeciona e limpa o cache de análises.

```bash
dockerls cache stats     # o que o cache está guardando
dockerls cache cleanup   # remove só as entradas vencidas
dockerls cache clear     # esvazia tudo
```

Saída real de `dockerls cache stats`:

```
  Location                 /root/.cache/dockerls/cache.db
  Entries                  0
  Expired (reclaimable)    0
  Size on disk             44.0 KB
```

**Como ler.** As entradas vencem preguiçosamente — uma linha velha é descartada
quando alguém tenta lê-la de novo. Uma tag que ninguém consulta mais nunca é
lida, então fica ocupando espaço: `Expired (reclaimable)` é exatamente quanto o
`cleanup` recuperaria agora. `Size on disk` inclui o arquivo `-wal`, que entre
checkpoints pode conter a maior parte dos dados.

O cache é chaveado pelo **digest do manifesto**, não pela tag, e a chave carrega
uma versão de schema. Um rebuild upstream de `node:22-alpine` não é servido pela
entrada antiga, e uma entrada gravada por uma versão anterior do DockerLs nunca é
lida como se fosse atual.

### version

```bash
dockerls version
```

```
DockerLs v2.0.0
```

### analyze-dockerfile

Valida um Dockerfile contra as regras de hardening da OWASP e mostra a tabela de
checks, o score e as sugestões de correção.

```bash
dockerls analyze-dockerfile .
dockerls analyze-dockerfile ./app/Dockerfile --no-suggestions
dockerls analyze-dockerfile . --format json
```

Saída real, contra este Dockerfile deliberadamente ruim:

```dockerfile
FROM node:latest
RUN apt-get update && apt-get install -y curl
ENV API_TOKEN=supersecret123
COPY . /app
CMD ["node", "/app/index.js"]
```

```
╭────────────────────────────╮
│ Dockerfile Analysis Report │
│ Dockerfile.demo            │
╰────────────────────────────╯

Summary: ✅ 2 passed | ⚠️ 6 warnings | ❌ 3 errors

                              Validation Checks
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Status   ┃ Check                ┃ Message                                 ┃ Severity ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ ❌ FAIL  │ base_image_pinned    │ Base image uses 'latest' tag or no tag  │   HIGH   │
│          │                      │ (implies latest)                        │          │
│ ❌ FAIL  │ non_root_user        │ Container runs as root (no USER         │   HIGH   │
│          │                      │ directive or USER root)                 │          │
│ ⚠️ WARN  │ multi_stage_build    │ Single-stage build detected             │  MEDIUM  │
│ ❌ FAIL  │ secrets_not_in_env   │ Potential secrets in ENV: API_TOKEN     │ CRITICAL │
│ ⚠️ WARN  │ package_cache_clean  │ Package manager cache not cleaned       │  MEDIUM  │
│ ⚠️ WARN  │ healthcheck_present  │ No HEALTHCHECK directive                │   LOW    │
│ ⚠️ WARN  │ security_labels      │ Missing security labels:                │   LOW    │
│          │                      │ security.scanner, maintainer            │          │
│ ⚠️ WARN  │ minimal_base         │ Base image may not be minimal (consider │  MEDIUM  │
│          │                      │ Alpine or Distroless)                   │          │
│ ✅ PASS  │ no_sudo              │ No sudo usage detected                  │   INFO   │
│ ➖ SKIP  │ entrypoint_exec_form │ No ENTRYPOINT directive to check         │   INFO   │
│ ✅ PASS  │ shell_usage          │ CMD uses exec form                      │   INFO   │
│ ⚠️ WARN  │ dockerignore_exists  │ .dockerignore not found                 │   LOW    │
└──────────┴──────────────────────┴─────────────────────────────────────────┴──────────┘

╭────────────────────────╮
│ Security Score: 30/100 │
│ Tier: C                │
│ Production Ready: No   │
╰────────────────────────╯

╭────────────────────╮
│ 💡 Recommendations │
╰────────────────────╯

#1. Upgrade base image
   Use a pinned, minimal base image
   Current: node:latest
   Fix: FROM node:22-alpine or FROM chainguard/node:latest-dev
   Reason: Pinned versions ensure reproducibility; minimal bases reduce attack surface

#2. Add non-root user
   Container should not run as root
   Current: No USER directive
   Fix: RUN adduser -D appuser && USER appuser
   Reason: Running as root increases impact of container breakout

#3. Remove secrets from ENV
   Secrets in ENV are visible in image history
   Current: Secrets: API_TOKEN
   Fix: Use BuildKit secrets: RUN --mount=type=secret,id=token
   Reason: ENV values persist in all layers and can be extracted
```

(sete recomendações no total; as quatro restantes foram omitidas aqui)

**Como ler.** `FAIL` reprova, `WARN` não. Cada recomendação traz o estado atual,
a correção concreta e o motivo — a intenção é que a linha possa ser colada no
Dockerfile, não que sirva de lembrete genérico. `SKIP` significa que a diretiva
não existe para ser checada, e não que ela passou.

**Exit codes:** `2` quando algum check falha (`errors > 0`), `1` quando o
Dockerfile não existe ou não pôde ser lido, `0` quando passa. Avisos nunca
reprovam.

**Controles de referência.** Abaixo da tabela, cada check que falhou ou avisou
aparece com o controle publicado que ele implementa:

```
Controles de referência
  DF002  non_root_user
    A process running as uid 0 starts from the most privileged position
    available inside the container, so any code-execution bug begins with
    control of the filesystem and of anything mounted into it.
    -> CIS Docker Benchmark 4.1 -- Ensure that a user for the container has been created
    -> OWASP Docker Security Cheat Sheet RULE #2 -- Set a user
    -> NIST SP 800-190 4.1.2 -- Image configuration defects
```

Isso existe porque `DF002` não significa nada fora deste repositório. Um achado
que cita *CIS Docker Benchmark 4.1* pode ser discutido, escalado, dispensado com
justificativa e mapeado para um programa de auditoria; um achado que cita
`DF002` só pode ser obedecido ou ignorado. Regras que **não** têm controle
publicado dizem isso explicitamente, em vez de omitir a linha — a diferença
entre "isto é CIS 4.1" e "isto é opinião nossa" é justamente o que o leitor tem
direito de saber.

### controls

Lista o catálogo inteiro de regras e os controles que elas implementam, sem
precisar produzir um Dockerfile que falhe primeiro.

```bash
dockerls controls              # o regulamento inteiro
dockerls controls DF002        # uma regra, com a justificativa
dockerls controls --format json
```

```
DF002  Run as a non-root user
  A process running as uid 0 starts from the most privileged position available
  inside the container, so any code-execution bug begins with control of the
  filesystem and of anything mounted into it.
  -> CIS Docker Benchmark 4.1 -- Ensure that a user for the container has been created
  -> OWASP Docker Security Cheat Sheet RULE #2 -- Set a user
  -> NIST SP 800-190 4.1.2 -- Image configuration defects
```

Todo identificador e todo título foram **conferidos na fonte primária**, não
recuperados de memória: a seção 4 do CIS Docker Benchmark contra a
implementação da própria Docker (`docker/docker-bench-security`,
`tests/4_container_images.sh`), o OWASP Docker Security Cheat Sheet contra a
página publicada, e o NIST SP 800-190 contra o sumário da publicação oficial.
A conferência mudou o conteúdo: três das quatro citações rascunhadas de memória
estavam erradas. Uma ferramenta que se recusa a reportar uma contagem de
vulnerabilidades que não mediu também não pode citar um controle que não
conferiu.

**Exit codes:** `1` para uma regra desconhecida (falha em vez de responder
vazio), `0` caso contrário.

### base-image

Gera o Dockerfile de uma **imagem base** — sem aplicação nenhuma, feita para
outros projetos consumirem com `FROM`. Você marca num menu o que entra.

```bash
dockerls base-image                       # menu interativo
dockerls base-image --os alpine --runtime java --with ca-certificates,tzdata,tini
dockerls base-image --os distroless --runtime node --no-pin
```

O menu mostra, para cada pacote, **o que ele serve e o que ele custa** — porque
o custo é o que se descobre tarde demais:

```
Pacotes na imagem base
Cada um existe em toda aplicação que consumir esta base, e toda CVE dele vira
triagem para quem nem sabe que ele está lá.

  1. ca-certificates (já presente na maioria das bases)
       serve para: validar TLS ao falar com qualquer serviço HTTPS
       custa: praticamente nenhum; sem ele toda conexão TLS falha na verificação
  3. curl
       serve para: HEALTHCHECK por HTTP e diagnóstico de rede
       custa: um cliente HTTP completo dentro do container -- é o que um atacante
              usa para baixar o segundo estágio
  6. git
       serve para: clonar ou inspecionar repositórios em tempo de execução
       custa: raramente necessário em produção, e traz uma árvore de dependências
              grande; quase sempre pertence ao estágio de build

Números separados por vírgula (vazio = nenhum pacote): 1,2,9
Marcados: ca-certificates, tzdata, tini
Confirma? [s/n] (s):
```

**A base sai fixada por digest**, resolvido no registry na hora da geração: uma
imagem base com tag móvel propaga a incerteza para cada projeto que a consome,
que é o oposto do que ela existe para fazer. Quando o registry não responde, o
Dockerfile sai sem digest **e diz isso em voz alta** num comentário, em vez de
fingir que está fixado.

**Três recusas estão codificadas**, e todas vêm da mesma ideia — conveniência
que se paga em superfície de ataque não é conveniência:

| Recusa | Motivo |
|---|---|
| `sudo`, `su-exec`, cliente `docker` | numa imagem que já roda sem privilégio, existem para cruzar a fronteira que ela acabou de estabelecer |
| pacotes em **distroless** | não há gerenciador de pacotes nem shell ali — é o ponto dela; o comando explica em vez de gerar um Dockerfile que falha |
| cache do gerenciador em camada separada | removê-lo depois deixa os bytes na camada anterior: a imagem carrega o peso e a superfície mesmo parecendo não carregar |

O resultado **não tem `ENTRYPOINT`, `EXPOSE` nem `HEALTHCHECK`**: uma imagem
base não sabe em que porta a aplicação escuta nem o que significa "saudável"
para ela, e declarar isso seria herdado errado por todo consumidor. O
`analyze-dockerfile` vai avisar de HEALTHCHECK ausente — é WARN, não erro, e
neste caso a ausência é intencional.

Combinações publicadas: `none`, `java`, `node`, `python` e `go` sobre `alpine`,
`debian`, `ubuntu` e `distroless` — só as que existem de verdade. Pedir `go`
sobre `ubuntu` é recusado com a lista do que há para aquela família.

Depois de gerar, construa e escaneie — é o que transforma a receita numa
afirmação sobre segurança:

```bash
dockerls build -t base-java:1.0 --fail-on critical .
```

#### `--compare`: alpine ou debian para isto?

O menu diz o custo de cada pacote uma linha por vez, o que não ajuda na
pergunta que de fato se faz. `--compare` monta a mesma receita sobre outra
família e mostra **a diferença de superfície** — sem escrever arquivo nenhum,
porque responder uma pergunta sobrescrevendo um Dockerfile seria um efeito
colateral que ninguém pediu.

```console
$ dockerls base-image --os alpine --runtime node --with ca-certificates,tzdata --compare distroless

npm and yarn will be removed from the final image (--keep-manager mantém).

node:22-alpine  ->  gcr.io/distroless/nodejs22-debian12:nonroot

  - ca-certificates  validar TLS ao falar com qualquer serviço HTTPS
  - tzdata  fusos horários; sem ele o container fica em UTC e datas locais erram

  ! libc muda de musl para glibc: dependências compiladas precisam de roda para a
    nova, ou serão compiladas do zero no build -- e algumas simplesmente não compilam
  ! distroless não tem gerenciador de pacotes nem shell: nada pode ser instalado
    nela depois, e nenhum `docker exec` vai funcionar

este é um diff de conteúdo, não de vulnerabilidade: contar pacotes não mede CVE,
e a única resposta para qual das duas é mais segura vem de escanear as duas.
Construa e rode `dockerls scan` em cada uma
```

`--compare-with pkg,pkg` troca os pacotes do lado comparado; sem ele, os mesmos
são carregados (e os que não existem naquela família aparecem como removidos).

**O diff deliberadamente não elege uma vencedora.** Contar pacotes não mede
vulnerabilidade: uma base com menos pacotes e um deles desatualizado é pior do
que uma com mais pacotes e todos corrigidos. A troca de libc ganha destaque
próprio porque é a única que muda o contrato binário — descobrir isso no diff
custa segundos, e no build de produção custa a janela de deploy.

### base

Confere cada `FROM` do seu Dockerfile contra o registry e diz quais bases
apodreceram. Por padrão **aplica** a correção; `--dry-run` mostra sem escrever.

```bash
dockerls base                # confere e atualiza os digests
dockerls base --dry-run      # só mostra o que mudaria -- é o modo de portão de CI
dockerls base --format json
```

Saída real, contra um Dockerfile fixado num digest de 2024:

```console
$ dockerls base --dry-run
Dockerfile

  linha 4  PINNED_STALE  (estágio builder)
    python:3.12-slim-bookworm@sha256:a3e58f93...
    fixada num digest que a tag não aponta mais: a base foi republicada e esta
    imagem continua construindo a partir da versão antiga
    -> python:3.12-slim-bookworm@sha256:a116514e...  (ARG PYTHON_DIGEST)

  linha 7  UNPINNED  (estágio assets)
    node:22
    tag móvel, sem digest: o que você testou e o que vai para produção podem ser
    bytes diferentes sem nenhuma mudança da sua parte
    -> node:22@sha256:0557ac14...  (linha 7)

2 desatualizada(s), 1 sem digest

Nada foi escrito (--dry-run).
$ echo $?
2
```

**Por que este comando existe.** A base deste próprio projeto ficou meses
fixada num digest de meados de 2024, carregando duas CVEs CRITICAL do
`libexpat1` que já tinham correção publicada. O Dockerfile estava
"corretamente" fixado o tempo todo — e é justamente esse o problema: fixar sem
nunca reavaliar é trancar a porta e jogar fora o calendário. Nada avisa, nada
quebra, e a base velha entra em produção build após build.

**Os quatro estados**, porque cada um pede uma ação diferente:

| Estado | O que significa | Ação |
|---|---|---|
| `PINNED_CURRENT` | fixada no digest que a tag aponta hoje | nenhuma |
| `PINNED_STALE` | fixada num digest que a tag deixou para trás | atualizar |
| `UNPINNED` | só uma tag, sem digest | fixar |
| `UNRESOLVED` | o registry não respondeu | investigar — **não** é "está em dia" |

**Detalhes que evitam surpresa:** quando o digest vem de um `ARG`
(`FROM python:3.12@${PYTHON_DIGEST}`), a atualização vai para **a linha do
`ARG`** — é onde o digest mora, e escrever no `FROM` quebraria o contrato do
arquivo. `--platform`, `AS <estágio>`, comentários e indentação sobrevivem
intactos. Estágios de build entram na conferência junto com o final: um
`golang` velho compila com toolchain velho, e isso é cadeia de fornecimento
mesmo que a imagem final seja endurecida.

**Exit codes:** `2` quando sobra base a corrigir (é o portão de CI, junto com
`--dry-run`), `1` quando o Dockerfile não existe ou não tem `FROM`, `0` quando
está tudo em dia ou a correção foi aplicada.

**Histórico da tag.** Cada digest observado é guardado no cache local, com a
data. "Esta base mudou" e "esta base muda toda semana" pedem decisões
diferentes, e antes disso as duas produziam a mesma linha:

```console
  linha 4  PINNED_STALE
    python:3.12-slim-bookworm@sha256:a3e58f93...
    fixada num digest que a tag não aponta mais: a base foi republicada e esta
    imagem continua construindo a partir da versão antiga
    histórico: mudou de digest 6 vezes desde 2026-01-08T09:14:00+00:00, a última
    em 2026-08-19T02:31:00+00:00
```

O histórico **começa na primeira vez que esta ferramenta olhou** — o que
aconteceu antes disso é desconhecido, não ausente, e a mensagem diz isso em vez
de esconder. Ele é um extra sobre o diagnóstico: se o cache estiver
indisponível, o comando continua sem a linha em vez de falhar por causa de um
enfeite.

#### `--alternatives`: e se a base certa fosse outra?

`base` atualiza o digest — o que resolve a data e não resolve a escolha.
Trocar `node:22` por `node:22` de ontem continua sendo `node:22`. Com
`--alternatives`, cada `FROM` distinto é **escaneado junto das candidatas**, e
a melhor medida aparece com o custo da troca ao lado:

```console
$ dockerls base --dry-run --alternatives

Alternativas medidas

  node:22
    -> cgr.dev/chainguard/node@sha256:4b91...
      CRITICAL -4, HIGH -9, score +31.0
      ! não há shell: `docker exec` e scripts de entrypoint deixam de funcionar
      ! usuário não-root por padrão: volumes montados podem precisar de ajuste

  golang:1.23
    ? golang:1.23 não pôde ser escaneada, então nenhuma melhora sobre ela pode
      ser medida. Isso é falha técnica, não veredito sobre a imagem

Nada aqui é aplicado: trocar a família da base é decisão de arquitetura, não
atualização de digest. O `base` escreve digest; a troca de imagem é sua.
```

Exige scanner instalado e **leva minutos** — por isso é opt-in. Três coisas
não acontecem aqui, de propósito:

- **Nada é aplicado.** O `base` reescreve digest; trocar a família da imagem
  muda libc, shell e usuário, e isso é revisão de arquitetura.
- **"Não medimos" nunca vira "não há nada melhor".** A saída marca os dois de
  formas diferentes porque levam a decisões diferentes.
- **Uma candidata pior não é escondida.** Se a melhor colocada não melhora o
  que foi medido, ela aparece com os números — filtrar silenciosamente o que
  ficou pior transformaria a lista num argumento em vez de uma medição.

Depois de aplicar, **reconstrua e escaneie antes de publicar**: trocar o digest
da base muda a imagem, e nada além de um scan diz se para melhor.

### build

Constrói imagens Docker passando pela validação do Dockerfile antes e pelo scan
de vulnerabilidades depois.

```bash
# Só valida, não constrói nada -- é o modo indicado para portão de CI
dockerls build --validate-only .

# Mesma validação, saída JSON em stdout para o pipeline consumir
dockerls build --validate-only --ci-mode .

# Só as sugestões de hardening
dockerls build --suggest-hardening .

# Build de verdade, reprovando se o scan achar CRITICAL
dockerls build -t minha-app:1.0 --fail-on critical .

# Build, scan e publicação num registry, com responsabilidade declarada
dockerls build -t minha-app:1.0 \
  --registry meuregistro.azurecr.io/apps/minha-app \
  --owner "Time de Plataforma" \
  --security-contact seguranca@empresa.com \
  --source https://github.com/org/minha-app \
  --provenance ./supply-chain.json .

# Templates hardened disponíveis para --base
dockerls build --list-templates
```

#### Todas as opções do `build`

| Opção | O que faz |
|---|---|
| `path` | Diretório com o Dockerfile. Padrão: `.` |
| `-t`, `--tag` | Tag da imagem. Obrigatória, exceto em `--validate-only`, `--suggest-hardening` e `--interactive` |
| `--base` | Template hardened da base (`alpine`, `maven-alpine`, `go-scratch`, …) |
| `--hardened` | Gera e usa um Dockerfile hardened a partir do template |
| `--list-templates` | Lista os 39 templates agrupados por stack, com exemplos, e sai |
| `-i`, `--interactive` | Assistente passo a passo |
| `--scan` / `--no-scan` | Escaneia após o build. Padrão: escaneia |
| `--fail-on` | Limiar que reprova: `critical`, `high`, `medium`, `low` |
| `--auto-fix` / `--auto-remediate` | Ciclo de remediação automática |
| `--zero-vulns` | Remedia até zero CVEs |
| `--max-iterations` | Teto de rodadas de remediação. Padrão: `3` |
| `-r`, `--report` | Salva o relatório de segurança (JSON ou HTML) |
| `-o`, `--output` | Arquivo de saída do relatório |
| `--no-cache` | Desliga o cache do Docker |
| `--build-args` | Argumentos de build, em JSON |
| `--labels` | Rótulos extras da equipe, em JSON |
| `--validate-only` | Só valida o Dockerfile; não constrói nada |
| `--suggest-hardening` | Só sugere melhorias; não constrói nada |
| `--push` | Publica após o build passar nos portões |
| `--registry` / `--acr` | Destino da publicação, **sem tag** |
| `--owner` | Time ou pessoa responsável → `maintainer` e `vendor` |
| `--security-contact` | Contato para vulnerabilidades → `security.contact` |
| `--source` | URL do repositório → `org.opencontainers.image.source` |
| `--provenance` | Arquiva o registro de supply chain em JSON |
| `--production` | Perfil de produção: liga o conjunto inteiro de uma vez e diz o que ligou |
| `--attribute` | Escaneia também a base e diz de quem é cada CVE. Custa um segundo scan |
| `--sign` | Assina a imagem publicada com cosign. Exige `--push` e procedência verificada |
| `--policy` | Arquivo de política a conferir. Padrão: `.dockerls-policy.yaml` do contexto |
| `--no-policy` | Ignora a política do contexto. Fica registrado na saída |
| `--non-interactive` | Não pergunta nada: o que faltar vira erro |
| `--ci-mode` | Saída JSON em stdout, sem interação |
| `--force` | Constrói mesmo com erros de validação |
| `-v`, `--verbose` | Log detalhado no terminal |

Algumas dependem umas das outras e vale saber antes: `--push` e `--registry`
ligam `--fail-on critical` automaticamente; `--push` com `--no-scan` é
recusado; publicar exige `--owner`, `--security-contact` e `--source` —
perguntados no terminal, ou obrigatórios por opção sob `--non-interactive`;
`--production` liga `--attribute` junto; e `--sign` sem `--push` é ignorado com
aviso, porque só se assina o que foi publicado.

**Sobre `--fail-on`, e isto já foi um bug aqui:** o limiar mais estrito é o
**mais baixo**, não a palavra mais grave. `--fail-on low` reprova em LOW *e em
tudo acima dele*; `--fail-on critical` só olha para CRITICAL. Quando a política
e a linha de comando declaram limiares diferentes, vence o mais estrito nos
dois sentidos — um YAML commitado não desliga o portão do pipeline, e uma flag
não afrouxa a política da organização.

#### `--production`: o conjunto inteiro, sob um nome só

Uma imagem que vai para produção precisa de sete coisas ao mesmo tempo. A
alternativa a nomeá-las é uma lista de flags que cada pipeline digita de novo,
esquecendo uma diferente por vez — e a que faltar não aparece em lugar nenhum,
porque o build passa.

`--production` liga o conjunto e **imprime o que ligou**. Saída real:

```console
$ dockerls build --production --validate-only demo/servico

Perfil de produção
  fail_on  critical
  require_scan  True
  require_pinned_bases  True
  require_nonroot  True
  required_labels  org.opencontainers.image.source, org.opencontainers.image.vendor,
security.contact
  require_provenance  True
```

Um `.dockerls-policy.yaml` no contexto continua valendo e **só pode apertar**:
`--production` é um piso, não um teto. Um perfil que muda o comportamento em
silêncio é um perfil que a pessoa descobre pelo build reprovando, e a primeira
reação a um portão que reprova sem explicar é desligá-lo.

`fail_on` fica em `critical` e não em `high` de propósito: um perfil que
ninguém consegue cumprir é um perfil que as pessoas desligam inteiro, e `high`
reprova praticamente toda base Debian num dia qualquer. Se o seu time quer o
teto de HIGH, declare-o no `.dockerls-policy.yaml`, onde se enxerga e se
discute.

#### Preflight: reprovar em segundos o que reprovaria em dez minutos

`--validate-only` agora confere também a política — a parte dela que se decide
**só lendo o Dockerfile**. Descobrir um rótulo obrigatório faltando depois de
dez minutos de build e um scan é o tipo de atrito que faz as pessoas pararem de
rodar o portão.

Saída real, contra o `demo/servico/Dockerfile` acima:

```console
$ dockerls build --production --validate-only demo/servico
...
╭──────────────────────────────────────────────────────────────────────────────╮
│ ❌ Validation Failed                                                         │
│                                                                              │
│ Dockerfile validation failed: 1 error(s) -- non_root_user: Container runs as │
│ root (no USER directive or USER root)                                        │
╰──────────────────────────────────────────────────────────────────────────────╯

Política não cumprida
  x require_pinned_bases  node:22 não está fixada por digest: o que foi testado e o
que vai para produção podem ser bytes diferentes sem nenhuma mudança sua
  x require_nonroot  a política exige execução sem privilégio: a imagem roda como
root
  x required_labels  rótulo obrigatório ausente ou vazio:
org.opencontainers.image.source -- sem ele ninguém sabe a quem recorrer quando esta
imagem aparecer num alerta às três da manhã
  x required_labels  rótulo obrigatório ausente ou vazio:
org.opencontainers.image.vendor -- sem ele ninguém sabe a quem recorrer quando esta
imagem aparecer num alerta às três da manhã
  x required_labels  rótulo obrigatório ausente ou vazio: security.contact -- sem
ele ninguém sabe a quem recorrer quando esta imagem aparecer num alerta às três da
manhã

Estas regras vêm do perfil `--production` e/ou do .dockerls-policy.yaml do contexto.
O arquivo é versionado junto do código: mudá-lo é uma alteração revisável, passar
uma flag diferente na linha de comando não é.
$ echo $?
2
```

As regras que **dependem de medição** (`require_scan`, `require_provenance`,
`max_vulnerabilities`) não reprovam aqui — e também não são consideradas
cumpridas. Elas simplesmente não são conferíveis sem construir, e continuam
valendo no build de verdade.

#### `--attribute`: de quem é cada CVE?

Um relatório que diz "47 vulnerabilidades" manda consertar sem dizer o quê, e
quem lê passa a tarde descobrindo que **nada no Dockerfile dela resolve o
problema**. Aqui isso aconteceu de verdade: uma `base-node` recém-gerada
reprovava com um CRITICAL que não vinha de nenhuma linha do Dockerfile, e sim
do npm que a imagem oficial embute — foi preciso um terceiro produto para
descobrir.

`--attribute` escaneia a base declarada junto da imagem e cruza os dois
conjuntos pela mesma identidade (`CVE|pacote`) que a validação cruzada entre
scanners usa. O resultado divide em três, e as três levam a ações diferentes:

| Grupo | O que significa | O que fazer |
|---|---|---|
| `INHERITED` | está na base e continua na sua imagem | atualizar (`dockerls base`) ou trocar (`dockerls base --alternatives`) a base |
| `INTRODUCED` | não está na base, está na sua imagem | veio do que você instala, copia ou constrói — é a parte sob seu controle |
| `REMOVED` | estava na base e não está mais | a medida do que o seu `apk upgrade` comprou |

```console
$ dockerls build -t api:1.0 --attribute --fail-on critical .

De onde vêm as vulnerabilidades
41 de 47 vêm da base node:22-alpine; 6 vêm das camadas deste Dockerfile;
3 que a base tinha foram removidas no build

    41  herdadas da base
        veio da base e nenhuma linha do seu Dockerfile resolve: atualize a base
        (`dockerls base`) ou troque-a (`dockerls base --alternatives`)
     6  das suas camadas
        veio do que este Dockerfile instala, copia ou constrói: é a parte sobre a
        qual você tem poder direto
     3  removidas no build
        estava na base e não está mais na imagem final: é a medida do que o seu
        endurecimento comprou

87% das vulnerabilidades desta imagem vieram da base.
Mexer no seu Dockerfile não resolve essa parte: rode `dockerls base --alternatives`
para medir outra base.
```

> **Nota sobre este bloco:** os números acima são ilustrativos — a máquina que
> escreveu esta documentação não tem scanner nem daemon Docker, e inventar um
> scan real seria exatamente o que o resto desta ferramenta existe para não
> fazer. Todos os outros blocos `console` deste README são capturas verbatim.

**Sem os dois scans não há atribuição.** Se a base não pôde ser escaneada, o
relatório sai `UNAVAILABLE` com o motivo — nunca "tudo é seu" nem "tudo é
herdado", que seriam as duas maneiras de transformar ausência de medição em
acusação.

#### O plano de trabalho: origem × existe correção?

"41 vêm da base" ainda não diz se **atualizar** a base adianta. Se nenhuma das
41 tem correção publicada upstream, atualizar é trabalho perdido e trocar a
base é o único caminho. `--attribute` cruza as duas dimensões e imprime os
quatro grupos, do que tem mais CRITICAL para o que tem menos:

```console
Plano de trabalho
     2  da base, com correção, 1 CRITICAL
        há correção publicada upstream: atualizar a base pode resolver -- pode,
porque a correção existir não significa que quem publica a base já reconstruiu
com ela. `dockerls base` confere se a tag moveu
        CVE-2026-0001 (openssl), CVE-2026-0002 (zlib)
     2  da base, sem correção, 1 CRITICAL
        não há correção publicada: atualizar a base não resolve nada aqui. Trocar
de base é o único caminho -- `dockerls base --alternatives` mede as candidatas
        CVE-2026-0003 (perl-base), CVE-2026-0004 (libexpat1)
     1  suas, sem correção, 1 CRITICAL
        não há correção publicada e o pacote é seu: avalie remover, substituir ou
isolar. É o grupo em que uma isenção documentada em `.dockerls-ignore.yaml` faz
sentido -- com prazo
        CVE-2026-0101 (urllib3)
     1  suas, com correção
        há correção publicada: suba a versão da dependência no seu manifesto e
reconstrua
        CVE-2026-0100 (requests)
```

*(Bloco gerado com achados sintéticos, pelo mesmo motivo da nota acima; o
formato é o real.)*

Repare no hedge do primeiro grupo: **"pode resolver"**, não "resolve". Uma
correção existir upstream não significa que quem publica a base já reconstruiu
com ela — e prometer o contrário é como uma ferramenta perde a confiança de
quem seguiu o conselho e não viu o número cair. O `dockerls base` é quem
confere se a tag efetivamente moveu.

Os quatro grupos são ordenados pelo número de CRITICAL, não pelo total: é onde
a primeira hora de trabalho rende mais, e ordenar por total faria um monte de
LOW passar à frente de dois CRITICAL sem correção. `REMOVED` fica fora do plano
— um plano que lista o que já não existe faz a lista parecer maior do que o
trabalho é.

#### O portão também diz de onde veio

Quando `--attribute` rodou, a linha que reprova o build carrega a origem:

```
Vulnerabilities exceed threshold (critical): 3 finding(s) at or above CRITICAL
[2 da base node:22-alpine (1 com correção publicada), 1 das suas camadas]
-- CVE-2026-0001 (CRITICAL) in openssl 3.0.14-r0 -> 3.0.15-r0; ...
```

É a informação mais cara de obter e a mais barata de mostrar ali: quem lê o log
do CI está decidindo, naquele segundo, se mexe no Dockerfile ou na base. Sem
isso a decisão é um palpite. Quando a atribuição **não** rodou ou não fechou, a
linha fica calada sobre origem — um portão que insinua uma origem que não mediu
é pior do que um portão calado.

#### Exemplos práticos, com a saída real

**1. Validar sem construir** — é o modo indicado para portão de CI. Contra um
Dockerfile deliberadamente ruim:

```dockerfile
FROM node:latest
RUN apt-get update && apt-get install -y curl
ENV API_TOKEN=supersecret123
COPY . /app
CMD ["node", "/app/index.js"]
```

```console
$ dockerls build --validate-only .
╭──────────────────────────────────────────────────────────────────────────────╮
│ ❌ Validation Failed                                                         │
│                                                                              │
│ Dockerfile validation failed: 3 error(s) -- base_image_pinned: Base image     │
│ uses 'latest' tag or no tag (implies latest); non_root_user: Container runs   │
│ as root (no USER directive or USER root); secrets_not_in_env: Potential       │
│ secrets in ENV: API_TOKEN                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯
$ echo $?
2
```

Nada foi construído. Exit code `2` = política violada.

**2. Build com portão de segurança:**

```console
$ dockerls build -t minha-app:1.0 --fail-on critical .
╭─────────────────────╮
│ ✅ Build Successful │
│ minha-app:1.0       │
╰─────────────────────╯

╭────────────────────────╮
│ Security Score: 81/100 │
│ Tier: B                │
╰────────────────────────╯

✅ Validation: 11 passed | ⚠️ 1 warnings | ❌ 0 errors

╭──────────────────────────╮
│ 🔍 Security Scan Results │
╰──────────────────────────╯
  CRITICAL: 0
  HIGH: 0
  MEDIUM: 4
  LOW: 1
```

Se houvesse CRITICAL, o portão reprovaria **nomeando os CVEs**, com pacote e
versão de correção — não com uma contagem solta.

**3. Base inexistente falha antes de construir:**

```console
$ dockerls build -t x:1 --base alpine-qualquer .
Error: --base inválido: 'alpine-qualquer'.
Disponíveis: alpine, debian, distroless, go, go-alpine, go-debian, go-distroless,
go-scratch, gradle, gradle-alpine, java, java-alpine, ... maven, maven-alpine, ...
$ echo $?
1
```

**4. Publicar sem dizer quem responde é recusado:**

```console
$ dockerls build -t x:1 --registry meuacr.azurecr.io/apps/x --push --non-interactive .
Destino: meuacr.azurecr.io/apps/x:1  (Azure Container Registry)
Autenticação: az acr login --name <registro>
Error: faltam rótulos obrigatórios: owner, security_contact, source. Informe-os nas
opções do build ou responda às perguntas (use --non-interactive para exigir que
venham por opção).
$ echo $?
1
```

Note que o destino foi validado e o comando de login foi nomeado **antes** de
qualquer build começar.

**5. O caminho completo, do jeito que vai para produção:**

```bash
dockerls build -t minha-api:1.0 \
  --hardened --base maven-alpine \
  --registry meuregistro.azurecr.io/apps/minha-api \
  --owner "Time de Plataforma" \
  --security-contact seguranca@empresa.com \
  --source https://github.com/org/minha-api \
  --provenance ./supply-chain.json \
  --report ./relatorio.json .
```

Gera um Dockerfile hardened de Java com Maven sobre Alpine, constrói, escaneia,
reprova em CRITICAL (ligado sozinho por publicar), publica no ACR, e deixa em
disco o relatório e o registro de supply chain.

**6. Em pipeline**, com saída JSON e sem nenhuma pergunta:

```bash
dockerls build -t minha-api:${GITHUB_SHA::7} --ci-mode --non-interactive \
  --registry ghcr.io/org/minha-api \
  --owner "$TEAM" --security-contact "$SEC_EMAIL" --source "$REPO_URL" .
```

O JSON em stdout carrega `status`, `exit_code`, `report` e `provenance` — é o
que o portão do pipeline lê.

#### Escolhendo a base: SO e stack

**Sem `--base` nem `--hardened`, o build usa o Dockerfile que já está no
diretório.** Ele não inventa base nenhuma — se o seu Dockerfile é de Python, a
imagem sai em Python. Os templates só entram quando você pede um:

```bash
# Node sobre Alpine
dockerls build --hardened --base node-alpine -t minha-api:1.0 .

# Java com Maven: constrói com a ferramenta, roda só com o JRE
dockerls build --hardened --base maven-alpine -t minha-api:1.0 --fail-on critical .

# Go estático, sem sistema operacional nenhum embaixo
dockerls build --hardened --base go-scratch -t minha-api:1.0 .

# Só o sistema operacional, sem runtime de linguagem
dockerls build --hardened --base ubuntu -t minha-base:1.0 .
```

São 39 templates, e `--list-templates` mostra todos agrupados por stack, com o
sistema operacional e o que distingue cada variante:

| Stack | Variantes |
|---|---|
| Sistema operacional puro | `alpine` `debian` `ubuntu` `distroless` |
| Node.js | `node` `node-alpine` `node-debian` `node-ubuntu` `node-distroless` |
| Python | `python` `python-alpine` `python-debian` `python-ubuntu` `python-distroless` |
| Java (runtime) | `java` `java-alpine` `java-debian` `java-ubuntu` `java-distroless` |
| Java com Maven | `maven` `maven-alpine` |
| Java com Gradle | `gradle` `gradle-alpine` |
| Go | `go` `go-alpine` `go-debian` `go-distroless` `go-scratch` |
| Rust | `rust` `rust-alpine` `rust-debian` `rust-scratch` |
| PHP | `php` `php-alpine` `php-debian` `php-ubuntu` |
| Ruby | `ruby` `ruby-alpine` `ruby-debian` |

Os de **Maven** e **Gradle** são multi-stage de verdade: a ferramenta de build
fica no primeiro estágio e o runtime carrega apenas o JRE. Compilador, cache do
Maven e a árvore de dependências de build não são necessários para *rodar* a
aplicação, e cada um deles é superfície de ataque e CVE para triar depois.

Ao escolher entre variantes, o que decide costuma ser a libc: `-alpine` é musl,
o resto é glibc. Módulos nativos de Node (`sharp`, `bcrypt`) e wheels de Python
precisam de build musllinux para funcionar lá. As `-distroless` não têm shell
nem gerenciador de pacotes — a menor superfície entre as que ainda carregam um
runtime; `go-scratch` e `rust-scratch` são o binário estático sozinho.

#### Publicar exige veredito

`--push` ou `--registry` ligam o portão de segurança automaticamente em
`critical` — não é preciso lembrar de passar `--fail-on`, e `--fail-on` continua
valendo quando você quer outro limiar. `--push` junto de `--no-scan` é recusado
de saída: uma imagem não medida não é uma imagem segura, é uma imagem
desconhecida.

#### Perguntas antes do build

Publicar sem saber para onde e sem saber quem responde é o que estas perguntas
impedem. Elas aparecem **antes** de validar, construir e escanear — descobrir
um destino errado depois disso desperdiça o trabalho inteiro, e rotular depois
do build significa reconstruir:

```
Para onde esta imagem vai?
  Azure ACR        meuregistro.azurecr.io/apps/minha-app
  Google Artifact  us-central1-docker.pkg.dev/meu-projeto/containers/minha-app
  Google GCR       gcr.io/meu-projeto/minha-app
  Docker Hub       minhaorg/minha-app
  GitHub GHCR      ghcr.io/org/minha-app
  Registry privado registry.interna:5000/time/minha-app

Quem responde por esta imagem?
  Time ou pessoa responsável pela imagem:
  Para quem avisar sobre uma vulnerabilidade nesta imagem:
  URL do repositório que gera esta imagem:
```

As respostas viram rótulos `org.opencontainers.image.*` no manifesto, mais
`maintainer`, `security.contact` e `security.scanner` — os mesmos que a regra
DF007 desta ferramenta cobra de todo Dockerfile que ela analisa.

Em pipeline, `--non-interactive` (ou `--ci-mode`) troca a pergunta por um erro
explícito: um runner não tem quem responda, e travar esperando entrada é o pior
comportamento possível ali. Cada provedor tem sua regra real de validação — o
Artifact Registry exige `projeto/repositório/imagem` no caminho, o Docker Hub
exige um namespace que não seja `library` — e a recusa nomeia o comando de
login que destrava aquele registry, porque o `denied` do Docker não diz qual é.
`dhi.io` é recusado como destino: ele distribui imagens endurecidas e não
aceita push.

#### Supply chain: hash antes, hash depois

Cada build produz um registro do que entrou e do que saiu:

```
🔗 Supply chain: VERIFIED
  entrada e saída digeridas, e a entrada não mudou durante o build

ENTRADA (medida antes do build)
  Dockerfile  sha256:4f1c…
  Contexto    sha256:9ab2…  (137 arquivos)
  Commit      7888d10…  (árvore suja)
  Base        python:3.12-alpine@sha256:d09d… -> sha256:d09d…

SAÍDA (medida depois do build)
  Imagem      sha256:21b0ca852dea…
  Manifesto   sha256:c7e4…
  Publicada   meuregistro.azurecr.io/apps/minha-app:1.0
```

O que faz disso controle e não decoração é a comparação: a entrada é digerida
de novo **depois** do build. Se o Dockerfile ou o contexto mudaram no meio do
caminho, o registro sai como `INPUT_CHANGED` e **a publicação é recusada** — a
imagem existe, mas não corresponde ao que foi medido. Entrada ou saída que não
puderam ser digeridas dão `INCOMPLETE`, que é ausência de prova e nunca vira
prova de integridade.

O digest do contexto é determinístico por construção: caminhos ordenados e
relativos, com o nome de cada arquivo entrando no digest junto do conteúdo, de
modo que renomear muda o contexto tanto quanto editar. O `.dockerignore` é
respeitado, porque ele decide o que o daemon realmente recebe. Uma base sem
digest é registrada como **tag móvel** em vez de omitida. O registro sai no
terminal, no `--format json` sob `provenance`, e em disco com `--provenance`.

Saída real de `dockerls build demoapp --validate-only` (mesmo Dockerfile da seção
anterior), com o rodapé que fecha a validação:

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ ❌ Validation Failed                                                         │
│                                                                              │
│ Dockerfile validation failed: 3 error(s) -- base_image_pinned: Base image     │
│ uses 'latest' tag or no tag (implies latest); non_root_user: Container runs   │
│ as root (no USER directive or USER root); secrets_not_in_env: Potential       │
│ secrets in ENV: API_TOKEN                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Exit code: `2`. Nada foi construído.

A mesma execução com `--ci-mode` produz JSON estruturado em stdout, que é o que o
pipeline consome (saída real, truncada):

```json
{
  "status": "FAILED",
  "exit_code": 2,
  "report": {
    "build_id": "0a822d4afbd9c950",
    "timestamp": "2026-08-16T19:12:06.007864+00:00",
    "image": "",
    "dockerfile_path": "demoapp/Dockerfile",
    "security_score": 30,
    "security_tier": "C",
    "validation": {
      "dockerfile_path": "demoapp/Dockerfile",
      "passed": 2,
      "warnings": 6,
      "errors": 3,
      "checks": [
        {
          "check": "base_image_pinned",
          "status": "FAIL",
          "message": "Base image uses 'latest' tag or no tag (implies latest)",
          "severity": "HIGH",
          "line": null
        }
      ]
    }
  }
}
```

Repare que o `exit_code` também vem **dentro** do documento: um consumidor que já
capturou o stdout não precisa correlacionar com o status do processo.

`--validate-only` e `--suggest-hardening` renderizam a mesma tabela de checks que
`analyze-dockerfile`, com o resumo das regras violadas ao final. Em `--ci-mode` a
saída é JSON estruturado em stdout, sem cores e sem tabela, contendo o relatório
completo — inclusive quando a validação reprova, que é exatamente quando o CI
precisa saber qual regra falhou.

Uma validação com `errors > 0` barra o build (`--force` ignora e constrói assim
mesmo).

`--fail-on` aceita `critical`, `high`, `medium` ou `low`, e cada nível reprova
também tudo que for mais severo que ele. Um valor fora dessa lista é rejeitado
antes do build começar — um limiar que a ferramenta não entende viraria um
portão aberto com cara de fechado. Pelo mesmo motivo, `--fail-on` sem nenhum
scanner disponível termina em `1` (o portão não pôde ser avaliado), nunca em `0`.

`--push` publica a tag **depois** dos portões: uma imagem que reprovou no scan
não é publicada.

#### `--hardened` é gerado no build, não na validação

`--hardened`/`--base` escrevem `Dockerfile.hardened` no diretório de contexto.
Combinado com `--validate-only`, **nada é escrito em disco**: um dry-run não tem
efeito colateral. Para gerar o arquivo, rode o build sem `--validate-only`.

### fleet

Varre uma árvore de repositórios e resume o estado de **todos** os Dockerfiles
de uma vez.

Cada outro comando desta ferramenta olha para um artefato. Isso resolve a
pergunta de quem está com o arquivo aberto e não resolve nenhuma das perguntas
de quem responde por trinta repositórios: "quantos ainda rodam como root?",
"quantos fixam a base?", "por onde eu começo?". Sem resposta, a resposta na
prática vira "por onde alguém reclamar".

```bash
dockerls fleet                       # varre o diretório atual
dockerls fleet ~/repos --limit 10    # só os dez primeiros da fila
dockerls fleet ~/repos --format json
dockerls fleet ~/repos --policy ./org-policy.yaml
```

```console
$ dockerls fleet ~/repos

/home/ana/repos
12 Dockerfile(s), 4 com todas as bases fixadas, 5 rodando como root, 1 com usuário indeterminado

  pagamentos/Dockerfile
    0/1 fixada(s)  root  1 estágio(s)
    x require_pinned_bases  node:22 não está fixada por digest: o que foi testado
      e o que vai para produção podem ser bytes diferentes sem nenhuma mudança sua
    x require_nonroot  a política exige execução sem privilégio: a imagem roda como root
  faturamento/Dockerfile.prod
    1/2 fixada(s)  sem privilégio  2 estágio(s)
    x require_pinned_bases  golang:1.23 não está fixada por digest: ...
  catalogo/Dockerfile
    2/2 fixada(s)  sem privilégio  2 estágio(s)

6 arquivo(s) com violação, 9 no total.
Só as regras decidíveis sem build foram aplicadas; as que dependem de scan
continuam valendo no `dockerls build`.
esta varredura lê Dockerfiles: não constrói imagem nem chama scanner. Ela diz o
que os arquivos declaram, e nada sobre as vulnerabilidades das imagens que eles
produzem
$ echo $?
2
```

**A fila é ordenada por violações, e o empate é resolvido pelo caminho.** O
desempate não é detalhe: sem ele a mesma frota sairia em ordem diferente a cada
varredura, e nenhum relatório seria comparável com o anterior.

**"root" e "indeterminado" são contados separados.** Juntá-los transformaria
ausência de medida em acusação, e a fila de trabalho de cada um é diferente.

**Só as regras decidíveis sem build são aplicadas** — `require_pinned_bases`,
`require_nonroot`, `required_labels` e `allowed_base_registries`. As que
dependem de scan (`fail_on`, `max_vulnerabilities`, `require_scan`,
`require_provenance`) continuam valendo no `build`, onde há medição para
conferi-las: aplicá-las aqui produziria uma violação idêntica por arquivo, e
uma lista toda vermelha não distingue nada.

**Um `FROM python:3.12@${PY}` conta como fixado.** As bases são lidas com
expansão de `ARG` — é a forma correta de fixar, e uma varredura que reprova
quem fez certo é uma varredura que ensina a fazer errado.

**Limites da varredura**, porque andar no disco é onde este comando pode se
machucar: symlinks nunca são seguidos (um link para `/` transformaria a
varredura de um repositório numa varredura da máquina), diretórios de
dependência (`node_modules`, `.venv`, `vendor`, `.git`, …) ficam de fora, e há
teto de arquivos e de profundidade. **Quando o teto é atingido, o relatório diz
que foi truncado** — um retrato parcial que se apresenta como completo é pior
do que nenhum retrato. Um arquivo ilegível vira uma linha de erro e nunca
desaparece: sumir com ele faria a frota parecer menor e mais em ordem do que é.

**O que este comando não faz está dito na própria saída.** Ele lê Dockerfiles;
não constrói imagem nem chama scanner. Chamar isso de "auditoria de segurança
da frota" seria exatamente a promessa que o resto desta ferramenta existe para
não fazer.

**Exit codes:** `2` quando há violação de política (é o portão de um repositório
guarda-chuva), `1` quando a raiz não é um diretório ou a política não carrega,
`0` caso contrário.

### policy

Mostra e valida a política declarada em `.dockerls-policy.yaml` — a política da
organização escrita **uma vez, versionada junto do código**, e conferida em
todo `dockerls build` naquele contexto.

`--fail-on critical` é um portão, mas é um portão que mora na linha de comando,
e uma regra que mora na linha de comando é uma regra que cada pipeline
reescreve à mão. Bastava um `--fail-on high` esquecido num repositório para que
a política deixasse de valer ali, sem que nada acusasse.

```yaml
# .dockerls-policy.yaml
fail_on: high
require_scan: true
require_pinned_bases: true
require_nonroot: true
require_provenance: true
required_labels:
  - org.opencontainers.image.source
  - org.opencontainers.image.vendor
allowed_base_registries:
  - docker.io
  - cgr.dev
max_vulnerabilities:
  critical: 0
  high: 5
```

| Regra | O que exige | Como é medida |
|---|---|---|
| `fail_on` | severidade a partir da qual o build reprova | contagem do scan |
| `max_vulnerabilities` | teto por severidade | contagem do scan |
| `require_scan` | que um scanner tenha rodado | presença do resultado |
| `require_pinned_bases` | todo `FROM` fixado por digest | os `FROM` lidos do Dockerfile, estágios intermediários incluídos |
| `require_nonroot` | execução sem privilégio | veredito do DF002 |
| `required_labels` | rótulos que a imagem carrega | os `LABEL` aplicados no build |
| `allowed_base_registries` | de onde as bases podem vir | host de cada `FROM` (sem host = `docker.io`) |
| `require_provenance` | procedência `VERIFIED` | comparação entre entrada e saída do build |

```bash
dockerls policy                  # mostra as regras do contexto atual
dockerls policy --format json    # para o pipeline consumir
dockerls build -t app:1.0 .      # confere automaticamente, se o arquivo existir
dockerls build --policy ../org-policy.yaml -t app:1.0 .
dockerls build --no-policy -t app:1.0 .   # ignora, e diz isso na saída
```

**Só entra o que é mensurável.** Não há regra de "não use pacotes inseguros" ou
"mantenha a imagem pequena": não há como decidir isso a partir de um build, e
uma regra que não pode ser avaliada é uma regra que reprova por engano ou
aprova por omissão.

**Não medir nunca aprova.** `max_vulnerabilities` sem scan é violação, não
silêncio — "contagem ausente" não é "contagem dentro do teto". `require_nonroot`
com a checagem ausente é violação, e a mensagem distingue "roda como root" de
"não foi possível determinar".

**A política nunca afrouxa o que a linha de comando apertou.** Quando as duas
declaram `fail_on`, vale a mais estrita: senão bastaria commitar um YAML para
publicar o que não passaria.

**Um arquivo malformado é erro, não ausência de política.** É a única diferença
importante de comportamento em relação ao `.dockerls-ignore.yaml`, e ela vem da
direção da falha: uma regra de ignore que não carrega deixa de esconder uma CVE
(mais alarme, e alarme a mais é seguro); uma regra de política que não carrega
deixa de exigir alguma coisa, e o build passa parecendo ter sido conferido.
`require_non_root` no lugar de `require_nonroot` viraria um portão aberto com
cara de fechado — então chave desconhecida, tipo errado e severidade
inexistente **falham o comando**:

```console
$ dockerls policy
Erro: .dockerls-policy.yaml: regra(s) desconhecida(s): require_non_root. As
aceitas são: allowed_base_registries, fail_on, max_vulnerabilities,
require_nonroot, require_pinned_bases, require_provenance, require_scan,
required_labels. Uma chave digitada errado seria um portão aberto com cara de
fechado.
$ echo $?
1
```

**Exit codes:** `1` quando o arquivo existe e não pôde ser entendido, `0`
quando carrega ou quando não há arquivo nenhum. No `build`, uma regra violada é
`2` (violação de política), e a imagem **não é publicada**.

### provenance

Confere um documento escrito por `build --provenance` e prepara a atestação.
Arquivar é metade do controle; a outra metade é alguém conferir antes de o
artefato seguir adiante — e era essa metade que faltava. Um documento que
ninguém lê descreve com precisão uma imagem que ninguém sabe se deveria ter
sido publicada.

```bash
dockerls provenance ./supply-chain.json                  # confere e mostra a cadeia
dockerls provenance ./supply-chain.json --format json    # para o pipeline consumir
dockerls provenance ./supply-chain.json --github-output  # dentro do GitHub Actions
```

```console
$ dockerls provenance ./supply-chain.json

minha-app:1.0
  VERIFIED  entrada e saída digeridas, e a entrada não mudou durante o build

  entrada
    Dockerfile  sha256:9f2c...
    contexto    sha256:41ae...  (128 arquivo(s))
    revisão     4b1c9d2  (com alterações não commitadas)
    base        python:3.12-alpine -> sha256:d09d15e6...

  saída
    sujeito     ghcr.io/org/minha-app:1.0
    digest      sha256:7c3b...  (manifesto no registry)
    scanner     trivy 0.58.0

$ echo $?
0
```

**O veredito é recalculado, não lido.** O campo `"status": "VERIFIED"` de um
arquivo JSON é editável por qualquer pessoa com um editor de texto; a
comparação entre os digests de antes e depois do build não é. Ler o status
gravado seria pedir ao documento que se auto-aprovasse.

**Exit codes:** `2` quando a procedência não fecha — `INPUT_CHANGED` (o
Dockerfile ou o contexto mudaram durante o build), `INCOMPLETE` (parte da
entrada ou da saída não pôde ser digerida) ou sem digest do artefato (uma
assinatura aponta para bytes, e "a imagem com esta tag" não são bytes). `1`
quando o arquivo não existe ou não é JSON válido. `0` só quando a cadeia fecha.

#### Fechando a cadeia no GitHub Actions

`--github-output` escreve `subject-name`, `subject-digest` e
`provenance-status` em `$GITHUB_OUTPUT`, para que
`actions/attest-build-provenance` ateste **exatamente a imagem que o scan
mediu**. Tirar o digest do documento em vez de redigitá-lo no YAML é o que
impede o caso silencioso: uma assinatura perfeitamente válida apontando para
bytes que ninguém escaneou.

```yaml
- name: Conferir a procedência
  id: provenance
  run: dockerls provenance provenance.json --github-output

- name: Atestar a imagem publicada
  uses: actions/attest-build-provenance@v2
  with:
    subject-name: ${{ steps.provenance.outputs.subject-name }}
    subject-digest: ${{ steps.provenance.outputs.subject-digest }}
    push-to-registry: true
```

O passo de assinar simplesmente não roda sobre um build cuja entrada mudou no
meio do caminho: o comando anterior falha o job. O workflow completo está em
[`examples/github/image-release.yml`](examples/github/image-release.yml).

### verify

Confere a assinatura de uma imagem com [cosign](https://github.com/sigstore/cosign).

O `scan` diz o que há dentro de uma imagem e o `provenance` diz de onde ela
veio. Nenhum dos dois impede alguém com acesso de escrita ao registry de
sobrescrever a tag com outra coisa: os dois falam sobre o artefato que
mediram, e a tag deixou de apontar para ele. A assinatura é o elo que fecha
isso — ela responde *quem publicou estes bytes*.

```bash
dockerls verify ghcr.io/org/app@sha256:4b91...
dockerls verify ghcr.io/org/app@sha256:4b91... \
  --identity 'https://github.com/org/.*' \
  --issuer https://token.actions.githubusercontent.com
```

**`cosign` ausente nunca vira "não assinado".** Confundir os dois acusaria
alguém por causa de uma ferramenta que faltava na máquina; na direção oposta,
uma verificação que falha em silêncio produz confiança sem base, que é pior do
que desconfiança. Por isso há **três saídas distintas**, e um pipeline precisa
delas:

| Exit | Estado | O que aconteceu |
|---|---|---|
| `0` | `VERIFIED` | o cosign conferiu e a assinatura vale |
| `2` | `UNSIGNED` | o cosign rodou e respondeu: não há assinatura. **Veredito** |
| `2` | `VERIFICATION_FAILED` | há assinatura, mas é de outra identidade/emissor, ou não confere de outra forma. **Veredito, pior que `UNSIGNED`** — não trate como "sem assinatura" |
| `1` | `SIGNER_MISSING` / `FAILED` | o cosign não rodou, ou falhou. **Falha do medidor** |

`VERIFICATION_FAILED` existe separado de `UNSIGNED` porque as duas são
veredictos muito diferentes: uma imagem sem assinatura é uma lacuna de
processo, uma imagem assinada pela parte errada é um artefato adulterado. As
duas saem por `EXIT_POLICY` — reprovação — e nenhuma pelo `EXIT_ERROR`
reservado a "não deu para conferir".

**Verificar sem `--identity` e `--issuer` responde "alguém assinou"**, não
"quem você espera assinou" — e a saída diz isso em vez de deixar passar como
se fosse a mesma coisa.

#### `dockerls build --sign`

Assina a imagem **depois** do push, e só quando é legítimo assinar:

```bash
dockerls build -t app:1.0 --registry ghcr.io/org/app --push --sign \
  --provenance ./supply-chain.json .
```

Duas recusas moram aí, e as duas são sobre o mesmo erro — uma assinatura aponta
para bytes e diz "eu publiquei isto":

- **Procedência não verificada recusa a assinatura.** Assinar sobre um artefato
  cuja entrada não fecha seria carimbar o desconhecido.
- **Sem digest do manifesto, recusa também.** Assinar a tag assinaria o que ela
  aponta agora, e ela pode mover no instante seguinte: a assinatura seguiria
  válida cobrindo outros bytes. A referência assinada é sempre
  `repositório@sha256:...`, com a tag removida.

O modo é keyless (OIDC) por padrão, porque é o que funciona em CI sem segredo
de longa duração no repositório — e um segredo de longa duração num
repositório é exatamente o que a assinatura deveria estar protegendo.

### registry-audit

Apura, **só pelo protocolo OCI e sem credencial de nuvem**, o que o registry
conta sobre uma imagem publicada.

Auditar a configuração de um registry — retenção, IAM, content trust — exige
credencial de nuvem e uma API diferente para cada provedor. Este comando não
faz isso, e a saída diz que não faz. A troca é deliberada: um relatório que
precisa de acesso administrativo para existir é um relatório que ninguém roda,
e o que dá para medir sem credencial é menos do que parece e mais do que se
costuma olhar.

```console
$ dockerls registry-audit cgr.dev/chainguard/static:latest

cgr.dev/chainguard/static:latest
sha256:14e00fd...

  v RESOLVABLE
      o registry respondeu qual digest esta referência aponta
  x PINNED_REFERENCE
      a referência é uma tag: o que foi testado e o que roda podem ser bytes
      diferentes sem nenhuma mudança sua
  i PUBLICLY_READABLE
      o registry respondeu sem nenhuma credencial: qualquer pessoa da internet
      consegue baixar esta imagem e inspecionar o que há dentro dela. Se isso é
      problema depende de para que ela existe, e essa parte só você sabe
  ? TAG_STABLE
      não há histórico desta tag: o que aconteceu antes da primeira observação
      é desconhecido, não ausente
  v SIGNATURE_PRESENT
      há assinatura cosign publicada para este digest
  v ATTESTATION_PRESENT
      há atestação cosign publicada para este digest

1 achado(s) que pedem atenção, 1 não medido(s)
esta auditoria usa só o protocolo OCI, sem credencial de nuvem: ela não lê
políticas de retenção, IAM nem configuração de imutabilidade do provedor. O que
ela mede, mede de verdade; o que não mede, diz que não mediu
```

**Cada achado é tri-estado, e o `?` não é enfeite.** Sem ele, "o registry não
respondeu sobre a assinatura" viraria "não há assinatura", e as duas frases
levam a decisões opostas. `UNKNOWN` nunca alerta e nunca aprova.

**`TAG_STABLE` é a única evidência *medida* de mutabilidade.** A configuração
de imutabilidade do registry é uma declaração; o histórico de digests (ver
[`base`](#base)) é uma observação. Quando as duas discordam, é a observação que
descreve o que aconteceu de fato.

**`PUBLICLY_READABLE` é relatado e nunca alerta.** "Público" é o estado correto
de uma imagem base oficial e o estado errado de um artefato interno — e a
diferença entre os dois é a intenção de quem publicou, que esta ferramenta não
tem como medir. Transformar o fato em alerta seria afirmar uma intenção;
relatá-lo entrega o fato a quem sabe qual era.

**Assinatura e atestação são procuradas onde o cosign as publica**, nas tags
derivadas do digest (`sha256-<hex>.sig` e `.att`). É convenção do sigstore, não
do OCI — então a ausência significa "não está assinado com cosign nesse
esquema", e não "ninguém assinou nada".

**Exit codes:** `2` quando há achado que pede atenção, `1` quando a referência
não permite apurar nada, `0` caso contrário.

### Exit codes

Os comandos que **avaliam um artefato seu** (`build`, `analyze-dockerfile`)
seguem esta tabela. É o contrato do qual um pipeline pode depender:

| Código | Significado | Quando acontece |
| --- | --- | --- |
| `0` | Sucesso | O comando rodou e nada violou política. |
| `1` | Erro de execução | Dependência ausente, falha de rede, Dockerfile inexistente, `--tag` faltando, JSON inválido em `--build-args`/`--labels`, erro do `docker build`. Nada foi medido, então o resultado não diz nada sobre segurança. |
| `2` | Política violada | O comando rodou bem e o resultado reprova: validação com `errors > 0`, ou `--fail-on` acionado. É o código que um portão de CI deve tratar como "essa imagem não passa". |

A distinção entre `1` e `2` importa: `1` significa "não sei", `2` significa "sei,
e reprovou". Um pipeline que trata os dois como falha genérica não consegue
diferenciar uma indisponibilidade do scanner de uma imagem realmente insegura.

`recommend` **não** cabe nessa tabela, e por um motivo: ele não avalia um
artefato seu, ele escolhe entre candidatos. "Não achei nada no baseline, mas
achei alternativas" é um desfecho que `0`/`1`/`2` não sabem expressar, então
`recommend` usa a escala própria de quatro códigos
[documentada acima](#exit-codes-de-recommend). Os demais comandos
(`search`, `compare`, `analyze`, `advisor`, `sbom`, `export`, `login`, `logout`,
`cache`) usam apenas `0` para sucesso e `1` para falha; `health` usa `1` para
"algum serviço degradado".

---

## Do zero à imagem em produção

Um percurso completo com dois Dockerfiles reais — um escrito às pressas e um
escrito com cuidado — mostrando o que cada comando responde. **Todas as saídas
abaixo são capturas verbatim**, exceto onde marcado.

Os arquivos:

```dockerfile
# demo/servico/Dockerfile — o que sai quando ninguém olhou ainda
FROM node:22
RUN npm ci --omit=dev
CMD ["node","server.js"]
```

```dockerfile
# demo/api/Dockerfile — o mesmo projeto, depois de passar por aqui
ARG PY_DIGEST=sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
FROM python:3.12-alpine@${PY_DIGEST} AS builder
RUN pip install --no-cache-dir .

FROM python:3.12-alpine@${PY_DIGEST}
LABEL org.opencontainers.image.source="https://github.com/org/api" \
      org.opencontainers.image.vendor="Plataforma" \
      security.contact="seguranca@org.com"
COPY --from=builder /app /app
USER 10001
CMD ["python","-m","api"]
```

E a política da organização, versionada junto do código:

```yaml
# demo/.dockerls-policy.yaml
fail_on: high
require_scan: true
require_pinned_bases: true
require_nonroot: true
required_labels:
  - org.opencontainers.image.source
```

### 1. Onde estamos? (`fleet`)

Antes de mexer em qualquer arquivo, o retrato:

```console
$ dockerls fleet demo

demo
2 Dockerfile(s), 1 com todas as bases fixadas, 1 rodando como root

  servico/Dockerfile
    0/1 fixada(s)  root  1 estágio(s)
    x require_pinned_bases  node:22 não está fixada por digest: o que foi testado e o
que vai para produção podem ser bytes diferentes sem nenhuma mudança sua
    x require_nonroot  a política exige execução sem privilégio: a imagem roda como
root
    x required_labels  rótulo obrigatório ausente ou vazio:
org.opencontainers.image.source -- sem ele ninguém sabe a quem recorrer quando esta
imagem aparecer num alerta às três da manhã
  api/Dockerfile
    2/2 fixada(s)  sem privilégio  2 estágio(s)

1 arquivo(s) com violação, 3 no total.
Só as regras decidíveis sem build foram aplicadas; as que dependem de scan continuam
valendo no `dockerls build`.
esta varredura lê Dockerfiles: não constrói imagem nem chama scanner. Ela diz o que os
arquivos declaram, e nada sobre as vulnerabilidades das imagens que eles produzem
$ echo $?
2
```

A fila de trabalho já está ordenada: `servico` primeiro, `api` sem nada a
fazer.

### 2. Que regras estão valendo aqui? (`policy`)

```console
$ dockerls policy demo

demo/.dockerls-policy.yaml

  fail_on  reprova o build a partir desta severidade
    high
  require_scan  exige que um scanner tenha rodado
    True
  require_pinned_bases  exige todo FROM fixado por digest
    True
  require_nonroot  exige execução sem privilégio
    True
  required_labels  rótulos que a imagem precisa carregar
    org.opencontainers.image.source

Conferida em todo `dockerls build` neste contexto. Entre o limiar daqui e o da linha
de comando vence o mais estrito: um arquivo no repositório não pode desligar um portão
que o pipeline pediu.
```

### 3. Fixar a base (`base`)

O `servico` usa uma tag móvel. O comando pergunta ao registry o que ela aponta
**agora** e propõe o digest:

```console
$ dockerls base demo/servico --dry-run

demo/servico/Dockerfile

  linha 1  UNPINNED
    node:22
    tag móvel, sem digest: o que você testou e o que vai para produção podem ser bytes
diferentes sem nenhuma mudança da sua parte
    -> node:22@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a
(linha 1)

1 sem digest

Nada foi escrito (--dry-run).
$ echo $?
2
```

Sem `--dry-run` ele **aplica**. E o `api`, que já foi tratado, confirma que
continua em dia — inclusive com o digest vindo de um `ARG`, que é a forma
correta de escrever isso:

```console
$ dockerls base demo/api --dry-run

demo/api/Dockerfile

  linha 2  PINNED_CURRENT  (estágio builder)
    python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78a
de7dc31
    fixada no digest que a tag aponta hoje

  linha 5  PINNED_CURRENT
    python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78a
de7dc31
    fixada no digest que a tag aponta hoje

Todas as bases estão no digest que a tag aponta hoje.
$ echo $?
0
```

### 4. Preflight antes de gastar um build (`build --production --validate-only`)

Ver a seção [`--production`](#--production-o-conjunto-inteiro-sob-um-nome-só)
acima: o portão reprova em segundos, listando cada regra, sem construir nada.

### 5. Construir, medir e atribuir

```bash
dockerls build -t api:1.0 --production \
  --owner "Plataforma" \
  --security-contact seguranca@org.com \
  --source https://github.com/org/api \
  --provenance ./supply-chain.json \
  demo/api
```

`--production` liga o portão, exige scan, bases fixadas, usuário sem
privilégio, procedência verificada, rótulos de responsabilidade — e a
atribuição dos achados, que responde "consertar o quê?".

### 6. Publicar e assinar

```bash
dockerls build -t api:1.0 --production \
  --registry ghcr.io/org/api --push --sign \
  --owner "Plataforma" --security-contact seguranca@org.com \
  --source https://github.com/org/api \
  --provenance ./supply-chain.json \
  demo/api
```

A assinatura só sai se a procedência fechar, e sempre sobre o digest do
manifesto — nunca sobre a tag.

### 7. Conferir depois (`provenance`, `verify`, `registry-audit`)

```console
$ dockerls verify ghcr.io/org/app@sha256:aaaa

ghcr.io/org/app@sha256:aaaa
  SIGNER_MISSING  cosign não está instalado: isto é ausência de resposta, e não
confirmação de que a imagem não está assinada
$ echo $?
1
```

Essa saída é a regra mais importante do comando em ação: **a ferramenta que
falta não vira veredito sobre a imagem**. Exit `1` é falha do medidor; exit `2`
seria a imagem realmente não assinada.

```console
$ dockerls registry-audit cgr.dev/chainguard/static:latest

cgr.dev/chainguard/static:latest
sha256:14e00fd...

  v RESOLVABLE
      o registry respondeu qual digest esta referência aponta
  x PINNED_REFERENCE
      a referência é uma tag: o que foi testado e o que roda podem ser bytes
      diferentes sem nenhuma mudança sua
  i PUBLICLY_READABLE
      o registry respondeu sem nenhuma credencial: qualquer pessoa da internet
      consegue baixar esta imagem e inspecionar o que há dentro dela. Se isso é
      problema depende de para que ela existe, e essa parte só você sabe
  ? TAG_STABLE
      não há histórico desta tag: o que aconteceu antes da primeira observação
      é desconhecido, não ausente
  v SIGNATURE_PRESENT
      há assinatura cosign publicada para este digest
  v ATTESTATION_PRESENT
      há atestação cosign publicada para este digest
```

### O que cada passo custa

| Passo | Precisa de | Tempo típico |
|---|---|---|
| `fleet`, `policy` | nada | < 1 s |
| `base`, `registry-audit` | rede | 1–5 s |
| `build --validate-only` | nada | < 1 s |
| `build` | daemon Docker | o build + o scan |
| `build --attribute` | daemon + scanner | o build + **dois** scans |
| `verify` | cosign | 1–3 s |

## Por que falha de scan não é segurança

Esta é a seção mais importante do README, e a razão de o projeto existir na
forma em que existe.

Um scanner que não conseguiu rodar produz **zero achados**. Um scanner que
rodou numa imagem impecável produz **zero achados**. Os dois números são
idênticos, e toda ferramenta que os trata igual acaba dizendo, com a mesma
confiança, "nenhuma vulnerabilidade encontrada" nos dois casos — sendo que só
um deles é uma afirmação sobre a imagem.

```
Trivy não instalado           ->  0 achados  ->  "imagem limpa"?     NÃO
Banco de vulnerabilidades off ->  0 achados  ->  "imagem limpa"?     NÃO
Scan expirou aos 300s         ->  0 achados  ->  "imagem limpa"?     NÃO
Registry recusou o pull       ->  0 achados  ->  "imagem limpa"?     NÃO
Scan parcial (alvos ilegíveis)->  0 achados  ->  "imagem limpa"?     NÃO
Scan completo, nada encontrado->  0 achados  ->  "imagem limpa"?     sim
```

No DockerLs, os cinco primeiros produzem `UNVERIFIED`: sem pontuação, sem
nível, sem recomendação, sem "production ready" — e com a causa classificada.
Só o último produz um veredito.

O mesmo princípio se aplica a tudo que a ferramenta não conseguiu determinar:

| Situação | O que **não** se conclui | O que o DockerLs diz |
|---|---|---|
| Catálogo de EOL fora do ar | "a release está em suporte" | `eol_status: unknown`, e isso aparece nos trade-offs |
| CISA KEV inacessível | "não há CVE explorado" | `kev_status: unknown`; a frase afirmativa não é impressa |
| EPSS não retornado | "probabilidade baixa" | `epss_known: false` |
| Config OCI não lida | "não tem shell" | `has_shell: unknown`, e a cobertura de hardening cai |
| Segundo scanner ausente | "o primeiro está certo" | confiança limitada a `MEDIUM`, com a lacuna nomeada |

**O veredito é uma política única.** `ProductionReadiness` é o único lugar que
escreve `production_ready`, e ele bloqueia por: não medido, confiança baixa,
EOL confirmado, achados acima do limite, CRITICAL sem correção, divergência
material entre scanners, ou tier abaixo do piso. Cada bloqueio tem um código
estável (`NOT_MEASURED`, `END_OF_LIFE`, ...) que um pipeline lê sem precisar
interpretar prosa.

```
UNVERIFIED
  Evidence gaps:
    - no completed scan: nothing was measured
  Not production ready
    x the scan did not complete, so nothing about this image was measured
    x the evidence behind this result has a material problem
```

```
HIGH
  Evidence:
    - scanned, pinned to a digest, confirmed in its registry
    - corroborated by a second scanner that agreed
  Production ready
```

Nenhuma dessas saídas pode ser confundida com a outra, e é esse o ponto.

---

## Segurança de rede

Uma referência de imagem é entrada do usuário e carrega um hostname.
`dockerls analyze 169.254.169.254/latest` é uma referência bem formada — e
resolvê-la significa requisitar o endpoint de metadados da nuvem. Num runner
de CI, com um nome vindo de um PR ou de uma variável de ambiente, isso é um
primitivo de SSRF.

O DockerLs decide por **resolução**, não por grafia (`localhost` e um nome
cujo registro A aponta para 127.0.0.1 são a mesma requisição), e exige que
**todos** os endereços de um nome passem — o que fecha também o rebinding.

| Configuração | Padrão | Por quê |
|---|---|---|
| `network_allow_loopback` | `false` | é o caminho para serviços do próprio runner |
| `network_allow_link_local` | `false` | `169.254.0.0/16` é onde vivem as credenciais de instância |
| `network_allow_private_networks` | **`true`** | registry interno é infraestrutura legítima e comum |
| `network_allowed_hosts` | `[]` | allowlist explícita, vence os três acima |

Permitir RFC1918 por padrão é deliberado: bloquear `10.x` fecharia o SSRF e
quebraria todo mundo que roda um registry interno. Quem quer o modo estrito
desliga num ajuste.

---

## Fontes de imagens (multi-source)

O DockerLs procura candidatos em vários catálogos ao mesmo tempo e os coloca
todos no **mesmo pipeline**. Uma imagem de catálogo hardened não ganha por
reputação: ela ganha por vulnerabilidade medida, hardening medido e evidência
verificável -- ou não ganha.

| `--source` | Catálogo | Padrão | Observação |
|---|---|---|---|
| `dockerhub` | Docker Hub | sempre | fonte primária, recebe o `--limit` inteiro |
| `chainguard` | Chainguard free tier (`cgr.dev`) | ligado | o tier gratuito publica só as tags móveis |
| `distroless` | Google Distroless (`gcr.io/distroless`) | ligado | único que data as tags via manifesto GCR |
| `dhi` | Docker Hardened Images (`dhi.io`) | **desligado** | catálogo público, registry **exige credenciais** |
| `all` | todos acima | — | equivalente a `--all-sources` |

```bash
# Só o catálogo DHI
dockerls search node --source dhi

# Todos os catálogos configurados, incluindo os opt-in
dockerls recommend node --all-sources

# Dois catálogos específicos
dockerls recommend node --source dockerhub --source chainguard

# Quais fontes este build conhece
dockerls doctor
```

Adicionar um provedor novo é **um `register()`** na camada de wiring
(`SourceRegistry`): nenhum comando conhece nomes de fornecedor, e nenhum `if
source == ...` cresce um braço novo.

### Docker Hardened Images

O DHI é diferente de todo o resto, e a diferença molda a integração inteira:

* o **catálogo** é público — um repositório GitHub com definições declarativas
  de build (pacotes instalados, conta de execução, datas de EOL);
* o **registry** não é — `dhi.io` recusa pull anônimo.

Ou seja: qualquer um descobre; só quem tem credencial escaneia. Isso não é um
problema a contornar, é exatamente o caso que o resto deste projeto foi feito
para tratar com honestidade:

```
Catálogo DHI (declaração)  ->  Registry (digest)  ->  Scanner  ->  Veredito
        │                            │
        └── metadados                └── sem credencial: 401
            declarados                   -> UNVERIFIED, nunca ranqueado
```

> **DHI metadata != veredito de segurança do DockerLs.**
> Uma definição que declara `run-as: node` é uma *declaração*. Se o config OCI
> da imagem publicada disser `root`, o DockerLs mantém o que mediu e registra a
> contradição como achado — é justamente para isso que a comparação existe.

**Custo.** O catálogo tem ~11 mil arquivos, e clonar ou percorrê-lo por
requisição seria inaceitável. O DockerLs faz **uma** chamada à API do GitHub por
TTL (a árvore recursiva), reduz a um índice compacto, guarda em cache, e depois
busca apenas as definições da imagem consultada — via CDN, que não consome a
cota da API. Medido: 1 requisição a frio sobre 11k blobs (14 ms), **0** a quente.

Sem token, a API do GitHub permite 60 requisições/hora para um cliente anônimo.
`DOCKERLS_GITHUB_TOKEN` (somente leitura, sem escopo) eleva esse teto.

---

## Como a recomendação funciona

O pipeline, na ordem em que roda. Cada etapa existe para reduzir trabalho da
seguinte ou para impedir que um resultado não comprovado chegue à tabela.

```
1. Descobrir       Docker Hub + Chainguard + Distroless + DHI, em paralelo,
   │               conforme --source/--all-sources. Assinaturas cosign,
   │               atestados, SBOMs, apelidos de arquitetura e duplicatas
   │               fixadas por commit são filtrados aqui.
   ▼
2. Fixar digest    Toda tag sem digest é resolvida no registry (um HEAD).
   │               É isso que faz a deduplicação funcionar ENTRE catálogos.
   ▼
3. Deduplicar      Tags que compartilham um digest de manifesto viram uma só
   │               unidade de trabalho -- inclusive vindas de fontes distintas.
   ▼
4. Consultar       Análise em cache, chaveada por digest + regras de ignore
   │  o cache      ativas. Um hit pula direto para a etapa 7.
   ▼
5. Escanear        Só o que sobrou. Trivy como principal, Grype como fallback
   │               por scan. Um scan que falha NÃO vira zero: vira Unverified.
   ▼
6. Enriquecer      EOL (endoflife.date), CISA KEV e EPSS.
   │
   ▼
7. Pontuar         SecurityScore -> SecurityTier -> RemediationScore.
   │
   ▼
8. Verificar       A tag existe mesmo no registry de origem? Isso vem ANTES da
   │  a tag        validação cruzada, para não gastar um scan secundário em quem
   │               vai cair -- e para que um candidato promovido no lugar de um
   │               descartado não entre na tabela sem ter sido checado.
   ▼
9. Validar         Os melhores candidatos são reescaneados com o segundo
   │  cruzado      scanner. Divergência material vira `!disputed`.
   ▼
10. Inspecionar    Só os finalistas: o config OCI de cada um é buscado no
   │               registry (com o blob conferido contra o próprio digest) e
   │               vira Hardening Score + Attack Surface Score. Uma declaração
   │               de catálogo preenche apenas o que a medição não determinou,
   │               e nunca a sobrescreve.
   ▼
11. Confiar        Confidence a partir de: scan concluído, concordância entre
   │               scanners, digest resolvido, tag confirmada, cobertura de
   │               hardening. Falha técnica = UNVERIFIED, e ponto.
   ▼
12. Ranquear       Confiança -> vulnerabilidade medida -> hardening ->
   │               superfície -> remediabilidade. Nessa ordem, sempre.
   ▼
13. Explicar       "Why this image?" e "Trade-offs" acompanham a recomendação.
```

**O portão final.** Antes de qualquer coisa sair do use case, a lista selecionada
é reconferida: nenhuma imagem sem scan concluído e com timestamp pode ser
apresentada como recomendação. Se alguma passasse, isso seria um erro de
programação e a execução falha alto em vez de recomendar algo não medido.

**Por que a imagem venceu.** A tabela responde isso em colunas: `Score` e `Tier`
dizem o veredito, `C/H/M` diz o que foi medido, `Fix` diz quanto disso tem
correção disponível, `Rem` diz o quão remediável é, `Source` diz de que catálogo
veio e `Tag` diz que o registry confirmou a existência dela. O bloco `Details`
abaixo aponta cada linha para o JSON bruto que a sustenta.

**O que ainda não está resolvido** aparece explicitamente: `! Requires review`
lista os níveis que obrigam a uma decisão humana, `! Scanner divergence` lista as
pontuações contestadas, e `! Unverified` lista o que não pôde ser medido.

---

## Algoritmo de pontuação

Cada imagem recebe uma pontuação de segurança de 0 a 100:

```
pontuação = 96 - penalidades + bônus      # limitada a [0, 100]
```

As vulnerabilidades medidas é que determinam a pontuação. Penalidades:

| Condição                                             | Penalidade      |
|------------------------------------------------------|-----------------|
| Vulnerabilidade CRITICAL                              | -20 cada        |
| Vulnerabilidade HIGH                                  | -5 cada         |
| Vulnerabilidade MEDIUM                                | -1 cada         |
| EOL (fim de vida)                                     | -20             |
| Vulnerabilidade com exploit confirmado (CISA KEV)     | -10 por vuln    |
| Vulnerabilidade com EPSS >= 0,5 (alta probabilidade prevista de exploração) | -5 por vuln |
| Idade da imagem                                       | -dias_de_idade/365 (teto de 3) |

Sinais qualitativos funcionam como critério de desempate. Somam **4,0** --
deliberadamente menos que um único achado HIGH, para que nenhuma combinação deles
consiga colocar uma imagem com um HIGH ou CRITICAL a mais acima de uma imagem
mais limpa:

| Condição                                             | Bônus  |
|------------------------------------------------------|--------|
| Imagem oficial                                        | +1     |
| Base mínima (Alpine, Distroless ou imagem de fornecedor hardened -- Chainguard, Wolfi, Bitnami) | +1 |
| Assinada digitalmente                                 | +1     |
| Versão LTS                                            | +0,5   |
| Atualizada nos últimos 30 dias                        | +0,5   |

O bônus de base mínima é aplicado uma única vez, mesmo que a imagem atenda a mais
de um sinal (por exemplo, uma imagem Chainguard baseada em Alpine não recebe +2).

Os bônus *podem* superar um ou dois MEDIUM, e isso é intencional: uma imagem
distroless oficial e assinada com dois medium é uma escolha defensável frente a
uma imagem sem nada de especial e sem nenhum.

A pontuação começa em 96 e não em 100 para que uma imagem limpa e com todos os
bônus chegue exatamente a 100 sem ser truncada. Isso importa: com bônus somando
+19 sobre uma base de 100, qualquer imagem razoavelmente bem qualificada batia no
teto, e uma imagem limpa, uma com 1 HIGH, uma com 2 HIGH e uma com 5 MEDIUM
reportavam todas exatamente `100.0`. Não existe bônus separado de "zero
vulnerabilidades" -- zero achados já significa zero penalidade, e premiar de novo
contava o mesmo fato duas vezes.

A idade só move a pontuação quando a fonte de fato informou uma data de
publicação. Registries que listam apenas nomes de tags (Chainguard e a maioria
dos catálogos OCI) não são penalizados pela idade nem recebem o bônus de
atualidade, para não serem punidos por metadados que o registry não publica.

As consultas a CISA KEV e EPSS são feitas em regime de melhor esforço: se esses
feeds estiverem inacessíveis, o DockerLs pontua sem esse sinal em vez de falhar o
scan. Ambos só são consultados quando o scan tem achados CRITICAL ou HIGH a
verificar.

---

## Níveis de segurança

O nível é derivado da **pontuação**, e a escala cobre toda a faixa 0-100:

| Nível | Pontuação | Leitura                                  | Pronto para produção |
|-------|-----------|------------------------------------------|----------------------|
| A     | 90-100    | pronta para produção                     | Sim*                 |
| B     | 75-89     | pronta para produção                     | Sim*                 |
| C     | 60-74     | condicional: exige revisão humana        | Não                  |
| D     | 40-59     | não pronta para produção                 | Não                  |
| E     | 20-39     | não pronta para produção                 | Não                  |
| F     | 0-19      | não usar                                 | Não                  |

\* Uma imagem em EOL nunca é reportada como pronta para produção, qualquer que
seja o nível.

**Trava por CRITICAL:** uma imagem com CRITICAL **sem correção disponível**
nunca passa de C, por mais alta que a pontuação tenha ficado. É um teto, não um
piso -- uma imagem já em F não sobe para C por causa dele.

Níveis que exigem ação aparecem numa seção `Requires review` na saída do
`recommend`, nomeando cada imagem afetada -- um nível C na tabela não passa
despercebido.

> **Mudança de contrato (não lançado).** A escala anterior era S/A/B/C e vinha
> de contagens de vulnerabilidade, não da pontuação. Ela parava em C, então uma
> imagem com pontuação 0,0, 6 CRITICAL e 170 achados recebia exatamente o mesmo
> nível de uma imagem 36 pontos melhor. O nível **S deixou de existir**; quem
> consome o campo `tier` em JSON/CSV/SARIF precisa ajustar.

---

## Hardening Score

Duas imagens com a mesma contagem de CVEs não são igualmente seguras. Uma pode
rodar como root, com shell, gerenciador de pacotes e compilador dentro; a outra
pode rodar como conta sem privilégio e sem nada disso. Nenhum número de CVE
expressa essa diferença — por isso hardening é uma **dimensão separada**, e não
um termo somado ao score de segurança.

### Os fatores e seus pesos

| Fator | Peso | Ganha crédito quando |
|---|---:|---|
| `non-root` | 25 | a conta padrão de execução não é root |
| `no-shell` | 15 | não há shell na imagem |
| `no-package-manager` | 12 | não há gerenciador de pacotes |
| `minimal-packages` | 12 | poucos pacotes instalados (crédito decai de 50 até 200) |
| `no-setuid` | 10 | não há binários SUID/SGID |
| `no-debug-tools` | 8 | não há compiladores nem utilitários de rede |
| `no-privileged-ports` | 8 | nenhuma porta abaixo de 1024 declarada |
| `explicit-entrypoint` | 5 | há entrypoint fixo, e ele não é um shell |
| `healthcheck` | 5 | a imagem declara um healthcheck |

### A regra que sustenta o número: `unknown` nunca pontua

Um fato de segurança tem **três** estados: verdadeiro, falso e *não
determinado*. Colapsar o terceiro em "falso" é a simplificação mais perigosa
disponível aqui: transformaria "ninguém olhou dentro da imagem" em "esta imagem
não tem shell", que é uma afirmação de hardening que ninguém fez.

Por isso o denominador do score é o peso dos fatores **efetivamente
determinados**, e `coverage` diz quanto do modelo isso representa:

```
Hardening: 100  (coverage 31%)   -> tudo o que deu para checar estava bom,
                                     e deu para checar menos de um terço
Hardening: n/a  (coverage 8%)    -> pouco demais para o número significar algo
```

Abaixo de 25% de cobertura o número não é exibido: aparece `n/a`. Um número
com cara de medição, calculado a partir de dois fatos, é pior que nenhum número.

### De onde vem cada fato

| Origem | O que estabelece | Vale como |
|---|---|---|
| `registry` | config OCI do digest resolvido: usuário, portas, entrypoint, healthcheck, camadas | **medição** |
| `scanner` | pacotes observados dentro da imagem | **medição** |
| `catalog` | definição de build publicada pelo fornecedor (DHI) | *declaração* |

A precedência é absoluta: uma medição nunca é sobrescrita por uma declaração.
Quando as duas discordam, a contradição vira achado em `conflicts` — não é
resolvida em silêncio.

E a assimetria que impede o erro clássico: um pacote de shell declarado **prova**
que há shell; a *ausência* dele não prova nada (uma base derivada de busybox
traz `/bin/sh` sem nunca nomeá-lo como pacote). Presença → `true`; ausência →
`unknown`, nunca `false`.

### Hardening nunca mascara vulnerabilidade

O Hardening Score **não** entra no `SecurityScore` e **não** é somado a ele. No
ranqueamento ele só é consultado depois da posição de vulnerabilidade medida, o
que é a razão estrutural de nunca poder compensá-la:

```
Hardening: 98
Vulnerability Risk: CRITICAL

Veredito final:  NOT PRODUCTION READY
```

Uma imagem perfeitamente configurada e cheia de CVEs exploráveis é uma imagem
perfeitamente configurada e vulnerável.

---

## Attack Surface Score

Distinto de hardening, e distinto de novo de vulnerabilidade. Hardening pergunta
*"isto está configurado defensivamente?"*; superfície de ataque pergunta *"se
houver execução de código aqui dentro, o que já está disponível para usar?"*.

| Item | Peso | Por quê |
|---|---:|---|
| `package-manager` | 25 | permite **instalar** o que faltar |
| `shell` | 20 | permite usar o que já está instalado |
| `debug-tools` | 15 | compiladores e utilitários de rede |
| `setuid` | 15 | caminho direto de escalonamento |
| `root-default` | 15 | multiplica o valor de todos os outros |
| `package-volume` | 10 | código instalado que ninguém auditou |

**A escala é invertida: maior é pior.** É a única métrica deste projeto nessa
direção, e isso é dito em toda renderização — `Surf` na tabela vem rotulado como
*lower is better*.

**Tamanho não é superfície.** Uma imagem de 900 MB feita de um único binário
estaticamente ligado tem superfície menor que uma de 40 MB com busybox, apk e
curl. Bytes não pontuam aqui; *pacotes* pontuam, porque cada pacote é uma
funcionalidade instalada.

Como no hardening, o score é calculado só sobre fatos determinados e reporta
`coverage`.

---

## Confiança (Confidence)

Todo número que esta ferramenta imprime é a saída de uma cadeia: descobrir,
resolver digest, escanear, conferir com um segundo scanner, ler a configuração.
Elos quebram o tempo todo. Sem um sinal de confiança, um score tirado de um
scanner sobre uma tag não resolvida é renderizado igual a um score de dois
scanners concordando sobre um digest fixado — e o leitor não tem como distinguir.

| Nível | Significa |
|---|---|
| `HIGH` | escaneado, fixado por digest, confirmado no registry, corroborado por um segundo scanner que concordou |
| `MEDIUM` | escaneado e consistente, com evidência faltando (só um scanner, sem digest, ou pouca inspeção) |
| `LOW` | escaneado, mas com problema material: scanners divergiram, tag não confirmada, ou referência não fixável |
| `UNVERIFIED` | **não houve scan concluído.** Nada pode ser concluído, em direção nenhuma |

`UNVERIFIED` é um **piso**: nenhum outro sinal tira um candidato dele, e o
ranqueamento nunca o coloca acima de algo que foi medido. Um scanner ausente, um
banco de vulnerabilidades que não baixou, um registry que recusou — todos
produzem `UNVERIFIED`, nunca "0 vulnerabilidades".

---

## Recomendações por digest

Uma tag é um ponteiro móvel: `node:22` de hoje não são os mesmos bytes de
`node:22` da semana que vem. Uma recomendação que nomeia só a tag não pode ser
conferida contra o scan que a produziu.

Por isso toda tag sem digest é resolvida no registry **antes** do scan, e a
recomendação registra:

```
repositório · tag · digest · arquitetura · scanner · timestamp do scan
```

Isso paga por si duas vezes:

* **fixação** — a saída diz `Pin to: node@sha256:...`, que é o que deveria ir no
  seu Dockerfile;
* **deduplicação entre fontes** — tags que compartilham manifesto viram um único
  scan, mesmo vindas de catálogos diferentes. Medido no benchmark: 40 tags / 12
  manifestos = 28 scans evitados ao custo de 40 requisições `HEAD`.

O digest é conferido de verdade: ao ler o config OCI, os bytes recebidos são
hasheados e comparados com o digest que os endereçava. Um registry, proxy ou
cache que devolva conteúdo diferente falha nessa comparação e o config é
descartado.

---

## Ignorando achados conhecidos

Crie um `.dockerls-ignore.yaml` no diretório de onde você executa o `dockerls`
para suprimir CVEs específicas da pontuação e das recomendações:

```yaml
ignores:
  - cve: CVE-2024-0001
    justification: "Não alcançável no nosso uso deste pacote"
    expires: 2026-12-31
```

`expires` é opcional; passada a data, a regra deixa de valer e a CVE volta a
contar. Arquivos de ignore malformados ou ausentes são tratados como "sem regras"
em vez de falhar o scan.

Imagens de nível C nunca são recomendadas para produção.

---

## Modo alternativo

Quando nenhuma imagem atende ao baseline (Critical=0, High=0), o DockerLs não
retorna resultado vazio. Em vez disso, ele:

1. Encontra todas as imagens com Critical = 0
2. Ordena pelo menor número de vulnerabilidades HIGH
3. Avalia a disponibilidade de correções
4. Calcula uma pontuação de correção
5. Apresenta a melhor alternativa com um plano de correção

### Pontuação de correção

| Pontuação | Significado                           |
|-----------|---------------------------------------|
| 100       | Todas as vulns têm correção           |
| 80        | A maioria tem correção                |
| 60        | Cerca de metade tem correção          |
| 40        | Poucas têm correção                   |
| 20        | Nenhuma correção disponível           |

---

## Performance

O custo de uma execução do `recommend` é dominado por duas coisas: chamadas de
rede aos registries e processos de scanner. Praticamente todo o trabalho de
performance aqui é sobre **não fazer** o que já foi feito.

### Duas correções medidas

Duas coisas eram lentas por construção, não por carga. Os números abaixo são de
execuções reais nesta máquina, e a metodologia está junto porque um número de
performance sem ela não é verificável.

**Digestão do contexto de build: 0,84 s → 0,013 s (65x).** O `--provenance`
digere o Dockerfile e o contexto antes de construir. A poda do `.dockerignore`
acontecia *depois* de percorrer a árvore inteira com `rglob("*")`, então `.git`
e `node_modules` eram abertos arquivo por arquivo só para serem descartados.
Num contexto sintético de **52.400 arquivos em que 401 são enviados ao
daemon**, 98% do tempo era gasto lendo entradas que o build nunca veria.

```
antes:  0.938s / 0.840s   (401 arquivos hasheados, 52.400 percorridos)
depois: 0.0139s / 0.0127s / 0.0124s
digest: sha256:6f9c715a713f3...  — idêntico nas duas versões
```

O digest ser **byte a byte o mesmo** é o que torna a mudança segura: a
ordenação final continua sobre os caminhos completos, então um documento de
procedência gerado pela versão antiga continua comparável com um novo.

**Arranque do CLI: 0,58 s → 0,39 s de mediana.** O SQLAlchemy era importado no
arranque de *toda* invocação, por causa de dois imports de módulo em caminhos
que a maioria dos comandos não usa. `dockerls version`, `--help`, `controls` e
`policy` pagavam por um ORM que nunca tocariam.

```
antes   min=0.578s mediana=0.606s   (5 execuções de `dockerls version`)
depois  min=0.390s mediana=0.412s
```

O que **não** foi feito, e por quê: hashear os arquivos do contexto em paralelo.
Medido em 201 MB de conteúdo real, o ganho foi de 0,20 s para 0,13 s com 4
threads — e *pior* com 8 e 16. Um pool de threads, risco de ordenação e
superfície de não-determinismo em troca de 70 ms não se paga num digest que
precisa ser idêntico em qualquer máquina.

### O que reduz trabalho

**Deduplicação por digest.** Tags são apelidos. `node:slim`, `node:trixie-slim` e
`node:current-trixie-slim` apontam para o mesmo manifesto, e escanear as três é
escanear a mesma imagem três vezes. As candidatas são agrupadas pelo digest do
manifesto e escaneadas uma vez só; as irmãs compartilham o resultado, e a
evidência é marcada com `(shared digest)` para que o caminho do arquivo não pareça
pertencer à imagem errada.

**Cache chaveado por digest.** Uma análise é guardada sob o digest, não sob a
tag, com TTL configurável (`DOCKERLS_CACHE_TTL_SECONDS`, padrão 24h). Um rebuild
upstream muda o digest, então o cache nunca serve um veredito sobre bytes que não
existem mais. A chave também carrega as regras de ignore ativas e o estado do
threat intel: uma isenção que venceu deixa de valer imediatamente, em vez de
ficar viva até o TTL expirar.

**SQLite em WAL.** O cache é lido e escrito por um pool de threads. Com o journal
padrão do SQLite um escritor tranca o banco inteiro, os leitores ficam na fila, e
um leitor que desiste é tratado como *miss* — o que significa escanear a imagem de
novo. O cache parava de funcionar exatamente sob carga, e em silêncio. Em WAL
leitores e escritor convivem, inclusive entre dois processos `dockerls`
compartilhando o mesmo arquivo.

**Reuso de conexões HTTP.** Cada cliente mantém um `httpx.AsyncClient` durante
toda a execução, então conexões e handshakes TLS são reaproveitados
(keep-alive) em vez de refeitos a cada requisição.

**Listagens memoizadas com single-flight.** Uma listagem de tags de um registry
hardened é buscada **uma vez por execução**. Antes, cada candidato verificado
refazia a listagem inteira — incluindo o 401 e a busca de token —, e como a
verificação roda em paralelo, um cache simples ainda deixaria todas passarem
juntas; por isso a primeira chamada é serializada por repositório.

**Isolamento do cache do Trivy.** O Trivy tranca com exclusividade o diretório de
cache dele. O banco de vulnerabilidades é baixado uma vez no início e vinculado
por *hard link* no diretório de cada worker, de modo que scans paralelos não
disputam a mesma trava. Sem hard link, o pool degrada para um cache único e
serializa — mais lento, nunca em disputa.

**Banco do Grype atualizado uma vez.** O Grype checa atualização a cada
invocação, o que é uma ida à rede por imagem. A validação cruzada roda
`grype db update` uma vez para o lote e depois escaneia com
`GRYPE_DB_AUTO_UPDATE=false`.

**Validação cruzada só onde importa.** Apenas os melhores candidatos passam pelo
segundo scanner, e só depois da verificação de tag — não faz sentido gastar um
scan secundário num candidato que vai cair.

### Medições

Os números abaixo foram medidos neste repositório e são reproduzíveis. Nenhum
deles é estimativa.

**Descoberta e verificação de tags** (`python benchmarks/bench_discovery.py`).
Cenário: listar as tags de um repositório hardened e depois verificar os dez
candidatos sobreviventes, contra um registry simulado que se comporta como os
reais (desafio 401, busca de token, dados), com 20 ms de latência por requisição.

| Métrica | Antes | Depois | Melhoria |
| --- | ---: | ---: | ---: |
| Requisições HTTP | 33 | 3 | −91% |
| Tempo de parede | 0,128 s | 0,064 s | −50% |

**Cache sob concorrência.** 200 escritas + 200 leituras simultâneas, que é o
padrão de acesso de `recommend --workers 10`:

| Métrica | Antes (journal padrão) | Depois (WAL) | Melhoria |
| --- | ---: | ---: | ---: |
| Tempo de parede | ~0,72 s | ~0,50 s | −31% |

**O que não foi medido, e por quê.** Os tempos ponta a ponta de `recommend`,
`analyze` e `advisor` contra imagens reais dependem do Trivy e do Grype, que não
puderam ser instalados no ambiente onde estas medições foram feitas (o download
dos binários é bloqueado). O tempo de scan e o de validação cruzada portanto
**não têm número aqui** — preferimos declarar a lacuna a publicar uma estimativa.

### Onde olhar quando estiver lento

A segunda linha do resumo do `recommend` é o começo do diagnóstico:

```
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
```

- `scans` alto com `cache` em zero → o cache não está sendo aproveitado; confira
  `dockerls cache stats` e se `--no-cache` não está ligado.
- `deduped` em zero com muitas tags → a fonte não reportou digests, então cada
  tag foi tratada como uma imagem distinta.
- `cross-validated` alto pesa no tempo total; `--no-cross-validate` desliga, ao
  custo de perder a confirmação por um segundo scanner.

Os mesmos números saem em `--format json`, sob `metrics`.

---

## Evidências e reprodutibilidade

Uma pontuação que não pode ser conferida é uma opinião. Toda execução deixa o
material que permite refazer a conta.

**JSON bruto de cada scan.** A saída completa do scanner é gravada em
`$XDG_STATE_HOME/dockerls/scans/...` ou, por padrão, em
`~/.local/state/dockerls/scans/...`. O bloco `Details` liga cada imagem aos
arquivos que sustentam a nota dela — um por scanner que a mediu. Defina
`DOCKERLS_EVIDENCE_DIR` quando quiser guardar esses artefatos junto do projeto.

**Manifesto por execução.** Cada execução grava um manifesto ligando cada
pontuação exibida à sua evidência, com digest, contagens por severidade, status
do scan, divergência entre scanners e estado da verificação de tag.

**Digest, não tag.** O cache e a deduplicação são chaveados pelo digest do
manifesto. Uma evidência sempre corresponde aos bytes que a produziram.

**Divergência é mostrada, não resolvida.** Quando os dois scanners discordam de
forma material na contagem de CRITICAL/HIGH, a pontuação aparece como
`!disputed` em vez de um número, com a discrepância logo abaixo. Escolher um dos
dois números seria apresentar uma confiança que o dado não sustenta.

**Nada de versão inventada.** As versões corrigidas dos planos de remediação vêm
do campo `FixedVersion` do scanner. Um achado sem correção publicada é listado
como pendência, não convertido num `upgrade` genérico.

**O que não é reprodutível, e é honesto dizer.** Bancos de vulnerabilidades mudam
todo dia: a mesma imagem escaneada com uma semana de diferença pode dar
contagens diferentes sem que nada tenha mudado na imagem. É por isso que a
evidência guarda o timestamp do scan, e não apenas o resultado.

---

## Arquitetura

O DockerLs segue Clean Architecture, com separação clara de camadas:

```
dockerls/
  cli/              # Comandos Typer e formatação de saída
  domain/
    entities/        # DockerImage, Vulnerability, ScanResult, Recommendation,
                     #   HardeningFacts (evidência), DeclaredImageMetadata (declaração)
    value_objects/   # SecurityScore, SecurityTier, RemediationScore,
                     #   HardeningScore, AttackSurfaceScore, Confidence, Tristate
    interfaces/      # Interfaces abstratas (portas)
  application/
    use_cases/       # SearchImages, RecommendImages, AnalyzeImage, CompareImages
    services/        # ScannerFactory, CrossValidator, CompositeImageRepository,
                     #   SourceRegistry (catálogos), HardeningAnalyzer (evidência),
                     #   verdict (ranking + explicação), migration (trade-offs)
    dto/             # AnalysisResult, ComparisonResult
  infrastructure/
    config/          # Settings (Pydantic)
    database/        # Modelos SQLAlchemy
    logging/         # Configuração do Loguru com mascaramento de segredos
    templates/       # Dockerfiles hardened servidos por --hardened/--base
    dockerfile_validator.py  # Regras OWASP e provedor de templates
    evidence.py      # Persistência do JSON bruto dos scans
  integrations/
    dockerhub/       # Cliente da API do Docker Hub
    trivy/           # Integração com o scanner Trivy
    grype/           # Integração com o scanner Grype (alternativa)
    registry/        # Catálogos hardened via OCI (Chainguard, Distroless) e
                     #   RegistryInspector (digest + config OCI verificado)
    dhi/             # Catálogo Docker Hardened Images (índice, definições, provider)
    endoflife/       # Verificador endoflife.date
    threat_intel/    # CISA KEV e EPSS
  cache/             # Implementação de cache em SQLite
  exporters/         # Exportadores JSON, CSV, HTML, Markdown, SARIF
  utils/             # Validação de entrada, autenticação, retry, rate limit,
                     #   circuit breaker e parsing YAML com limites explícitos
engine/              # Orquestrador de scans em Go (opcional, ver abaixo)
```

**A engine em Go (`engine/`)** dispara Trivy/Grype em paralelo sobre um lote
de imagens e devolve tudo num único processo, em vez de um `subprocess` por
scan. É opcional: `pip install dockerls` não instala o binário, e o
pipeline em Python continua sendo o caminho completo — qualquer problema do
lado da engine (binário ausente, timeout, saída ilegível) faz a CLI voltar
sozinha para o caminho Python, sem falhar o comando. Detalhes, protocolo e
como compilar estão em [`engine/README.md`](../engine/README.md).

Os dados fluem para dentro: CLI -> Casos de uso -> Domínio. As integrações
externas implementam interfaces do domínio e são injetadas pelo construtor de
dependências.

**Adicionar uma fonte de imagens** não toca em nenhum comando: implemente
`ImageRepositoryInterface` em `integrations/`, e registre um `SourceSpec` em
`build_source_registry()`. O nome vira automaticamente um valor válido de
`--source`, aparece no `doctor` e entra no `--all-sources`. O domínio não importa
`httpx`, nem SDK de registry, nem scanner.

---

## Configuração

As configurações são resolvidas nesta ordem de prioridade: variáveis de ambiente,
depois `~/.config/dockerls/config.toml` (ou
`$XDG_CONFIG_HOME/dockerls/config.toml`), depois os padrões embutidos.

### Variáveis de ambiente

| Variável                        | Descrição                                  |
|---------------------------------|--------------------------------------------|
| DOCKERHUB_USERNAME              | Usuário do Docker Hub                      |
| DOCKERHUB_TOKEN                 | Token de acesso do Docker Hub              |
| XDG_CACHE_HOME                  | Sobrescreve o diretório de cache           |
| XDG_CONFIG_HOME                 | Sobrescreve o diretório do arquivo de config |
| DOCKERLS_ENABLE_THREAT_INTEL    | `false` desativa as consultas a CISA KEV / EPSS |
| DOCKERLS_DISABLE_THREAT_INTEL   | Idem, forma legada (mantida por compatibilidade) |
| DOCKERLS_GITHUB_TOKEN           | Token só-leitura para elevar o limite de 60 req/h da API do GitHub (catálogo DHI) |
| DOCKERLS_<NOME_DA_CONFIG>       | Sobrescreve qualquer outra configuração abaixo (ex.: `DOCKERLS_MAX_TAGS=200`) |

### Arquivo de configuração

```toml
# ~/.config/dockerls/config.toml
max_tags = 200
workers = 20
log_level = "DEBUG"
```

As chaves correspondem aos nomes das configurações da tabela abaixo (snake_case,
sem prefixo).

Toda flag de limite (`--max-critical`, `--max-high`, `--max-medium`,
`--workers`, `--limit`) recorre ao valor configurado quando omitida, então tanto
`DOCKERLS_MAX_MEDIUM=10` quanto uma entrada no `config.toml` fazem efeito. Uma
flag explícita sempre vence a configuração.

### Limites padrão

| Parâmetro     | Padrão  |
|---------------|---------|
| max-critical  | 0       |
| max-high      | 0       |
| max-medium    | 5       |
| workers       | automático (ver abaixo) |
| limit (tags descobertas) | 100 |
| scan_budget (tags medidas) | 25 |
| TTL do cache  | 24h     |

### SBOM que existe para quem baixa a imagem

Sem `--attest`, o SBOM é um arquivo no seu disco: útil, e invisível para
quem faz `docker pull`. É a atestação que o `registry-audit` procura — e
que, até agora, ele nunca encontrava para imagens construídas por esta
própria ferramenta.

```bash
dockerls sbom ghcr.io/org/app@sha256:abc... --attest
```

Assina o SBOM com cosign e o anexa ao manifesto, com o tipo de predicado
certo (`cyclonedx` ou `spdxjson`) — sem ele o documento é anexado como
predicado genérico e quem consome não sabe que é um SBOM, o que é quase o
mesmo que não ter anexado.

**Só por digest.** Uma tag pode mover, e uma atestação que sobrevive à
mudança segue descrevendo uma imagem que ela nunca viu. A recusa acontece
antes da geração: descobrir isso depois de escanear a imagem inteira
desperdiçaria o trabalho.

Cosign ausente não é falha da imagem: o SBOM foi gerado e continua válido,
e o que não aconteceu foi a publicação — a saída diz exatamente isso.

### O `doctor` confere que o scanner mede, não só que ele existe

Um Trivy com base de vulnerabilidades de três semanas produz um scan
**limpo, verde e sem erro nenhum** que simplesmente não conhece os CVEs do
último mês. É a falha de medição mais silenciosa que existe aqui: nada no
relatório indica que a resposta está velha.

`dockerls doctor` passou a ler a data da base de cada scanner instalado:

| estado | idade | o que significa |
|---|---|---|
| Fresh | até 24h | cobre o que se publicou recentemente |
| Aging | 1 a 3 dias | ainda mede, e já perdeu dias de publicação |
| Stale | mais de 3 dias | um scan contra ela volta limpo para tudo que saiu desde |
| Unknown | — | **não foi possível ler a data**, o que não é o mesmo que estar atualizada |

Por padrão isso é um aviso, e não muda o código de saída: `doctor` sempre
significou "os componentes estão presentes", e mudar esse contrato em
silêncio quebraria pipelines. Para transformar em portão:

```bash
dockerls doctor --require-fresh-db
```

`Unknown` reprova junto com `Stale` sob essa flag, pela mesma razão de
sempre: a pergunta é "dá para confiar na atualidade desta base", e "não
sei" não é sim.

### Isenções portáveis: OpenVEX

O `.dockerls-ignore.yaml` já é um documento VEX em tudo menos no formato --
tem o CVE, a justificativa e o prazo. `dockerls vex` o escreve num formato
que o resto do mundo lê, para que uma exceção decidida uma vez valha no
pipeline inteiro em vez de só dentro desta ferramenta (Trivy e Grype
consomem OpenVEX nativamente).

```bash
dockerls vex ghcr.io/org/app:1.2.3 --author "Plataforma <sec@org.example>"
```

**O que ele não faz é transformar risco aceito em alegação técnica.** VEX
tem quatro estados, e o que quase toda implementação emite para uma isenção
é `not_affected` — mas `not_affected` é uma afirmação *técnica* (o código
vulnerável não está presente, ou não é alcançável, ou já está mitigado), e
o padrão exige dizer qual das cinco razões é.

"A equipe aceitou o risco até o Q3" não é nenhuma das cinco. Então:

| a regra diz | o documento diz |
|---|---|
| justificativa em texto livre | `affected`, com o texto no `action_statement` |
| `vex_justification: vulnerable_code_not_present` | `not_affected`, com a justificativa do padrão |

O consumidor vê a exceção e vê o motivo, sem receber uma alegação que
ninguém fez — e VEX existe justamente para ser acreditado.

O prazo entra no `action_statement`, porque VEX não tem campo para
expiração e uma isenção sem prazo visível é uma isenção que ninguém revisa.
Regras vencidas não entram no documento: ressuscitá-las diria ao mundo
inteiro que continuam valendo.

`--author` é obrigatório. Uma afirmação VEX é alguém afirmando alguma
coisa; sem autor ela não responsabiliza ninguém.

### O portão olha exploração, não só severidade

`--fail-on` aceita três tipos de portão, e eles respondem perguntas
diferentes:

| portão | pergunta |
|---|---|
| `critical` / `high` / `medium` / `low` | qual a severidade que o vendor atribuiu? |
| `kev` | está sendo explorado no mundo real? (catálogo CISA KEV) |
| `epss>=N` | qual a probabilidade de exploração nos próximos 30 dias? (FIRST EPSS) |

Podem ser combinados por vírgula, e **todos** precisam passar:

```bash
dockerls build . -t app:1.0 --fail-on critical,kev
dockerls build . -t app:1.0 --fail-on epss>=0.5
```

O caso que motivou isto: um CVE **sendo explorado hoje**, classificado
MEDIUM pelo vendor da distro, atravessava um `--fail-on high` sem um pio. E
o inverso — um CRITICAL teórico, sem exploit publicado e com EPSS de
0,0003 — reprovava o build. A ferramenta já media a diferença e não a usava
onde ela decide alguma coisa.

**Um portão que não pôde ser avaliado não passa.** Se você pediu `kev` e o
catálogo não respondeu, o build para com `Gate not evaluated` — e a
mensagem diz que aquilo é ausência de medição, não um achado. Aprovar ali
gastaria falta de consulta como tranquilidade, e desligaria um portão de
segurança em silêncio numa oscilação de rede.

A rede só é tocada quando algum portão a exige: `--fail-on high` não sai
para buscar o catálogo KEV.

O `.dockerls-policy.yaml` aceita os mesmos valores em `fail_on`. Quando os
dois lados pedem portões de tipos diferentes, eles **somam** — entre
`critical` e `kev` não dá para dizer qual é mais estrito, e escolher um
descartaria o outro em silêncio.

### Descobrir não é medir

`--limit` (config `max_tags`) governa quantas tags a **busca** traz; `--budget`
(config `scan_budget`) governa quantas delas são de fato **escaneadas**. São
coisas diferentes: descobrir 100 tags custa uma chamada HTTP, medir as 100
custa dois a quatro minutos de Trivy — para exibir cinco.

O corte não esconde nada. As tags não medidas voltam no resultado, no bloco
`Not Measured` e no campo `deferred` do JSON, cada uma com o motivo — quase
sempre "existe uma tag mais nova da mesma linha". **Uma tag não medida não é
uma tag pior**: nada foi medido nela, então nada está sendo afirmado sobre ela.
É a mesma disciplina que separa `unverified` (o scan falhou) de um scan limpo.

A regra de seleção só usa fatos que a listagem já trouxe — sem rede, sem
scanner: majors diferentes nunca competem entre si (`20-alpine` continua
sendo resposta legítima ao lado de `22-alpine`), variantes diferentes nunca
competem, e um apelido móvel (`22-alpine`) nunca é colapsado num patch fixo
(`22.14-alpine`) porque são perguntas diferentes. Havendo folga no orçamento,
nada é cortado.

```bash
dockerls recommend node                # 100 descobertas, 25 medidas
dockerls recommend node --budget 50    # mede mais
dockerls recommend node --budget 0     # mede todas (comportamento anterior)
```

### Uso de recursos

Cada worker segura um **processo de scanner**, não uma corrotina: o Trivy
carrega uma base de centenas de MB, desempacota camadas e casa pacotes,
ocupando um núcleo inteiro enquanto isso. Dez deles num runner de dois núcleos
não terminam dez vezes mais rápido — terminam mais devagar e podem levar o job
a ser morto por falta de memória.

Por isso o padrão é `0`, que significa **"dimensione para esta máquina"**:

```
workers = min(CPUs utilizáveis, memória disponível / 768 MB), limitado a 16
```

"CPUs utilizáveis" é a cota real, não o que o host tem. Isso importa porque
esta ferramenta analisa containers e costuma rodar dentro de um, onde
`os.cpu_count()` reporta os núcleos da máquina inteira enquanto o cgroup
permite meio núcleo. São lidos: cota de cgroup (v2 e v1), máscara de afinidade
e `MemAvailable`.

Um valor explícito continua valendo — `--workers 20` entrega 20, com um aviso
no log dizendo o que a máquina comporta. Quem mede o próprio runner tem o
direito de sobrecarregá-lo de propósito; o que não pode é isso acontecer em
silêncio.

```bash
dockerls recommend node              # dimensiona sozinho
dockerls recommend node --workers 2  # explícito, para runner apertado
dockerls recommend node --workers 0  # explicitamente automático
```

### Rede e política de acesso

| Configuração                      | Padrão | O que faz |
|-----------------------------------|--------|-----------|
| `network_allow_private_networks`  | `true`  | Permite registries em faixas RFC1918 |
| `network_allow_loopback`          | `false` | Permite referências que resolvem para loopback |
| `network_allow_link_local`        | `false` | Permite link-local, incluindo o endpoint de metadados |
| `network_allowed_hosts`           | `[]`    | Hosts liberados independentemente de onde resolvem |

### Motor multi-source

| Configuração              | Padrão | O que faz |
|---------------------------|--------|-----------|
| `include_hardened_sources` | `true`  | Consulta Chainguard e Distroless junto do Docker Hub |
| `include_dhi_source`       | `false` | Consulta o catálogo Docker Hardened Images (opt-in: `dhi.io` exige credencial para escanear) |
| `dhi_catalog_ttl_seconds`  | `21600` | Validade do índice do catálogo DHI (6h = 1 requisição de API por janela) |
| `dhi_definition_limit`     | `12`    | Definições lidas por consulta DHI (cada uma é uma requisição de CDN) |
| `github_token`             | `""`    | Eleva o teto anônimo da API do GitHub |
| `resolve_digests`          | `true`  | Fixa toda tag no digest antes do scan (é o que faz a deduplicação funcionar entre fontes) |
| `inspect_image_config`     | `true`  | Busca o config OCI dos finalistas para medir hardening em vez de confiar em declaração |
| `hardened_tag_limit`       | `10`    | Tags trazidas por fonte não primária |

---

## Uso com Docker

### Build

```bash
docker build -t dockerls:latest .
```

### Execução segura

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  dockerls:latest analyze-dockerfile /work
```

### A imagem não embute um scanner

Isto é uma limitação declarada, não um detalhe. O binário do Trivy era copiado
para o stage final e as dependências Go dele respondiam por ~330 das 339
vulnerabilidades que o Docker Scout reportava contra a imagem — nenhuma delas do
código Python deste projeto. Ele saiu.

**O que funciona dentro do container:** `analyze-dockerfile`, `controls`,
`search`, `version`, `cache`, `login`.

**O que não funciona:** `recommend`, `analyze`, `compare`, `advisor`,
`alternatives`, `sbom` e o passo de scan do `build`. Sem `trivy` ou `grype` no
PATH, o `ScannerFactory` devolve `SCANNER_MISSING` — que, pela política deste
projeto, é reportado como **não verificado** e nunca como "limpo". A ausência de
medição não é um resultado de segurança.

Para escanear, rode o `dockerls` num host que tenha trivy ou grype instalado
(o modo de uso normal fora de container), ou monte um scanner no PATH do
container. O CI não é afetado: ele escaneia com a `aquasecurity/trivy-action`,
que nunca dependeu do binário embutido.

### Docker Compose

```bash
docker compose run dockerls analyze-dockerfile /work
```

A imagem parte de `python:3.12-alpine`, e a escolha foi medida: sobre a base
Debian slim sobravam seis CRITICAL **sem versão de correção publicada**, quatro
delas no `perl-base` — um pacote que o DockerLs nunca invoca e que o Debian
marca como `Essential: yes`, então nem `apt-get purge` o remove. Trocar a base
resolve; silenciar as CVEs num arquivo de ignore só esconderia. Numa ferramenta
que se recusa a apresentar como segura uma imagem que não conseguiu medir,
fazer o próprio portão passar por supressão seria o pior precedente possível.

Fora isso, a imagem segue as boas práticas de segurança Docker da OWASP: build
multi-estágio, base fixada por digest de manifest-list, `apk upgrade` no stage
final, usuário não-root, rótulos `org.opencontainers.image.*` no manifesto
final, suporte a sistema de arquivos somente leitura e todas as capabilities
removidas.

---

## Desenvolvimento

```bash
# Instalar dependências de desenvolvimento
make dev

# Rodar o linter
make lint

# Rodar o verificador de tipos
make type-check

# Rodar os testes; falha cedo com uma mensagem clara se os extras dev não estiverem instalados
make test

# Rodar a auditoria completa (lint + tipos + testes + segurança)
make audit

# Formatar o código
make format
```

---

## CI/CD

Workflows do GitHub Actions incluídos:

- **CI**: linting com Ruff, verificação de tipos com Mypy, Pytest em Python
  3.11/3.12/3.13
- **Security**: SAST com Bandit, checagem de dependências com pip-audit, scan de
  contêiner com Trivy
- **CodeQL**: code scanning do GitHub
- **Release**: publicação automatizada no PyPI ao enviar uma tag, com atestado
  nativo de proveniência SLSA do GitHub e artefatos assinados via Sigstore
  anexados ao release
- **Dependabot**: atualizações semanais de dependências

Os workflows disparam em qualquer pull request (sem filtro de branch de destino)
e em pushes fora das branches do Dependabot. Um grupo de concorrência junta as
execuções duplicadas de push e pull request e cancela as superadas.

---

## Modelo de segurança

### Modelo de ameaças

O DockerLs opera como ferramenta consultiva somente leitura. Ele:
- Lê da API do Docker Hub (dados públicos)
- Executa Trivy/Grype como subprocessos locais
- Consulta as APIs endoflife.date, CISA KEV e EPSS
- Faz cache dos resultados localmente em SQLite

Ele não:
- Baixa nem executa imagens Docker
- Modifica qualquer configuração do Docker
- Acessa registries privados sem credenciais explícitas
- Transmite dados do usuário a terceiros

### Que dados saem da sua máquina

| Destino | O que é enviado | Quando |
| --- | --- | --- |
| `hub.docker.com` | Nome do repositório e da tag consultados | `search`, `recommend`, `export`, verificação de tag |
| `hub.docker.com` | Usuário e token, num POST de login | Só em `dockerls login` / com `DOCKERHUB_*` definidos |
| `cgr.dev`, `gcr.io` | Nome do repositório consultado | Descoberta em fontes hardened |
| `endoflife.date` | Nome do produto e versão (`node`, `22`) | Checagem de EOL |
| `cisa.gov` (KEV) | Nada: o feed inteiro é baixado | Enriquecimento de threat intel |
| `api.first.org` (EPSS) | **Os IDs de CVE encontrados na imagem** | Enriquecimento de threat intel |
| Trivy / Grype | A referência da imagem, como argumento | Cada scan |

O único item dessa lista que descreve *a sua* imagem é a consulta ao EPSS, que
envia IDs de CVE de imagens públicas. Desligue com
`DOCKERLS_ENABLE_THREAT_INTEL=false` se mesmo isso não for aceitável.

**Nunca é enviado:** conteúdo de imagem, camadas, SBOMs, seu Dockerfile, o
código do seu projeto, nomes de host internos ou credenciais de registry
(exceto o login explícito no Docker Hub).

### Como os subprocessos são executados

- Sempre com **lista de argumentos**, nunca `shell=True` — não há string de
  comando para escapar em lugar nenhum.
- `argv[0]` é resolvido para **caminho absoluto** antes da execução, então um
  diretório gravável no início do `$PATH` não decide qual binário roda. Sequestrar
  o `$PATH` de um scanner de segurança é sequestrar o veredito de um pipeline.
- Referências de imagem passam por validação que rejeita, entre outras coisas,
  qualquer componente começando com `-`. Sem isso, uma referência vinda de uma
  variável de CI como `--ignore-unfixed` chegaria ao `trivy image` como *flag*, e
  não como alvo — controle sobre como (ou se) o scan roda.
- Todo processo é **morto e coletado** no timeout ou no cancelamento. Um scanner
  que sobrevive ao seu timeout continua segurando a trava exclusiva do cache do
  Trivy e atrapalha a execução seguinte.

### Onde ficam as credenciais

No keyring do sistema (`dockerls login`), ou nas variáveis `DOCKERHUB_USERNAME` /
`DOCKERHUB_TOKEN`. Nunca em arquivo de configuração, nunca no cache, nunca nos
arquivos de evidência. Um backend de keyring indisponível degrada para acesso
anônimo — nunca aborta o comando.

### Como os logs mascaram segredos

O mascaramento roda em **todos** os sinks de log e cobre as formas em que uma
credencial costuma aparecer: pares chave/valor em JSON e em `repr` de dicionário,
pares sem aspas (`token=...`), esquemas de autorização (`Bearer`, `Basic`),
credenciais embutidas em URL (`https://user:senha@host`), `curl -u`, corpos
multipart, e formatos autoidentificáveis mesmo sem chave que os introduza (PAT do
Docker, token do GitHub, JWT, chave AWS, token do Slack). O mascaramento é
deliberadamente agressivo: mascarar demais uma linha inócua custa pouco, vazar um
token para um arquivo de log não.

### Operações somente leitura

Tudo, exceto três coisas explícitas: `dockerls build` (roda `docker build`),
`dockerls build --push` (publica, e só depois dos portões), e a escrita do
`Dockerfile.hardened` com `--hardened`/`--base` (que **não** acontece sob
`--validate-only` — um dry-run não tem efeito colateral). O DockerLs não baixa
nem executa imagens; o Trivy e o Grype cuidam disso internamente para escanear.

### Limitações conhecidas

- **A ferramenta confia nos scanners.** Se o Trivy e o Grype não conhecem uma
  vulnerabilidade, o DockerLs também não. A validação cruzada reduz o ponto cego
  de um scanner só, não o elimina.
- **Não há verificação de assinatura.** `is_signed` vem de metadados, não de uma
  verificação cosign feita aqui.
- **Bancos de vulnerabilidades mudam diariamente.** Duas execuções da mesma
  imagem em dias diferentes podem discordar sem que a imagem tenha mudado.
- **Um digest só é tão confiável quanto o registry.** A deduplicação e o cache
  confiam no digest que o registry reporta.

### Alinhamento com a OWASP

- Validação de entrada em todos os nomes de imagem (prevenção de injeção)
- Sem `shell=True` nas chamadas de subprocesso (prevenção de injeção de comando)
- Mascaramento de credenciais em toda saída de log
- Detecção de path traversal em nomes de imagem
- Armazenamento seguro de credenciais via keyring do sistema
- Scan de dependências em CI (pip-audit, Dependabot)
- Scan SAST (Bandit, CodeQL)
- Scan de contêiner (Trivy)

---

## Solução de problemas

### "No scanner available"

Instale o Trivy:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Ou instale o Grype como alternativa:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### "Rate limited by Docker Hub"

Autentique-se para aumentar os limites de requisição:
```bash
dockerls login
```

### Scans lentos

Comece pelos números da execução, não pelos parâmetros. A segunda linha do
resumo diz onde o tempo foi:

```
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
```

- Reduza a quantidade de tags: `--limit 20`
- Pule a validação cruzada: `--no-cross-validate`
- Confira o cache: `dockerls cache stats`
- Aumente os workers: `--workers 20` — mas veja abaixo

**Aumentar `--workers` nem sempre acelera.** Cada worker é um processo de scanner
com o próprio diretório de cache; passado o ponto em que a máquina fica sem I/O
ou CPU, mais workers só adicionam disputa. O limite é 50, e valores altos também
pressionam os limites de requisição do Docker Hub. Se `scans` já está baixo por
causa do cache e da deduplicação, workers não é a variável que importa.

### "Unverified (technical error)" em todas as tags

Isso não é um veredito sobre as imagens — é uma falha da execução, e o exit code
é `1`. Olhe a linha `Causes:` do bloco: ela agrupa as falhas por causa
classificada, então noventa tags falhando dizem *um* problema, não noventa.

| Causa | O que significa | O que fazer |
| --- | --- | --- |
| `SCANNER_MISSING` | Nenhum scanner no PATH | `dockerls doctor` |
| `DB_INIT_FAILED` | Banco de vulnerabilidades não ficou pronto | Libere acesso a `ghcr.io` e repita |
| `TIMEOUT` | Scans estouraram o tempo | Aumente `DOCKERLS_SCANNER_TIMEOUT` ou reduza `--workers` |
| `RATE_LIMITED` | Registry limitou as requisições | `dockerls login`, ou repita mais tarde |
| `AUTH_REQUIRED` | O registry exige credencial | `dockerls login` |
| `NOT_FOUND` | As tags não puderam ser baixadas | Confira o nome da imagem |

### Ruído do keyring antes da saída

Se você via algo assim antes dos resultados:

```
ModuleNotFoundError: No module named '_cffi_backend'
thread '<unnamed>' panicked at pyo3-0.20.2/src/err/mod.rs:788:5
```

era um backend de keyring quebrado — comum em container e em runner de CI. A
falha sempre foi tratada (a execução segue anonimamente), mas o texto vinha do
runtime Rust direto no descritor 2, abaixo do ponto onde o Python pode capturar.
Isso está silenciado desde a versão atual; a causa continua registrada no arquivo
de log.

### Problemas de cache

```bash
dockerls cache stats     # veja o que está guardado antes de apagar
dockerls cache cleanup   # remove só o que já venceu
dockerls cache clear     # esvazia tudo
```

Uma base de cache corrompida ou ilegível é tratada como *miss*, nunca como falha
de scan: no pior caso a imagem é escaneada de novo.

---

## Perguntas frequentes

**P: O DockerLs baixa imagens Docker?**
R: Não. O Trivy/Grype cuidam do download da imagem internamente, para escanear.
O DockerLs só consulta metadados no Docker Hub.

**P: Dá para usar com registries privados?**
R: `analyze` e `compare` aceitam qualquer referência válida, inclusive registries
privados com porta (`registry.internal:5000/team/app:tag`), hosts comuns de
registry privado (GHCR, Harbor, ECR, GAR) e referências por digest
(`node@sha256:...`). O scan continua passando pelo Trivy/Grype, então autentique
no registry do jeito que você normalmente faria para essas ferramentas (por
exemplo, `TRIVY_USERNAME`/`TRIVY_PASSWORD`, ou um `~/.docker/config.json` já
autenticado) -- o DockerLs não gerencia credenciais de registry por conta
própria. `search` e `recommend` continuam consultando a API de listagem de tags
do Docker Hub, então ficam limitados a repositórios do Docker Hub (mais os
catálogos hardened do Chainguard e Distroless).

**P: Quão precisa é a pontuação?**
R: A pontuação combina contagem de vulnerabilidades, idade da imagem e tipo de
base. É uma heurística -- sempre revise a lista detalhada de CVEs para decisões
críticas.

**P: E se o Trivy e o Grype estiverem ambos indisponíveis?**
R: O DockerLs reporta o problema. Rode `dockerls doctor` para checar as
dependências.

---

## Licença

Licença MIT. Veja [LICENSE](LICENSE).
