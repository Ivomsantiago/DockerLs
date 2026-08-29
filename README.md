# DockerLs

[![CI](https://github.com/Ivomsantiago/DockerLs/actions/workflows/ci.yml/badge.svg)](https://github.com/Ivomsantiago/DockerLs/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Ivomsantiago/DockerLs/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ivomsantiago/DockerLs/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**DockerLs ajuda você a escolher a imagem Docker mais segura para produção —
e a provar por quê.**

Em vez de você pesquisar tag por tag no Docker Hub e adivinhar qual é mais
confiável, o DockerLs escaneia várias de uma vez (Trivy e/ou Grype), compara
com alternativas mais seguras (Chainguard, Distroless, Docker Hardened
Images) e recomenda uma — com o motivo escrito, não só um número.

```bash
dockerls recommend node
```

isso já basta para ver a ideia funcionando. O resto deste documento existe
pra te dar o resto do contexto: o que instalar, todos os comandos, e por que
as respostas dele são diferentes das de um scanner comum.

---

## Índice

- [Por que não é só mais um scanner](#por-que-não-é-só-mais-um-scanner)
- [Instalação](#instalação)
- [Comece por aqui](#comece-por-aqui)
- [Todos os comandos](#todos-os-comandos)
- [Configuração](#configuração)
- [Exit codes (pra CI)](#exit-codes-pra-ci)
- [Desenvolvimento](#desenvolvimento)
- [Licença](#licença)

---

## Por que não é só mais um scanner

Um scanner comum responde "quantas vulnerabilidades essa imagem tem?". Isso
quase nunca é a pergunta que importa. As perguntas de verdade são "qual
imagem eu deveria usar?" e "o que eu faço com o que foi encontrado?" — e é
sobre essas duas que o DockerLs foi pensado.

| | Scanner comum | DockerLs |
|---|---|---|
| Escopo | uma imagem que você já escolheu | **todas as tags candidatas**, ranqueadas |
| Fontes | um registry | Docker Hub + Chainguard + Distroless + Docker Hardened Images, no mesmo pipeline |
| Identidade | a tag que você digitou | **digest do manifesto**, resolvido antes do scan — uma tag se move, um digest não |
| Configuração da imagem | fora do escopo | **Hardening Score** medido no config OCI publicado (root, portas, entrypoint) |
| Superfície de ataque | confundida com tamanho | **Attack Surface Score** próprio: shell, gerenciador de pacotes, ferramentas de debug |
| Exploração real | só a severidade da distro | CISA KEV + FIRST EPSS + Exploit-DB pesam no score e aparecem na tabela |
| Dado que falta | vira "zero" ou "seguro" | vira `unknown` — nunca credita, nunca penaliza por adivinhação |
| Falha de scan | vira "0 vulnerabilidades" | vira `UNVERIFIED`, com causa classificada, fora da recomendação |
| Confiança de dois scanners | não existe | validação cruzada; divergência material é sinalizada, não escondida |
| A imagem mudou desde ontem? | você não sabe | `analyze` registra e avisa quando a tag mudou de digest ou o CVE count mudou |
| Prova do que foi medido | um número na tela | JSON bruto de cada scan + manifesto de evidência por execução |

O princípio que organiza tudo isso: **uma imagem que não pôde ser medida
nunca é apresentada como uma imagem segura.** Ela some da recomendação e vai
para uma lista à parte, com o motivo.

Quer o detalhe fino de cada um desses pontos — o algoritmo de pontuação, o
modelo de confiança, a arquitetura interna? Está tudo na
**[referência completa](docs/REFERENCE.md)**.

### O que mais ele faz, além de recomendar

- **SBOM assinado** (`sbom --attest`) — CycloneDX/SPDX anexado ao manifesto
  via cosign, visível pra quem faz `docker pull`, não só um arquivo no seu
  disco.
- **VEX** (`vex`) — publica suas exceções de CVE (findings que você já
  avaliou e decidiu ignorar) num formato que outras ferramentas entendem.
- **Procedência** (`provenance`) — confere um documento de build e prepara a
  atestação.
- **Auditoria de Dockerfile** (`analyze-dockerfile`, `controls`) — regras de
  hardening mapeadas para controles publicados (CIS, NIST, OWASP).
- **`build` com portão de segurança** — valida, constrói, escaneia e recusa
  publicar se houver CVE explorado de verdade (CISA KEV), mesmo que a distro
  classifique como "médio".
- **`fleet`** — varre uma árvore inteira de repositórios e resume o estado
  de todos os Dockerfiles de uma vez.

---

## Instalação

```bash
pip install dockerls
```

Também dá para instalar com suporte a keyring (guarda credenciais do Docker
Hub no sistema, em vez de texto puro):

```bash
pip install "dockerls[keyring]"
```

### O que você precisa ter instalado

| Precisa de | Pra quê | Se faltar |
|---|---|---|
| **Python 3.11+** | tudo | nada roda |
| **Trivy** ou **Grype** | medir vulnerabilidade de verdade (`recommend`, `analyze`, `compare`, `advisor`, etc.) | ainda funciona, mas os resultados saem marcados como "não verificado" |
| **Docker** (o daemon) | só o comando `build` | `build` falha; todo o resto continua normal |
| **git** | opcional — usado pra registrar de onde veio o build | sai sem esse detalhe, marcado como incompleto |
| **cosign** | opcional — assinar SBOM/imagens (`sbom --attest`, `build --sign`) | funciona sem, mas nada sai assinado |
| **Go 1.24+** | opcional — só se você quiser compilar a engine que acelera runs grandes | dispensável, a CLI funciona 100% sem isso |

Pra conferir tudo de uma vez e instalar o que faltar:

```bash
dockerls doctor            # confere o ambiente
dockerls doctor --install  # instala Trivy/Grype pra você
dockerls health            # confere conectividade com CISA KEV, EPSS, Exploit-DB etc.
```

Nos bastidores, parte da orquestração de scans (`recommend` com muitas tags)
pode rodar num binário auxiliar escrito em Go — é 100% opcional, a CLI
volta sozinha pro caminho em Python se ele não estiver compilado ou
instalado. Detalhes de como compilar em [`engine/README.md`](engine/README.md).

---

## Comece por aqui

```bash
# Qual versão do Node é a mais segura pra usar agora?
dockerls recommend node

# Quero saber tudo sobre essa tag específica
dockerls analyze node:22-alpine

# Já uso essa imagem — o que eu conserto nela?
dockerls advisor node:22-alpine

# Duas imagens, lado a lado
dockerls compare node:22-alpine node:22-bookworm-slim

# Alternativas mais seguras pra imagem que eu já rodo
dockerls alternatives node:18-alpine

# Construir uma imagem já validando, escaneando e (se quiser) assinando
dockerls build . -t minhaapp:1.0 --fail-on high

# Exportar o relatório pra anexar num PR ou mandar pro SIEM
dockerls export node:22-alpine --format sarif --output results.sarif
```

Toda vez que você roda `analyze` contra a mesma imagem, o DockerLs lembra:
se a tag mudou de digest, ou se a contagem de CVE mudou desde a última vez
(mesmo no mesmo digest — a base do scanner pode aprender sobre um CVE novo),
ele avisa.

---

## Todos os comandos

| Comando | Pra que serve | Exit codes |
|---|---|---|
| `search` | Lista as tags que existem de uma imagem | `0` `1` |
| `recommend` | Ranqueia as tags mais seguras e recomenda uma | `0` `1` `2` `3` |
| `advisor` | Plano de correção completo pra melhor imagem (ou pra uma tag específica) | `0` `1` |
| `alternatives` | Alternativas mais seguras pra imagem que você já roda, com trade-offs | `0` `1` `2` |
| `analyze` | Raio-x completo de uma tag: CVEs, CVSS, origem, correção, histórico | `0` `1` `2` |
| `compare` | Duas ou mais imagens, lado a lado | `0` `1` `2` `3` |
| `build` | Valida, constrói, escaneia e (se você quiser) publica e assina | `0` `1` `2` |
| `base` | Confere as bases do Dockerfile contra o registry e atualiza os digests | `0` `1` `2` |
| `base-image` | Gera um Dockerfile de base já enxuto, a partir de um menu | `0` `1` |
| `analyze-dockerfile` | Valida um Dockerfile inteiro contra regras de hardening | `0` `1` `2` |
| `controls` | Mostra os controles (CIS, NIST, OWASP) por trás de cada regra | `0` `1` |
| `sbom` | Gera e opcionalmente assina o inventário de componentes da imagem | `0` `1` |
| `vex` | Publica suas exceções de CVE num formato que outras ferramentas entendem | `0` `1` |
| `provenance` | Confere um documento de procedência e prepara a atestação | `0` `1` `2` |
| `verify` | Confere a assinatura de uma imagem com cosign | `0` `1` `2` |
| `registry-audit` | O que o registry conta sobre uma imagem publicada | `0` `1` `2` |
| `fleet` | Varre vários Dockerfiles de um repositório de uma vez | `0` `1` `2` |
| `policy` | Mostra e valida a política declarada em `.dockerls-policy.yaml` | `0` `1` |
| `export` | Exporta o relatório em JSON, CSV, HTML, Markdown ou SARIF | `0` `1` |
| `doctor` | Confere se scanner, base de dados e o resto do ambiente estão prontos (e instala o que falta) | `0` `1` |
| `health` | Checa a conectividade com os serviços externos (KEV, EPSS, Exploit-DB, registries) | `0` `1` |
| `cache` | Inspeciona e limpa o cache de análises | `0` `1` |
| `login` / `logout` | Guarda ou remove credenciais do Docker Hub no keyring do sistema | `0` `1` |
| `version` | Mostra a versão instalada | `0` |

Cada um desses tem opções que não cabem aqui — a lista completa, com
exemplos de saída real, está na **[referência completa](docs/REFERENCE.md)**.

---

## Configuração

Resolvida nesta ordem: flag na linha de comando → variável de ambiente →
`~/.config/dockerls/config.toml` (ou `$XDG_CONFIG_HOME/...`) → padrão
embutido.

```toml
# ~/.config/dockerls/config.toml
max_tags = 200
workers = 20
log_level = "DEBUG"
```

Variáveis de ambiente mais usadas:

| Variável | Pra quê |
|---|---|
| `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` | Autenticação no Docker Hub |
| `DOCKERLS_ENABLE_THREAT_INTEL` | `false` desativa as consultas a CISA KEV / EPSS / Exploit-DB |
| `DOCKERLS_GITHUB_TOKEN` | Token só-leitura pra elevar o limite de requisições do catálogo DHI |
| `DOCKERLS_<NOME_DA_CONFIG>` | Sobrescreve qualquer configuração (ex.: `DOCKERLS_MAX_TAGS=200`) |

Toda a lista de configurações, com valores padrão, está na
**[referência completa](docs/REFERENCE.md#configuração)**.

---

## Exit codes (pra CI)

A maioria dos comandos segue o mesmo contrato: `0` quando está tudo dentro
do esperado, `1` quando é uma falha técnica (nada foi medido — scanner
ausente, rede indisponível) **ou** quando `--fail-on` foi violado, e um
código próprio (`2` ou `3`, dependendo do comando) quando *foi medido* e o
resultado não bate com o que você pediu — por exemplo, nenhuma tag atingiu
o baseline em `recommend`. A distinção que importa: nada nesse contrato
confunde "não consegui olhar" com "olhei, e é inseguro".

```bash
dockerls recommend node --max-critical 0
echo $?   # 0 = achou uma imagem dentro do baseline | 2 = achou candidatas, nenhuma dentro do baseline
```

---

## Desenvolvimento

```bash
make dev      # instala as dependências de desenvolvimento
make test     # roda os testes
make lint     # roda o linter
make audit    # roda tudo: lint + tipos + testes + segurança
make engine   # compila a engine em Go (opcional, precisa de Go 1.24+)
```

Mais detalhes sobre CI/CD, arquitetura interna e como contribuir estão na
[referência completa](docs/REFERENCE.md#desenvolvimento).

---

## Licença

MIT. Veja [LICENSE](LICENSE).
