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
- [Guia completo: criando e usando uma imagem hardened do zero](#guia-completo-criando-e-usando-uma-imagem-hardened-do-zero)
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

## Guia completo: criando e usando uma imagem hardened do zero

Uma sessão de terminal única, do gerador até a imagem em produção. Todo
output abaixo é real — rodado neste repositório, com Trivy de verdade.

### 1. Escolher sistema operacional, runtime e pacotes — antes do build

A pergunta certa não é "quais pacotes eu tiro depois", é "quais eu realmente
preciso". `base-image` faz essa escolha acontecer antes de qualquer coisa
existir: sem `--with`, ele mostra um menu com o custo de cada pacote em
superfície de ataque, não só o que ele serve.

![menu de pacotes do base-image](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/base_image_menu.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ dockerls base-image --os alpine --runtime node

Packages in the base image
Each one exists in every application that consumes this base, and every CVE in
it becomes triage for someone who does not even know it is there.

  1. ca-certificates (already present in most bases)
       used for: validating TLS when talking to any HTTPS service
       custa: practically none; without it every TLS connection fails
verification
  2. tzdata
       used for: time zones; without it the container stays on UTC and local
dates are wrong
       custa: a few MB of data, no new executable
  3. curl
       used for: HTTP HEALTHCHECK and network diagnostics
       custa: a full HTTP client inside the container -- what an attacker uses
to fetch the second stage
  4. wget
       used for: an alternative to curl for downloading files
       custa: the same cost as curl; having both doubles the surface, not the
use
  5. bash
       used for: scripts relying on features the Alpine `sh` does not have
       custa: a more capable shell is a more useful shell for whoever breaks in
  ...
  9. tini
       used for: a minimal init that forwards signals and reaps orphaned
processes
       custa: almost nothing, and it fixes the pid 1 that ignores SIGTERM

Comma-separated numbers (empty = no packages): 1,2,9
```

</details>

Repare no `curl`: o propósito ("HEALTHCHECK e diagnóstico de rede") é
legítimo, mas o custo dito ali do lado é o mesmo que um atacante usa pra
buscar o segundo estágio de um ataque. O menu não esconde isso pra depois —
mostra na hora de marcar.

Em pipeline não tem menu pra responder. `--with` aceita a mesma lista
separada por vírgula e pula direto pro Dockerfile:

![base-image com --with, gerando o Dockerfile](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/base_image_with.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ dockerls base-image --os alpine --runtime node \
    --with "ca-certificates,tzdata,tini" -o Dockerfile \
    --owner "team-x" --title minhaapp

npm and yarn will be removed from the final image (--keep-manager keeps them).

Dockerfile written to Dockerfile.

Next step
  dockerls build -t minhaapp:1.0 --fail-on critical .
  Building and scanning is what turns this recipe into a claim about security;
until then it is only an intention.
```

</details>

Existem três pacotes que esse catálogo se recusa a oferecer, mesmo por
`--with` — são recusas documentadas, não omissões:

| Pacote | Por que não |
|---|---|
| `sudo` | numa imagem que já roda sem privilégio, `sudo` existe pra cruzar a fronteira que acabou de ser estabelecida — e é setuid pra isso |
| `su-exec` | trocar de usuário em runtime desfaz o `USER` da imagem; se o processo precisa de outro usuário, declare isso no `USER` |
| `docker` | o cliente Docker dentro do container implica acesso ao socket do daemon, que equivale a root no host |

### 2. A versão do runtime vem fixa por família — trocando e resolvendo o digest de novo

Cada combinação de `--os`/`--runtime` mapeia pra uma versão específica,
travada no catálogo (`RUNTIME_BASES`, em
`dockerls/domain/value_objects/base_recipe.py`) — não é um parâmetro:
`node:22-alpine`, `python:3.12-alpine`, `golang:1.23-alpine`,
`eclipse-temurin:21-jre-alpine`, e o equivalente em Debian/Ubuntu/distroless
pra cada um. Se você precisa de outra versão, o caminho é editar a linha
`FROM` manualmente e resolver o digest de novo:

![dockerls base . repinando o digest](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/base_pin_digest.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ sed -i 's/FROM node:22-alpine@\${BASE_DIGEST}/FROM node:20-alpine/; s/ARG BASE_DIGEST=.*/ARG BASE_DIGEST=/' Dockerfile
$ dockerls base .

Dockerfile

  line 14  UNPINNED
    node:20-alpine
    moving tag, no digest: what you tested and what goes to production can be
different bytes with no change on your part
    ->
node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609
372293  (line 14)

1 without a digest

1 update(s) written to Dockerfile.
Rebuild and scan before publishing: changing the base digest changes the image,
and only a scan tells you whether for the better.
```

</details>

`base` não sabe (nem tenta adivinhar) se a troca de versão é segura — ele só
garante que, seja qual for a tag, ela fica pinada por digest antes de ir pra
frente. A resposta sobre segurança vem do scan, no passo 5.

### 3. Nota pra quem usa PowerShell

`--with ""` falha no PowerShell com `Got unexpected extra argument(s)`. Não é
bug do DockerLs: o PowerShell descarta argumentos de string vazia ao chamar
executáveis nativos, e isso empurra o parsing dos flags seguintes. A forma
correta é `--with=` (sem espaço, sem aspas) ou, se precisar passar outros
argumentos complicados, `dockerls --% base-image ...` pra desligar o parsing
do PowerShell inteiro a partir dali.

### 4. Validar antes de construir

![resultado do analyze-dockerfile](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/analyze_dockerfile.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ dockerls analyze-dockerfile .

Summary: 9 passed | 4 warnings | 0 errors

  PASS   base_image_pinned         Base image tag is not 'latest' (still a
                                    moving tag -- `dockerls base` pins it by
                                    digest)
  PASS   non_root_user             Container runs as non-root user: node
  WARN   multi_stage_build         Single-stage build detected
  PASS   secrets_not_in_env        No obvious secrets in ENV variables or ARG
                                    defaults
  WARN   package_cache_clean       Package manager cache not cleaned
  WARN   healthcheck_present       No HEALTHCHECK directive
  PASS   security_labels           Security labels present
  PASS   minimal_base              Using minimal base image
  PASS   no_sudo                   No sudo usage detected
  WARN   dockerignore_exists       .dockerignore not found
  PASS   add_not_used_for_copy     No ADD directives (COPY is used to bring
                                    files in)
  PASS   no_unverified_remote_scr… No remote script is piped straight into a
                                    shell
  PASS   no_setuid_binaries_added  No setuid or setgid bit is set in the build

Security Score: 90/100   Tier: A   Production Ready: Yes
```

</details>

Isso roda sem Docker, sem scanner, sem rede — é análise estática do texto do
Dockerfile. Os warnings aqui (sem multi-stage, sem HEALTHCHECK, sem
`.dockerignore`) são exatamente o que aparece de novo como sugestão depois do
build, no passo 5.

### 5. Build com portão de segurança

`--production` liga de uma vez o perfil inteiro: gate em critical, exige que
o scan realmente tenha rodado, bases pinadas por digest, usuário
não-privilegiado, procedência verificada (hash do Dockerfile, do contexto e
da imagem final, amarrados), labels de ownership obrigatórias e atribuição de
findings (base vs. suas camadas). `--fail-on critical,kev` soma mais um
critério: falhar também se algum CVE encontrado está no catálogo CISA KEV —
sendo explorado ativamente, mesmo que não seja CRITICAL.

![dockerls build --production com o gate de segurança](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/build_production.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ dockerls build . -t minhaapp:1.0 --production --fail-on critical,kev `
    --owner "team-x" `
    --source "https://github.com/suaorg/minhaapp" `
    --security-contact "security@suaorg.com"

Production profile
  fail_on  critical
  require_scan  True
  require_pinned_bases  True
  require_nonroot  True
  required_labels  org.opencontainers.image.source, org.opencontainers.image.vendor, security.contact
  require_provenance  True

╭──────────────────╮
│ Build Successful │
│ minhaapp:1.0     │
╰──────────────────╯

╭────────────────────────╮
│ Security Score: 85/100 │
│ Tier: B                │
╰────────────────────────╯

Validation: 8 passed | 5 warnings | 0 errors

╭───────────────────────╮
│ Security Scan Results │
╰───────────────────────╯
  CRITICAL: 0
  HIGH: 0
  MEDIUM: 0
  LOW: 0

╭────────────────────────╮
│ Supply chain: VERIFIED │
╰────────────────────────╯
  input and output digested, and the input did not change during the build

INPUT (measured before the build)
  Dockerfile  sha256:e696d147012323b8b1c27de847b48f566ab4a8282b2377ba00fe35215a71a249
  Contexto    sha256:a8d265c6ff3c1a57b43ad00c24f9d07b13531923d66acaa5948c85697476252c  (1 files)

OUTPUT (measured after the build)
  Image       sha256:5e5a079bbd616d166b155f15dac48c9c603a9d605876c732fde620a7aa7958bc
```

</details>

Sem `--owner`, `--source` e `--security-contact`, esse mesmo comando falha —
de propósito: `required_labels` é parte do perfil `--production`, e o motivo
está no próprio erro quando isso acontece: "sem isso ninguém sabe pra quem
ligar quando essa imagem aparecer num alerta às três da manhã".

### 6. Usando a imagem depois de construída

![docker run --rm minhaapp:1.0 id](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/docker_run_id.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ docker run --rm minhaapp:1.0 id
uid=1000(node) gid=1000(node) groups=1000(node),1000(node)
```

</details>

`uid=1000`, não `uid=0`. É o `USER node` do Dockerfile confirmado em
execução, não só lido no texto — a mesma checagem que `non_root_user` faz de
forma estática no passo 4, agora contra o container de verdade.

### 7. Fechando o loop

![dockerls analyze minhaapp:1.0 (imagem já construída)](https://raw.githubusercontent.com/Ivomsantiago/DockerLs/Master/docs/assets/analyze_final.svg)

<details>
<summary>Ver como texto (copiar/colar)</summary>

```console
$ dockerls analyze minhaapp:1.0

Analysis: minhaapp:1.0

  Score                96.0
  Tier                 A
  Critical             0
  High                 0
  Medium               0
  Low                  0
  Total Vulns          0
  Fixable              0 (n/a)
  Remediation Score    100/100
  EOL                  No
  LTS                  No
  Scanner              trivy
```

</details>

O mesmo `analyze` que você rodaria contra `node:22-alpine` pra decidir se
confia nela funciona igual contra o que você acabou de construir. Não existe
um comando separado pra "auditar a própria imagem" — é o mesmo raio-x, na
mesma régua.

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
