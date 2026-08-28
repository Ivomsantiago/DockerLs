# DockerLs

[![CI](https://github.com/Ivomsantiago/DockerLs/actions/workflows/ci.yml/badge.svg)](https://github.com/Ivomsantiago/DockerLs/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Ivomsantiago/DockerLs/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ivomsantiago/DockerLs/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**DockerLs ajuda você a escolher a imagem Docker mais segura para produção.**

Em vez de você pesquisar tag por tag no Docker Hub e adivinhar qual é mais
confiável, o DockerLs escaneia várias de uma vez, compara com alternativas
mais seguras (Chainguard, Distroless, Docker Hardened Images) e recomenda
uma — explicando o porquê.

A diferença central é simples: quando não dá para medir alguma coisa com
confiança, o DockerLs diz isso em vez de inventar uma resposta bonita. Uma
imagem que o scanner não conseguiu analisar nunca aparece como "segura" —
ela some da recomendação e vai para uma lista à parte, com o motivo.

```
dockerls recommend node
```

isso já basta para ver a ideia funcionando.

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

Você vai precisar de um scanner de vulnerabilidades instalado — [Trivy](https://aquasecurity.github.io/trivy)
ou [Grype](https://github.com/anchore/grype). Sem um dos dois, o DockerLs
ainda funciona, mas nada é "medido de verdade": os resultados saem marcados
como não verificados. Para checar se está tudo certo na sua máquina:

```bash
dockerls doctor
```

Esse comando também instala os scanners para você, se quiser (`doctor --install`).

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

# Construir uma imagem já validando e escaneando no processo
dockerls build . -t minhaapp:1.0 --fail-on high
```

---

## O que ele faz, em uma tabela

| Comando | Pra que serve |
|---|---|
| `search` | Lista as tags que existem de uma imagem |
| `recommend` | Ranqueia as tags mais seguras e recomenda uma |
| `advisor` | Plano de correção pra imagem que você já roda |
| `alternatives` | Alternativas mais seguras, com os trade-offs de cada uma |
| `analyze` | Raio-x completo de uma tag: CVEs, origem, correção |
| `compare` | Duas ou mais imagens, lado a lado |
| `build` | Valida, constrói, escaneia e (se você quiser) publica e assina |
| `base-image` | Gera um Dockerfile de base já enxuto, a partir de um menu |
| `sbom` | Gera e opcionalmente assina o inventário de componentes da imagem |
| `vex` | Publica suas exceções de CVE num formato que outras ferramentas entendem |
| `fleet` | Varre vários Dockerfiles de um repositório de uma vez |
| `doctor` | Confere se scanner, base de dados e o resto do ambiente estão prontos |
| `export` | Exporta o relatório em JSON, CSV, HTML, Markdown ou SARIF |

Tem mais comandos além desses — a lista completa, com todas as opções e
exemplos de saída real, está na **[referência completa](docs/REFERENCE.md)**.

---

## Por que confiar no que ele diz

Um scanner comum responde "quantas vulnerabilidades essa imagem tem?". Isso
quase nunca é a pergunta que importa. As perguntas de verdade são "qual
imagem eu deveria usar?" e "o que eu faço com o que foi encontrado?" — e é
sobre essas duas que o DockerLs foi pensado.

Algumas escolhas que fazem diferença no dia a dia:

- **Nenhum fornecedor é levado no automático.** Uma imagem anunciada como
  "hardened" só é tratada como tal depois de o DockerLs escanear e
  confirmar — a etiqueta do fornecedor é só um dado a mais, não a resposta.
- **Dado que falta nunca vira "não tem problema".** Se o scanner não
  conseguiu medir uma coisa, ela fica marcada como "não verificado" — nunca
  como zero, nunca como aprovado.
- **A tag pode mudar de conteúdo amanhã; o digest, não.** Toda recomendação
  é resolvida por digest antes do scan, exatamente para evitar essa
  armadilha.
- **Um segundo scanner confere o primeiro.** Quando os dois discordam de
  forma relevante, isso aparece no resultado em vez de ser escondido.
- **O portão de segurança do `build` também olha exploração real**, não só
  o rótulo de severidade que o fabricante da distro escolheu — dá pra
  reprovar um build por um CVE que já está sendo explorado no mundo real
  (CISA KEV), mesmo que ele seja classificado como "médio".

Se você quer entender o algoritmo de pontuação, o modelo de confiança, a
arquitetura interna ou qualquer detalhe fino, tudo isso está documentado na
**[referência completa](docs/REFERENCE.md)**.

---

## Desenvolvimento

```bash
make dev      # instala as dependências de desenvolvimento
make test     # roda os testes
make lint     # roda o linter
make audit    # roda tudo: lint + tipos + testes + segurança
```

Mais detalhes sobre CI/CD, arquitetura e como contribuir estão na
[referência completa](docs/REFERENCE.md#desenvolvimento).

---

## Licença

MIT. Veja [LICENSE](LICENSE).
