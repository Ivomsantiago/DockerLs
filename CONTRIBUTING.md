# Política de Segurança

## Versões suportadas

| Versão | Suportada |
|--------|-----------|
| 1.x    | Sim       |

## Reportando uma vulnerabilidade

Se você descobrir uma vulnerabilidade de segurança no DockerLs, por favor reporte de forma responsável.

**Não abra uma issue pública.**

Use o recurso de reporte privado de vulnerabilidades do GitHub neste repositório:
**Security → Report a vulnerability**.

### O que incluir

- Descrição da vulnerabilidade
- Passos para reproduzir
- Avaliação de impacto
- Correção sugerida (se houver)

### Prazos de resposta

- Confirmação de recebimento: até 48 horas
- Avaliação inicial: até 1 semana
- Correção e divulgação: coordenadas com quem reportou

## Design de segurança

O DockerLs segue estes princípios de segurança:

### Validação de entrada

- Todos os nomes de imagem são validados contra um padrão de regex estrito
- Ataques de path traversal são bloqueados
- Injeção de comando é impedida (sem `shell=True`, sem interpolação de strings nos comandos)

### Tratamento de credenciais

- As credenciais são armazenadas no keyring do sistema (nunca em arquivos de texto puro)
- Variáveis de ambiente são suportadas como alternativa
- Todas as credenciais são mascaradas na saída de log
- Bearer tokens e senhas são filtrados do logging estruturado

### Segurança de rede

- Todas as requisições HTTP usam HTTPS
- Timeouts são aplicados em todas as chamadas externas
- A lógica de retry usa backoff exponencial para não sobrecarregar os serviços
- Rate limiting é respeitado

### Cadeia de suprimentos

- As dependências são fixadas no `pyproject.toml`
- O Dependabot monitora dependências vulneráveis
- O `pip-audit` roda no CI
- A imagem Docker usa build multi-stage com tags de versão específicas

### Segurança de contêiner

- Usuário não-root na imagem Docker
- Suporte a sistema de arquivos somente leitura
- Todas as capabilities removidas
- Flag de no-new-privileges
- Healthcheck configurado

---

## Convenção de idioma

O projeto é publicado em inglês -- README, PyPI, nomes de comando e de flag --
e a saída do CLI segue a mesma língua. A regra separa o que o usuário lê do
que só quem mexe no código lê:

| O quê | Idioma | Por quê |
|---|---|---|
| Strings de saída ao usuário: `console.print`, mensagens de erro, `help=` do Typer, docstring de função de comando (vira o `--help`), conteúdo de tabelas Rich | **Inglês, obrigatório** | é o que chega a quem instala do PyPI |
| Comentários de código e docstrings internas | **Português, permitido** | convenção estabelecida do projeto; explicam decisões de design para quem mantém |

Vale para toda a árvore, não só para `cli/`: uma string em `domain/` ou
`infrastructure/` que é impressa por um comando é saída ao usuário e segue a
primeira linha da tabela.

### Sem emoji na saída

Nada de `✅ ⚠️ ❌ 🔍 💡` no terminal. A cor do Rich (`[green]`, `[yellow]`,
`[red]`) já carrega o sinal visual, e ela degrada de forma limpa sob
`--no-color` ou num pipe para arquivo de log -- coisa que um emoji não faz.
Status de check são texto: `PASS` / `WARN` / `FAIL` / `SKIP`. Bullets são `-`.

Box Drawing (`├─`, `└─`) **não** é emoji: é estrutura de árvore, a mesma
convenção do `tree`, e pode ficar.

### O guard

`tests/unit/cli/test_output_is_english_ascii.py` roda cada comando traduzido
contra um fixture mínimo e reprova se a saída trouxer caractere acentuado ou
emoji. Comandos ainda não traduzidos estão listados ali em
`_NOT_YET_TRANSLATED`, explicitamente, para que a ausência deles não seja lida
como aprovação.

Uma limitação conhecida: o guard detecta acento, então português **sem
acentuação** (`"Apenas valida sem sugerir melhorias"`) passa por ele. A
revisão humana continua sendo o que pega esse caso.
