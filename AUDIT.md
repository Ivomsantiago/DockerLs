# Auditoria de evidência — 2026-08

Relatório produzido **antes** de qualquer alteração, conforme a Fase A.
A coluna *Status* foi preenchida depois, quando cada achado foi corrigido. Cada
achado foi verificado no código e, onde marcado *(demonstrado)*, reproduzido
executando o próprio pacote.

O critério que orienta a severidade é um só:

> Uma imagem que não pôde ser medida nunca deve ser apresentada como segura.

Um achado é **crítico** quando a ferramenta afirma segurança sem evidência que
a sustente; **alto** quando ausência de dado é convertida em fato favorável;
**médio** quando a evidência é frágil, contaminável ou irreprodutível.

---

## Sumário

| # | Sev. | Achado | Status |
|---|------|--------|--------|
| F1 | CRÍTICA | `production_ready` não conhece confidence: `PARTIAL` sem achados vira tier A e "production ready" enquanto o confidence diz `UNVERIFIED` | **corrigido** — política central `ProductionReadiness`, único escritor do campo |
| F2 | ALTA | EOL desconhecido é convertido em `False` | **corrigido** — `eol_status` tri-state; `UNKNOWN` não penaliza, não credita e é reportado |
| F3 | ALTA | Feed KEV/EPSS indisponível faz todo CVE virar "não explorado", e o rationale **afirma** "no known-exploited vulnerabilities" | **corrigido** — `kev_status` tri-state; a afirmação só sai sobre achados efetivamente consultados |
| F4 | ALTA | SSRF para loopback, RFC1918 e endpoint de metadados *(demonstrado)* | **corrigido** — `NetworkPolicy` + `HostGuard`, decisão por resolução |
| F5 | MÉDIA | Injeção de markup Rich a partir de texto do scanner *(demonstrado)* | **corrigido** — `cli/text.safe()` nas interpolações de terceiros |
| F6 | MÉDIA | `PARTIAL` recebe score de segurança | **mitigado** — o score continua sendo calculado (relatórios precisam dele), mas nunca é veredito: `PARTIAL` é `UNVERIFIED` e bloqueado por `NOT_MEASURED` |
| F7 | MÉDIA | EPSS binário em 0.5 | **corrigido** — degrau preservado + termo contínuo; monotônico e testado |
| F8 | MÉDIA | `run_capture` sem teto de saída | **corrigido** — 256 MiB por fluxo, excesso vira `INVALID_OUTPUT` |
| F9 | MÉDIA | Evidência bruta sem redação | **corrigido** — redator central aplicado a artefatos e manifesto |
| F10 | MÉDIA | Chave de cache ignora scanner e versão | **corrigido** — identidade do scanner entra no fingerprint |
| F11 | MÉDIA | Versão do scanner nunca registrada | **corrigido** — capturada por execução, no manifesto e no cache |
| F12 | MÉDIA | Cross-validation por contagem | **corrigido** — comparação por identidade (CVE+pacote) e desfecho classificado |
| F13 | BAIXA | `TAG_MOVED` não detectado | **corrigido** — `base` já registrava e reportava o histórico por tag (`tag_history.py`, commit `45f9821`, 2026-08-21) para bases fixadas em Dockerfile; `analyze` (e por extensão `compare`/`advisor`/`alternatives`) agora reporta o mesmo fato para uma tag consultada diretamente |

Um achado extra apareceu durante a correção e foi tratado junto:

| F14 | BAIXA | Processo morto por timeout deixava o transporte para o coletor de lixo, e o `__del__` rodava depois do event loop fechar | **corrigido** — `_close_transport` no reap |

---

## F1 — `production_ready` não conhece confidence  *(CRÍTICA)*

**Arquivo.** `dockerls/domain/value_objects/security_tier.py`, `SecurityTier.production_ready`.

**O que faz hoje.**

```python
@property
def production_ready(self) -> bool:
    if self._is_eol:
        return False
    return self._tier in PRODUCTION_READY_TIERS
```

O tier vem do score, e o score vem do scan. Nada nessa cadeia sabe se o scan
foi *concluído*.

**Impacto.** Um scan `PARTIAL` (alvos que não puderam ser inspecionados) com
zero achados nos alvos que puderam produz score alto → tier A →
`production_ready = True`. Ao lado, `confidence` reporta `UNVERIFIED`. A mesma
análise afirma as duas coisas. É exatamente a substituição que o princípio
fundamental proíbe, e está no campo que um portão de CI mais provavelmente lê.

**Proposta.** Criar uma política central `ProductionReadiness` no domínio, que
consuma tier, EOL, confidence, divergência e verificação do scan — e fazer
`ImageAnalysis.production_ready` derivar dela. Regra: qualquer coisa abaixo de
`MEDIUM` de confidence não é production ready, independentemente do tier.

---

## F2 — EOL desconhecido vira `False`  *(ALTA)*

**Arquivo.** `dockerls/integrations/endoflife/checker.py`, `is_eol`/`is_lts`.

Todo caminho de falha — produto não catalogado, versão não extraída, rede
indisponível — retorna `False`. `SecurityScore` recebe `is_eol: bool` e não
distingue "não está EOL" de "não foi possível saber".

**Impacto.** Uma imagem cuja data de fim de vida ninguém conseguiu consultar é
pontuada como se estivesse dentro do suporte, e passa por `production_ready`.
Ausência de evidência tratada como evidência favorável.

**Proposta.** Tri-state. `EOLCheckerInterface` ganha `eol_status()` devolvendo
`Tristate`; `is_eol()` permanece para compatibilidade. `UNKNOWN` não penaliza
(não há evidência de EOL) mas **impede** o topo da confiança e aparece no
rationale — que é a diferença entre "não está EOL" e "ninguém sabe".

---

## F3 — Feed de threat intel indisponível vira "não explorado"  *(ALTA)*

**Arquivos.** `integrations/threat_intel/client.py` (retorna `set()`/`{}` em
qualquer falha) e `application/services/verdict.py:148`.

O enriquecimento faz `exploit_known = cve in kev_ids`. Com o feed fora do ar,
`kev_ids` é vazio e **todo** CVE fica `exploit_known=False`. Em seguida o
rationale imprime, afirmativamente:

```
no known-exploited (CISA KEV) vulnerabilities
```

**Impacto.** A frase mais forte que a ferramenta produz sobre exploração real é
emitida justamente quando ela não conseguiu consultar nada. Pior que o score:
é uma afirmação em linguagem natural que o leitor vai citar.

**Proposta.** Registrar se o feed respondeu. `NOT_LISTED` (consultado, não
consta) ≠ `UNKNOWN` (não consultado). A frase afirmativa só sai no primeiro
caso; no segundo, o texto diz que a inteligência não estava disponível, e o
confidence cai.

---

## F4 — SSRF em referências de imagem  *(ALTA, demonstrado)*

**Arquivo.** `integrations/registry/inspector.py`, `_registry_target`.

Reproduzido com o pacote instalado:

```
169.254.169.254/latest      -> ('169.254.169.254', 'latest')
127.0.0.1:5000/app          -> ('127.0.0.1:5000', 'app')
10.0.0.5:5000/internal/app  -> ('10.0.0.5:5000', 'internal/app')
```

O host só é validado quanto ao *formato*. `RegistryInspector` então emite
`GET https://169.254.169.254/v2/latest/manifests/...`.

**Impacto.** Num runner de CI, uma referência vinda de um PR, de um
`config.toml` ou de uma variável de ambiente transforma o DockerLs num
primitivo de SSRF contra o endpoint de metadados da nuvem e contra serviços
internos. O corpo não volta para o atacante, mas o alcance de rede é dele.

**Proposta.** Uma `NetworkPolicy` explícita, aplicada antes de qualquer
requisição. Padrão: **bloquear loopback e link-local** (169.254.0.0/16 inclui o
endpoint de metadados; nenhum registry público legítimo mora lá) e **permitir
RFC1918**, porque registry interno é caso legítimo e comum — como o próprio
enunciado adverte. Configurável nos dois sentidos, com allowlist de hosts.

---

## F5 — Injeção de markup Rich vinda do scanner  *(MÉDIA, demonstrado)*

Descrições de CVE, nomes de pacote e mensagens de erro do scanner são passados
a `rich` sem escape. Reproduzido:

```
entrada : "[red]FIXED - no action needed[/red] [blink]"
render  : "FIXED - no action needed"      # markup interpretado, não exibido
```

**Impacto.** Quem controla o conteúdo de um advisory upstream — ou os metadados
de um pacote dentro de uma imagem sob análise — controla a formatação do
relatório: pode colorir um achado como benigno, aplicar `[blink]`, ou fabricar
texto que parece anotação da ferramenta. É o único ponto em que dado não
confiável vira instrução de apresentação.

**Proposta.** `rich.markup.escape` em toda interpolação de texto de terceiros,
e teste adversarial fixando o comportamento.

---

## F6 — `PARTIAL` recebe score  *(MÉDIA)*

`SecurityScore.__init__` aceita `OK` **e** `PARTIAL`. Um scan parcial produz
número, tier e — via F1 — veredito. O próprio docstring de
`ScanResult.is_verified` diz que `PARTIAL` é um limite inferior, não uma
medição; o score não respeita isso.

**Proposta.** Não remover a capacidade (relatórios querem mostrar o que foi
achado), mas marcar: o score de um `PARTIAL` nunca é apresentado como veredito,
e a política de production readiness o rejeita.

---

## F7 — EPSS binário  *(MÉDIA)*

```python
penalty += HIGH_EPSS_PENALTY * sum(1 for v if v.epss_score >= 0.5)
```

EPSS 0.97 e EPSS 0.51 custam o mesmo; 0.49 custa zero.

**Proposta.** Preservar o degrau (é o que o operador entende) e somar um termo
contínuo proporcional, mantendo o teto abaixo da penalidade de CRITICAL.

---

## F8 — Saída do scanner sem teto  *(MÉDIA)*

`run_capture` usa `proc.communicate()`, que acumula stdout inteiro em memória.
Um scanner comprometido, ou apenas uma imagem com dezenas de milhares de
achados, é lido sem limite.

**Proposta.** Ler com teto explícito e classificar o excesso como
`INVALID_OUTPUT` — que já é um estado não verificado.

---

## F9 — Evidência bruta sem redação  *(MÉDIA)*

`EvidenceStore._record_scan_sync` faz `path.write_text(raw)`. O mascaramento de
segredos existe, mas só no sink de log. A evidência é o artefato que as pessoas
anexam a tickets.

**Proposta.** Passar o artefato pelo mesmo redator central, sem destruir os
campos de diagnóstico.

---

## F10/F11 — Cache e reprodutibilidade  *(MÉDIA)*

A chave é `analysis:{fingerprint}:{digest|referência}`. O fingerprint cobre
regras de ignore e presença de threat intel; **não** cobre qual scanner rodou,
sua versão, nem a versão da base de vulnerabilidades. Um `dockerls` que trocou
de Trivy para Grype, ou que atualizou a base, serve o resultado antigo dentro
do TTL.

A versão do scanner não é capturada em lugar nenhum, então a análise não é
reconstruível — que é o requisito da Fase 18.

**Proposta.** Capturar identidade do scanner (nome + versão) uma vez por
execução, incluí-la no fingerprint do cache e registrá-la no manifesto.

---

## F12 — Cross-validation por contagem  *(MÉDIA)*

`_describe_divergence` compara `critical_count` e `high_count`. Dois scanners
que reportam **um** CRITICAL cada, mas CVEs diferentes, são classificados como
concordância.

**Proposta.** Comparar identidade de vulnerabilidade (CVE + pacote), classificar
em `AGREEMENT` / `MINOR_DIVERGENCE` / `MATERIAL_DIVERGENCE` / `NO_SECOND_SCANNER`
e alimentar o confidence com a classe, não com um booleano.

---

## F13 — `TAG_MOVED` não é detectado  *(BAIXA, corrigido)*

A chave de cache por digest já evita servir resultado de outra imagem. O que
faltava era *dizer* que a tag se moveu — informação acionável para quem fixou a
tag num Dockerfile.

**Proposta original.** Registrar o último digest visto por tag e reportar a
mudança.

**Nota da revisão de 2026-08-18.** O impacto continua BAIXO e o motivo ficou
claro: a confiança já rebaixa toda referência não fixada num digest para
`LOW`/`MEDIUM`, com a razão escrita ("reference is not pinned to a digest and
was not confirmed"). Ou seja, o leitor não recebe uma tag móvel apresentada
como se fosse medida definitiva — ele só não recebia o aviso específico de que
ela *se moveu desde a última vez*.

**Status real, revisão de 2026-08-29.** Já estava corrigido para `base`: o
commit `45f9821` (2026-08-21, três dias depois da nota acima) introduziu
`domain/value_objects/tag_history.py` + `application/services/
tag_history_store.py`, que fazem exatamente a proposta -- guardam o digest
observado por tag, com timestamp, e `base_cmd.py` imprime `history: mudou de
digest N vezes desde ...` quando `historico.moves` é maior que zero. Essa
correção nunca foi cruzada de volta com esta entrada. O que faltava era
estender o mesmo mecanismo, já testado, para quem consulta uma tag fora de um
Dockerfile: `AnalyzeImageUseCase` agora recebe um `TagHistoryStore` opcional e
grava/lê pelo mesmo histórico, então `analyze` -- e por extensão `compare`,
`advisor` e `alternatives`, que reaproveitam o mesmo caso de uso -- também
mostram `tag_drift_note` quando a tag pedida mudou de digest desde a última
vez que esta ferramenta olhou para ela. Uma referência por digest
(`name@sha256:...`) nunca entra nesse histórico: ela não tem tag para
acompanhar.

---

## F14 — O pull do próprio scanner ignorava a política de rede  *(ALTA)*

**Achado.** A política de SSRF (F5) guardava o `RegistryInspector`, que é
**uma** das portas. `trivy image X` e `grype X` abrem o próprio socket e
puxam a imagem sozinhos: uma referência como `169.254.169.254/latest:v1` —
sintaticamente válida, aprovada por `sanitize_image_name`, e chegando de uma
variável de CI, de um arquivo de config ou de um pull request — mirava a
conexão do scanner no endpoint de metadados da nuvem enquanto a porta
guardada permanecia fechada. Guarda numa porta de um prédio com duas.

**Agravante encontrado no caminho.** A regra "o primeiro componente é um host
de registry" estava escrita duas vezes (em `DockerImage.registry_host` e em
`dockerhub/urls.py`), e ambas testavam apenas ponto-ou-dois-pontos. Com isso
`localhost/evil` era lido como o usuário "localhost" do Docker Hub — exatamente
o caso que um atacante quer, porque é o único host interessante que não tem
ponto nem porta.

**Correção.** `domain/value_objects/image_reference.py` passa a ser a única
definição da regra (Docker's own: ponto, dois-pontos, **ou `localhost`**), e
`DockerImage.registry_host` delega para ela. `integrations/scan_target.py`
consulta o `HostGuard` **antes** de invocar o binário; a recusa é um
`ScanResult` com status `ERROR` e `error_kind=BLOCKED_BY_POLICY` — nunca uma
lista de achados vazia, que seria indistinguível de uma imagem limpa. O novo
`BLOCKED_BY_POLICY` é deliberadamente **não** `is_scanner_fault`: um segundo
scanner puxaria do mesmo host recusado, então o fallback só gastaria o dobro
do tempo para chegar à mesma recusa.

**O que continua passando.** Docker Hub nunca é julgado (contatá-lo é a função
da ferramenta) e registries internos em RFC1918 continuam escaneáveis — a
política que já existia, aplicada agora à porta que faltava.

---

# Auditoria de desempenho — 2026-08

Segunda passagem, dirigida a consumo de CPU e memória. Diferente da primeira,
aqui **tudo foi medido** antes de ser mexido: o perfil do pipeline inteiro
mostrou que ele não é limitado por CPU, e que os dois custos reais estavam
fora dele.

| # | Sev. | Achado | Medição | Status |
|---|------|--------|---------|--------|
| P1 | CRÍTICA | `redact()` com backtracking catastrófico, executado uma vez por imagem escaneada | **19 445 ms** num artefato de 2,1 MB | **corrigido** — 245 ms (79x) |
| P2 | ALTA | `workers = 10` fixo, sem nenhuma referência à máquina; num container lê os núcleos do *host*, não a cota | 10 processos de scanner num runner de 2 núcleos | **corrigido** — derivado de CPU e memória, ciente de cgroup |
| P3 | MÉDIA | `cross_validate_workers = 5` igualmente fixo, abrindo uma segunda leva de processos | — | **corrigido** — limitado pela máquina e pelo pool primário |
| P4 | — | Memória do pipeline | 107 MB de pico para 100 tags x 800 achados, 6 MB residuais | **aceitável** — sem vazamento, liberada ao fim |
| P5 | — | Recontagem de severidades a cada acesso (`sum(1 for v in ...)`) | 90 ms para pontuar 100 tags x 800 achados | **não alterado** — ver abaixo |

## P1 — a regressão que eu mesmo introduzi

O padrão de chave começava com `[\w.-]*`:

```
["']?[\w.-]*(?:token|password|...)[\w.-]*["']?\s*[:=]\s*
```

Numa descrição de CVE com 400 caracteres de texto corrido, o motor tenta cada
divisão possível daquele `*` em cada posição, e falha em todas. O custo
explode com o tamanho do documento.

A correção não é "otimizar o regex": é **inverter a ordem**. Com a alternância
literal na frente, o motor procura uma palavra-chave — coisa que ele faz por
varredura direta — e só então expande para os lados, onde os limites são a
própria palavra:

```
(?:token|password|...)[\w.-]*["']?\s*[:=]\s*
```

O texto antes da palavra-chave (`x_` em `x_api_key`) fica fora do casamento e
sobrevive intacto, então a saída é idêntica caractere por caractere. Há teste
de equivalência sobre doze formatos e teste de orçamento de tempo.

## P2 — o número que ignorava a máquina

Cada worker segura um **processo de scanner**, não uma corrotina: o `trivy`
carrega uma base de centenas de MB, desempacota camadas e casa pacotes,
consumindo um núcleo inteiro enquanto isso. Dez deles num runner de dois
núcleos não terminam dez vezes mais rápido — terminam mais devagar, despejam o
page cache e podem levar o job a ser morto por falta de memória.

O agravante é específico desta ferramenta: ela analisa containers e é rodada
*dentro* de um. `os.cpu_count()` ali reporta os núcleos do host enquanto o
cgroup permite uma fração de um. `utils/resources.py` lê a cota real (cgroup v2
e v1), a máscara de afinidade e a memória disponível, e o padrão passa a ser o
menor dos três.

Configuração explícita continua valendo: quem pede 20 recebe 20, com um aviso
dizendo o que a máquina comporta.

## P5 — o que foi medido e deliberadamente não mudou

`ScanResult.critical_count` e as sete contagens vizinhas percorrem a lista
inteira a cada acesso. Parecia gargalo; medido, são 90 ms para pontuar 100 tags
com 800 achados cada — irrelevante ao lado de um único scan real, que leva
segundos.

Cachear essas contagens exigiria invalidação em `model_copy`, que é usado pelas
regras de ignore e pelo enriquecimento de threat intel. Trocar um custo
irrelevante por um risco de contagem obsoleta seria um mau negócio, e "otimizar
o que não é gargalo" é como se introduz o próximo P1.
