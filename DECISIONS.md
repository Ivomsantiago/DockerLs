# DECISIONS.md

Decisões tomadas durante a implementação autônoma de `dockerls build` e
`dockerls update`. Cada entrada registra a ambiguidade encontrada, as opções
consideradas e por que a escolhida é a mais segura.

---

## D-001 — Mapeamento da árvore de módulos

**Ambiguidade.** A especificação descreve `domain/`, `application/`,
`infrastructure/` e `interface/cli/` na raiz. Este repositório usa
`dockerls/domain/`, `dockerls/application/`, `dockerls/infrastructure/`,
`dockerls/integrations/` e `dockerls/cli/` — a camada de interface chama-se
`cli`, não `interface`, e as integrações de rede vivem em `integrations/`,
não em `infrastructure/`.

**Decisão.** Mapear a especificação sobre a árvore existente:

| Especificação | Neste repositório |
|---|---|
| `domain/build/*` | `dockerls/domain/build/*` |
| `domain/templates/models.py` | `dockerls/domain/templates/models.py` |
| `application/*` | `dockerls/application/use_cases/*` |
| `infrastructure/docker/*` | `dockerls/infrastructure/docker/*` |
| `infrastructure/registry/*` | `dockerls/integrations/registry/*` (já existe) |
| `infrastructure/feeds/eol.py` | `dockerls/integrations/endoflife/` (já existe) |
| `interface/cli/*` | `dockerls/cli/commands/*` |

**Motivo.** Criar uma segunda árvore paralela partiria o projeto em duas
arquiteturas concorrentes. O invariante 6 manda reutilizar o que existe, e a
convenção do repositório vale mais que a nomenclatura do enunciado.

---

## D-002 — `dockerls build` já existe

**Ambiguidade.** A especificação pede "implementar `dockerls build`", mas o
comando **já existe** (`dockerls/cli/commands/build.py`,
`BuildImageUseCase`), com contrato próprio: `--validate-only`,
`--suggest-hardening`, `--hardened`, `--fail-on`, `--ci-mode`,
`--list-templates`, e exit codes 0/1/2 documentados no README.

**Decisão.** **Estender, não substituir.** As opções novas (`--dry-run`,
`--stack`, `--template`, `--platform`, `--fixable-only`, `--apply-vex`,
`--sbom`, `--output`, `--offline`, `--fix`) são acrescentadas ao comando
existente, preservando toda flag atual e o significado dos exit codes.

**Motivo.** Trocar o comando quebraria os pipelines de quem já usa
`--validate-only`/`--ci-mode`, e a especificação não pede quebra de
compatibilidade — pede capacidade nova. Um comando que muda de significado
sem aviso é exatamente a classe de defeito que este projeto vem corrigindo.

**Consequência registrada.** O `--fail-on` do `build` existente aceita
`critical|high|medium|low`; a especificação pede `none|critical|high|medium`.
Aceito a união: `none` passa a ser válido (equivale a não passar a flag) e
`low` continua válido. Nenhum valor antes aceito deixa de ser.

---

## D-003 — `Severity`: reutilizar o enum existente

**Ambiguidade.** A especificação declara `Severity` com valores minúsculos
(`"critical"`). O domínio já tem
`dockerls.domain.entities.vulnerability.Severity`, um `StrEnum` com valores
maiúsculos (`"CRITICAL"`), usado pelos scanners, pelo motor de score, pelos
exporters e pelo SARIF.

**Decisão.** Reutilizar o enum existente, sem introduzir um segundo.

**Motivo.** Invariante 6. Dois enums de severidade no mesmo processo é uma
fonte garantida de comparação silenciosamente falsa (`"critical" != "CRITICAL"`).
Onde a serialização precisar de minúsculas, a conversão é feita na borda.

---

## D-004 — `model_config = ConfigDict(frozen=True)` só nas entidades novas

**Ambiguidade.** O invariante 4 exige entidades de domínio congeladas. As
entidades existentes (`DockerImage`, `ScanResult`, `Vulnerability`) são
mutáveis, e há código que depende disso — `CrossValidator` escreve
`analysis.scan_divergence`, `_verify_tags` escreve `analysis.hub_url`.

**Decisão.** Toda entidade **nova** de domínio nasce `frozen=True`.
As existentes não são retrofitadas neste trabalho.

**Motivo.** Congelar as antigas quebraria caminhos em produção que hoje
funcionam, sem que a especificação peça essa mudança. Fica registrado como
dívida conhecida, não como omissão.

---

## D-005 — AST nova, sem aposentar o parser existente

**Ambiguidade.** Já existe `DockerfileParser` em
`dockerls/infrastructure/dockerfile_validator.py`, baseado em regex por
linha. A especificação exige explicitamente "AST própria (não regex de linha
solta)", com heredoc, `ARG` pré-`FROM`, stages nomeados e `COPY --from`.

**Decisão.** Criar `dockerls/domain/build/dockerfile_ast.py` como parser
novo e puro, e **manter** o parser antigo servindo `analyze-dockerfile`.

**Motivo.** O parser antigo tem 30 testes verdes cobrindo o comportamento de
`analyze-dockerfile`; trocá-lo por baixo seria uma migração não pedida com
risco de regressão. Os dois coexistem até que uma migração explícita seja
solicitada. A duplicação está consciente e registrada aqui.

---

## D-006 — O guard de código morto do projeto governa a ordem de construção

**Ambiguidade.** `tests/unit/test_no_dead_configuration.py` reprova qualquer
símbolo público que nada no pacote alcance. Durante uma construção em
camadas, o módulo de baixo nasce antes do seu consumidor — e fica
temporariamente "morto" pelo critério do guard.

**Decisão.** Não enfraquecer o guard nem adicionar allowlist. Em vez disso:
**nenhum helper é escrito antes do seu consumidor.** Helpers já removidos por
esse critério, para voltar junto com quem os usa:

| Símbolo | Volta no passo |
|---|---|
| `Stage.base_tag` | 4 — resolução de base |
| `BaseCandidate.pinned_reference` | 4 — pin por digest |
| `BaseCandidate.blocking_count` | 7 — motor de política |
| `RuleFinding.location` | 8 — renderização |
| `BuildPlan.manual` | 8 — renderização |
| `compute_cve_delta` | 8 — relatório |

**Motivo.** O guard existe porque este projeto já entregou cinco vezes algo
declarado, documentado e nunca alcançado. Contorná-lo durante a construção é
como a sexta vez começaria. Enquanto o consumidor não existe, o símbolo não
existe.

**Estado atual.** `domain/build/rules.py` e `check_all` ainda não têm
chamador — a wiring do `--dry-run` na CLI é o próximo passo, e é ela que
fecha essa pendência. Enquanto isso, os dois testes do guard estão
**vermelhos de propósito**, e é a primeira coisa a corrigir na próxima
iteração. Nenhum stub silencioso foi criado para escondê-los.

---

## D-007 — A abstração multi-source estende `ImageRepositoryInterface`

**Ambiguidade.** O enunciado pede um `Protocol` novo (`ImageSource`) com
`search`, `resolve`, `get_metadata` e `verify`.

**Decisão.** Não criar um segundo protocolo. `ImageRepositoryInterface` +
`CompositeImageRepository` **já são** a abstração multi-source: interface no
domínio, implementações em `integrations/`, fan-out concorrente com
degradação por fonte. O que faltava não era a interface, era um **registro
nomeado** — que fosse capaz de mapear `--source dhi` para um provedor sem
espalhar `if source == ...`. Foi isso que se acrescentou
(`application/services/source_registry.py`).

**Motivo.** Um segundo protocolo obrigaria todo provedor existente a
implementar as duas faces, ou obrigaria a um adaptador por provedor. Nenhum
dos dois compra capacidade nova: `resolve`/`verify` do enunciado já existem,
como `RegistryInspector` (digest + config) e como `tag_exists`, e ambos
servem a *todas* as fontes em vez de serem reimplementados em cada uma.

---

## D-008 — Scores calculados sobre os fatos determinados, não sobre um denominador fixo

**Ambiguidade.** O enunciado descreve o Hardening Score como uma soma de
pesos fixos (`Non-root +20`, `No shell +15`, ...), o que implica um
denominador constante.

**Decisão.** O denominador é o peso dos fatores **efetivamente
determinados**, e o valor vem acompanhado de `coverage` (quanto do modelo
isso representa) e de `reportable` (falso abaixo de 25%, quando o número
passa a ser exibido como `n/a`).

**Motivo.** Com denominador fixo, uma imagem excelente que ninguém conseguiu
inspecionar pontua trinta e poucos — e esse número é lido como veredito de
hardening, quando na verdade mede a *nossa* falta de acesso. A maior parte
dos fatos do modelo (SUID, shell, gerenciador de pacotes) não é determinável
sem desempacotar o filesystem, coisa que este projeto não faz. Um score que
diz "100 com 31% de cobertura" é verdadeiro e útil; um que diz "34" é falso
e prejudicial. A regra que isso preserva é a mesma do resto do projeto:
**não medido nunca vira medição ruim**, do mesmo jeito que scan falho nunca
vira zero CVE.

**Consequência registrada.** Cobertura passa a ser um insumo de
`Confidence`, e o ranking só consulta hardening quando `reportable` é
verdadeiro — senão um 100 tirado de um fato ganharia de um 85 medido de
verdade.

---

## D-009 — Fatos de imagem são de três estados, e `unknown` não é `false`

**Ambiguidade.** O enunciado pede campos como `has_shell`, `runs_as_non_root`
e `is_distroless`, e diz que o valor deve ser `unknown` quando indeterminado.

**Decisão.** `Tristate` (`TRUE`/`FALSE`/`UNKNOWN`) no domínio, usado em todo
fato de hardening, com uma assimetria explícita na inferência: a presença de
um pacote de shell **prova** shell; a ausência não prova nada e permanece
`UNKNOWN`.

**Motivo.** Um `bool` faz o caminho errado ser o caminho fácil: `not
has_shell` transforma "ninguém olhou" em "não tem shell", e isso vira
crédito num score. A assimetria existe porque uma base derivada de busybox
traz `/bin/sh` sem nomear pacote nenhum — concluir `false` por ausência
seria uma afirmação de hardening que nenhuma evidência sustenta.

**Consequência registrada.** Nome de imagem **nunca** é evidência.
`DockerImage.is_distroless`/`is_alpine`/`is_hardened_source` continuam
existindo e continuam alimentando o bônus qualitativo (mínimo, e limitado
abaixo de um único HIGH) do `SecurityScore` legado, mas não alimentam nem o
Hardening Score nem o Attack Surface Score: lá só entra o que o registry, o
scanner ou uma declaração auditável disseram.

---

## D-010 — DHI é fonte opt-in, e um candidato não escaneável é `UNVERIFIED`

**Ambiguidade.** O enunciado trata DHI como mais um catálogo a fanar por
padrão.

**Decisão.** `dhi` fica **desligado** por padrão (`include_dhi_source =
false`), ligável por execução com `--source dhi`/`--all-sources`.

**Motivo.** `dhi.io` recusa pull anônimo — verificado durante a auditoria: o
endpoint de token responde 401 sem credencial. Numa máquina sem
entitlement, ligar DHI por padrão produziria uma coluna de `UNVERIFIED` em
toda execução, que é *correto* mas ruidoso, e gastaria scans que falham em
cima de candidatos que não podem entrar na tabela. Com credencial
configurada, uma flag liga tudo.

**O que não muda:** metadado de catálogo continua não sendo veredito. Uma
definição DHI que declare `run-as: node` não torna a imagem não-root aos
olhos do DockerLs; se o registry servir o config e ele disser `root`, vale o
config, e a contradição é registrada como achado.

---

## D-011 — Bomba YAML: medir a expansão, não contar aliases

**Ambiguidade.** Nenhuma: o enunciado só exige "parsing seguro" e proíbe
`yaml.load`.

**Decisão.** Além de `SafeLoader` e do teto de bytes, o documento é
**composto** num grafo de nós (onde alias é aresta compartilhada), o tamanho
expandido é calculado sobre esse grafo com memoização e clamp, e só então
`construct_document` roda.

**Motivo.** A primeira implementação contava aliases no texto cru, e o teste
adversarial derrubou essa premissa: a bomba clássica (nove níveis de
aliasing nônuplo) usa ~70 aliases — abaixo de qualquer limite razoável — e
expande para 387 milhões de nós. O guard passava e o parser travava. O que
precisa ser limitado é o **produto**, não a contagem. Fica registrado porque
o erro é sedutor: um limite de aliases *parece* proteger e não protege.

**Consequência registrada.** O teste afirma o tempo de recusa, não só a
exceção. Um guard que recusa depois de expandir executou o ataque em vez de
impedi-lo, e só o tempo distingue os dois casos.

---

## D-012 — `ProductionReadiness` é uma política central, não uma propriedade do tier

**Ambiguidade.** `production_ready` já existia como propriedade de
`SecurityTier`, e a regra parecia completa: tier A/B e não-EOL.

**Decisão.** Criar `domain/value_objects/production_readiness.py` como
**única** fonte do veredito, consumindo tier, confidence, verificação do
scan, EOL tri-state, contagens e divergência material. `ImageAnalysis.
production_ready` passa a ser escrito só por ela, e o default do campo virou
`False`.

**Motivo.** O tier enxerga o score e nada mais. Ele não sabe se o scan
terminou — então um scan `PARTIAL` sem achados nos alvos que conseguiu ler
produzia score alto, tier A e `production_ready = True`, na mesma análise que
reportava `confidence = UNVERIFIED`. Uma análise que afirma as duas coisas é
pior que uma que não afirma nenhuma, e o campo contraditório é justamente o
que um portão de CI lê.

**Consequência registrada.** O default `False` é deliberado: uma análise que
nunca passou pela política não é "pronta por omissão". `SecurityTier.
production_ready` continua existindo como a regra de nível de tier que a
política consome, com um docstring dizendo, com todas as letras, que não é o
veredito.

---

## D-013 — Confiança mínima para produção é MEDIUM, não HIGH

**Ambiguidade.** Se `HIGH` exige validação cruzada, exigir `HIGH` para
produção parece a leitura mais segura.

**Decisão.** O piso é `MEDIUM`.

**Motivo.** `HIGH` requer um segundo scanner. Exigir isso transformaria o
veredito numa afirmação sobre o *toolchain do operador* em vez de sobre a
imagem: numa máquina com só o Trivy instalado, nenhuma imagem do mundo seria
production ready, e o campo perderia sentido. `MEDIUM` já exige scan
concluído, sem divergência material e com referência fixada ou confirmada —
que é evidência suficiente para uma decisão, com as lacunas nomeadas ao lado.

---

## D-014 — Ausência de dado nunca vira dado favorável (EOL, KEV, EPSS)

**Ambiguidade.** As três integrações externas degradavam "para não quebrar o
scan" — `is_eol` devolvia `False`, o KEV devolvia conjunto vazio, o EPSS
devolvia dicionário vazio.

**Decisão.** Cada uma passa a distinguir *consultado* de *não consultado*:
`eol_status` tri-state, `kev_status` tri-state, `epss_known`.

**Motivo.** Degradar para "sem sinal" é correto para o *fluxo*; o erro estava
em traduzir "sem sinal" como "sem risco". O caso mais grave era o KEV: com o
catálogo fora do ar, todo CVE ficava `exploit_known=False` e o relatório
imprimia, afirmativamente, `no known-exploited (CISA KEV) vulnerabilities` —
a frase mais forte que a ferramenta produz sobre exploração real, emitida
exatamente quando nada foi consultado.

**Consequência registrada.** A frase afirmativa agora nomeia quantos achados
foram de fato checados. `UNKNOWN` não penaliza o score (não há evidência de
risco) e também não credita (não há evidência de segurança): aparece nos
trade-offs e limita a confiança.

---

## D-015 — Política de rede: bloquear loopback e link-local, permitir RFC1918

**Ambiguidade.** Uma referência de imagem carrega um hostname e é entrada do
usuário. Bloquear tudo que é privado fecha o SSRF; também quebra todo
registry interno, que é infraestrutura legítima e comum.

**Decisão.** Padrão: **loopback e link-local bloqueados**, **RFC1918
permitido**. Ambos configuráveis, com allowlist de hosts vencendo os dois.
A decisão é tomada por **resolução**, não por grafia, e *todos* os endereços
que um nome resolve precisam passar.

**Motivo.** `169.254.0.0/16` é onde os provedores servem credencial de
instância — não existe registry legítimo ali, e é o alvo real. Loopback é o
caminho para serviços do próprio runner. Já `10.x`/`192.168.x` é onde os
registries internos de verdade moram, e uma ferramenta que não consegue olhar
para `registry.internal:5000` não é usável. Julgar por resolução fecha o
caso em que um nome inócuo aponta para 127.0.0.1 — e exigir que *todos* os
endereços passem fecha o rebinding, em que uma resposta pública e uma
loopback chegam juntas.

**Consequência registrada.** A regra vive no domínio e a resolução DNS na
infraestrutura, porque o guarda de arquitetura proíbe `socket` em `domain/` —
e ele está certo: essa separação é o que permite testar a política inteira
contra literais de endereço, sem rede.

---

## D-016 — Cross-validation compara identidade de achado, não contagem

**Ambiguidade.** A comparação por contagem de CRITICAL/HIGH já existia e
funcionava para o caso óbvio (0 vs 5).

**Decisão.** Comparar conjuntos de `CVE|pacote` por faixa de severidade, e
classificar o desfecho em `AGREEMENT` / `MINOR_DIVERGENCE` /
`MATERIAL_DIVERGENCE` / `NO_SECOND_SCANNER`.

**Motivo.** Contagem aceitava um caso que não deveria: dois scanners
reportando **um** CRITICAL cada, para CVEs completamente diferentes,
concordavam perfeitamente na aritmética enquanto descreviam imagens
diferentes. A versão está no `AUDIT.md` (F12) e o caso vira teste.

**Consequência registrada.** Divergência *menor* passou a existir como
categoria própria: duas bases de vulnerabilidade legitimamente diferem nas
margens, e chamar isso de "disputado" faria toda imagem parecer contestada.
Ela não refuta o resultado — só impede que a confiança chegue a `HIGH`.
`scan_divergence`, que a tabela e os exporters já liam, continua reservado ao
caso material.

---

## D-017 — O que é evidência é redigido, não só o que é log

**Ambiguidade.** O mascaramento de segredos já existia e era bom; morava
dentro do sink de log.

**Decisão.** Extrair para `infrastructure/redaction.py` e aplicar também aos
artefatos brutos de scan e ao manifesto.

**Motivo.** O log é o arquivo que ninguém abre; a evidência é o arquivo que
as pessoas anexam a ticket e colam em chat. Um scanner que falha um pull
autenticado ecoa a requisição que tentou, cabeçalhos inclusos — e isso ia
para o disco sem passar por padrão nenhum. Um redator, duas portas.

**Consequência registrada.** A redação não pode destruir diagnóstico: há
teste afirmando que CVE, pacote, versão instalada e versão corrigida
sobrevivem intactos.

---

## D-018 — Toda regra cita o controle publicado, ou admite que não tem um

**Ambiguidade.** `analyze-dockerfile` sempre respondeu com um código: `DF002
falhou`. Esse código não significa nada fora deste repositório. Quem recebe o
achado não tem como saber se a regra é um requisito publicado ou a preferência
de um mantenedor, e um auditor que precisa mapear achados para um framework de
conformidade faz isso à mão, a partir do texto da mensagem.

**Decisão.** Um catálogo em `domain/security_controls.py` liga cada regra
DF001–DF012 aos controles que ela implementa (CIS Docker Benchmark, NIST SP
800-190, OWASP Docker Security Cheat Sheet, documentação da Docker,
especificação OCI), com uma justificativa em nossas próprias palavras num campo
separado. As citações aparecem no terminal e no JSON, e o comando `dockerls
controls` expõe o catálogo inteiro.

**Motivo.** Um achado que cita *CIS Docker Benchmark 4.1* pode ser discutido,
escalado, dispensado com justificativa e mapeado para um programa de auditoria.
Um achado que cita `DF002` só pode ser obedecido ou ignorado. A diferença é
quem carrega o ônus da prova.

**Consequência registrada — a citação é conferida, não lembrada.** Todo
identificador e todo título foi verificado na fonte primária. Isso não foi
cerimônia: **três das quatro citações rascunhadas de memória estavam erradas**.
`NIST SP 800-190 4.4.2` é *Unbounded network access from containers*, não
"least privilege"; `OWASP RULE #8` é *Set filesystem and volumes to read-only*,
não "minimal base images". Uma ferramenta que se recusa a reportar uma contagem
de vulnerabilidades que não mediu não pode citar um controle que não conferiu —
é o mesmo princípio, aplicado à outra metade do relatório.

**Consequência registrada — o título é citado, não parafraseado.** `Control.title`
guarda a redação da fonte. Parafrasear tornaria a citação impossível de
localizar, o que anula a razão de existir dela. Por isso `rationale` mora num
campo separado: o controle diz *o quê*, nós dizemos *por quê*, e a separação é
o que impede que a paráfrase seja lida como citação.

**Consequência registrada — ausência de controle é declarada.** Onde nenhum
controle publicado cobre a regra, `controls_for` devolve tupla vazia e os
renderizadores dizem que a orientação é do próprio DockerLs. Inventar um número
plausível seria pior que não ter nenhum: é o tipo de erro que sobrevive à
revisão, porque parece exatamente com o acerto. Um teste garante que toda regra
emitida pelo validador está catalogada e que nenhuma regra catalogada é órfã,
de modo que a divergência aparece como falha e não como citação faltando em
silêncio.

---

## D-019 — A política de rede vale para toda conexão, não só para as nossas

**Ambiguidade.** `NetworkPolicy` foi escrita pensando nas requisições que este
processo faz com `httpx`. Mas `trivy image X` também é uma conexão que este
processo causa — só que aberta por um filho.

**Decisão.** Verificar o alvo contra o `HostGuard` antes de invocar o binário,
nos dois scanners, e recusar com `ERROR` / `BLOCKED_BY_POLICY`.

**Motivo.** A pergunta que a política responde não é "quem abriu o socket", é
"para onde uma referência não confiável consegue apontar esta máquina". Pelo
critério errado, a defesa cobria a porta que era fácil de ver.

**Consequência registrada — a recusa é ausência de medição, não medição limpa.**
Zero vulnerabilidades com status `ERROR` é o mesmo estado que um scan que deu
timeout, e o pipeline inteiro já trata não-medido como não-verificado. Um teste
fixa isso explicitamente, porque a alternativa (devolver `SUCCESS` com lista
vazia) seria a exata substituição que este projeto recusa em todo lugar.

**Consequência registrada — `BLOCKED_BY_POLICY` não é culpa do scanner.** O
`FallbackScanner` tenta a segunda ferramenta quando a primeira falha por
motivo próprio. Um host recusado não é isso: o grype puxaria do mesmo lugar.
Marcar como falha de scanner gastaria o dobro do tempo para chegar à mesma
recusa.

**Consequência registrada — uma única definição de "host de registry".** A
regra estava em duas cópias e as duas erravam em `localhost`. Agora
`DockerImage.registry_host` delega para o domínio. Duas cópias de uma regra de
segurança não divergem em teoria — elas divergem exatamente no caso que
importa.

## D-020 — Um documento de procedência não se auto-aprova

**Contexto.** O `build --provenance` grava um JSON com os digests de entrada e
saída do build, e um campo `status` calculado na hora. O passo seguinte natural
— um workflow que decide se assina o artefato — leria esse campo.

**Decisão.** `dockerls provenance` **recalcula** o status a partir dos digests
e ignora o que está gravado. O campo `"status": "VERIFIED"` num arquivo JSON é
editável por qualquer pessoa com um editor de texto; a comparação entre
`source` e `source_after_build` não é.

**Consequência.** O `from_dict` precisa reconstruir o documento inteiro em vez
de ler um resumo, e qualquer campo ilegível leva a `INCOMPLETE` — nunca a
`VERIFIED` por omissão. É o mesmo princípio que governa o resto da ferramenta:
o que não pôde ser verificado não é apresentado como verificado.

**Alternativa recusada.** Assinar o documento junto do artefato e verificar a
assinatura. Resolve a adulteração, mas não a pergunta que importa — um
documento íntegro pode descrever um build cuja entrada mudou no meio do
caminho, e é esse caso que o recálculo pega.

## D-021 — O sujeito da atestação sai do documento, nunca do YAML

**Contexto.** `actions/attest-build-provenance` precisa de `subject-name` e
`subject-digest`. O caminho óbvio é escrevê-los no workflow.

**Decisão.** `--github-output` extrai os dois do documento de procedência e os
publica em `$GITHUB_OUTPUT`. O workflow referencia a saída do passo, não uma
string literal.

**Consequência.** A atestação fala necessariamente da mesma imagem que o scan
mediu. Um digest redigitado à mão é onde a cadeia arrebenta em silêncio: a
assinatura continua criptograficamente válida enquanto cobre bytes que ninguém
escaneou, e nada no processo acusa.

## D-022 — Podar o histórico nunca faz uma tag parecer mais estável

**Contexto.** O histórico de digests por tag tem teto (`MAX_OBSERVATIONS`). A
poda óbvia — descartar as observações mais antigas — faria a contagem de
movimentos regredir.

**Decisão.** A primeira observação é preservada (ela ancora o "desde quando") e
o que cai vira contagem em `dropped`, que soma em `moves`.

**Consequência.** Um campo a mais no formato serializado. Em troca, a tag que
mais muda — justamente a que estoura o teto e a que mais importa — não aparece
como a mais estável de todas no instante em que passa do limite.

## D-023 — Comparar duas receitas descreve trocas, não elege vencedora

**Contexto.** `base-image --compare` mostra a diferença entre duas receitas de
imagem base. Seria fácil (e vendável) coroar a de menor superfície.

**Decisão.** O diff descreve o que entra, o que sai e o que cada troca custa, e
termina mandando escanear as duas.

**Consequência.** A pessoa ainda precisa construir e medir para decidir. É o
custo de não mentir: contar pacotes não mede vulnerabilidade — uma base com
menos pacotes e um deles desatualizado é pior que uma com mais pacotes e todos
corrigidos, e um número que ignora isso seria apresentado como medida sem ser
uma.

## D-024 — Política malformada é erro; regra de ignore malformada é silêncio

**Contexto.** `.dockerls-ignore.yaml` degrada para "nenhuma regra" quando não
carrega. O `.dockerls-policy.yaml` poderia seguir a mesma convenção.

**Decisão.** Não segue. Chave desconhecida, tipo errado, severidade inexistente
e arquivo vazio **encerram o comando**.

**Consequência.** A direção da falha é o que decide. Uma regra de ignore que
não carrega deixa de esconder uma CVE: o resultado é mais alarme, e alarme a
mais é seguro. Uma regra de política que não carrega deixa de exigir alguma
coisa, e o build passa parecendo ter sido conferido. `require_non_root` no
lugar de `require_nonroot` seria um portão aberto com cara de fechado, e
ninguém descobre isso olhando uma saída verde.

**Alternativa recusada.** Avisar e seguir. O aviso vira ruído no log de CI em
duas semanas, e o portão continua desligado.

## D-025 — Entre a política e a linha de comando, vence a mais estrita

**Contexto.** `fail_on` pode vir do `.dockerls-policy.yaml` e do `--fail-on`.
Alguma das duas precisa ganhar.

**Decisão.** Vence a mais estrita, venha de onde vier.

**Consequência.** Um arquivo no repositório não desliga um portão que o
pipeline pediu — senão bastaria commitar um YAML para publicar o que não
passaria. E um pipeline não afrouxa a política da organização passando uma
flag. Nenhum dos dois lados pode relaxar o outro; ambos podem apertar.

## D-026 — A política só contém regras mensuráveis

**Contexto.** Uma política de segurança "completa" naturalmente incluiria
coisas como "não use pacotes inseguros" ou "mantenha a imagem enxuta".

**Decisão.** Só entra regra decidível a partir do que este build mediu.

**Consequência.** A lista é curta e cada regra aponta para uma medição
específica. Uma regra que não pode ser avaliada é uma regra que reprova por
engano ou aprova por omissão, e as duas corroem a confiança no portão até
alguém desligá-lo inteiro.

## D-027 — A varredura de frota nunca fala sobre vulnerabilidade

**Contexto.** `dockerls fleet` percorre uma árvore e resume o estado dos
Dockerfiles. A palavra "frota" convida a chamar isso de auditoria de segurança.

**Decisão.** Não é. O relatório diz, na própria saída, que leu Dockerfiles e não
construiu imagem nem chamou scanner, e nenhuma métrica dele fala de CVE.

**Consequência.** Quem quiser o número de vulnerabilidades ainda precisa
construir e escanear cada imagem. É o custo de não converter "li o arquivo" em
"medi a imagem" — a mesma substituição que esta ferramenta recusa em todo lugar.

## D-028 — Na frota, a política aplicada é o subconjunto estático

**Contexto.** A varredura não constrói nem escaneia, então `require_scan` e
`max_vulnerabilities` violariam em todo arquivo.

**Decisão.** `BuildPolicy.static_subset()` remove as regras que dependem de
medição, e a saída diz que fez isso.

**Consequência.** As regras removidas **não** são consideradas cumpridas — elas
continuam valendo no `build`, que é onde há medição. Uma lista em que tudo está
vermelho pela mesma razão não distingue nada, e a fila de trabalho deixaria de
ser fila.

## D-029 — Symlink não é seguido, e o truncamento é dito em voz alta

**Contexto.** Percorrer uma árvore arbitrária no disco de outra pessoa.

**Decisão.** Symlinks são ignorados; há teto de arquivos e de profundidade; e o
relatório carrega `truncated` quando qualquer um deles é atingido.

**Consequência.** Um link para `/` num repositório não transforma a varredura
numa varredura da máquina inteira, e um retrato parcial nunca se apresenta como
completo. Em troca, um repositório que usa symlink para compartilhar
Dockerfiles entre pastas terá o arquivo contado uma vez só — o que é o
comportamento correto, e não uma limitação.

## D-030 — Assinante ausente não é imagem não assinada

**Contexto.** `cosign` pode não estar instalado, pode falhar por rede, ou pode
responder que não há assinatura. Um booleano colapsaria os três.

**Decisão.** `SignatureStatus` tem cinco valores e `is_conclusive` separa
veredito de falha do medidor. `dockerls verify` sai `0`, `2` e `1`
respectivamente.

**Consequência.** Um pipeline consegue tratar "esta imagem não está assinada"
de forma diferente de "não deu para conferir". Sem isso, uma máquina sem cosign
reprovaria toda imagem da organização — e a resposta previsível seria desligar
a checagem.

## D-031 — Só se assina por digest, e só com procedência verificada

**Contexto.** `--sign` roda depois do push, e a tag está ali à mão.

**Decisão.** A referência assinada é sempre `repositório@sha256:...`, com a tag
removida; e a assinatura é recusada quando a procedência não é `VERIFIED`.

**Consequência.** Uma assinatura aponta para bytes e diz "eu publiquei isto".
Assinar uma tag assinaria o que ela aponta naquele instante, e a assinatura
seguiria válida depois que a tag mudasse. Assinar sem procedência seria
carimbar um artefato cuja entrada ninguém conseguiu fechar — o carimbo é
exatamente o que uma assinatura não pode ser.

## D-032 — `base --alternatives` mede e propõe; não aplica

**Contexto.** O `base` já reescreve o Dockerfile para atualizar digests. Seria
coerente reescrever também para trocar a base por uma melhor.

**Decisão.** Não reescreve. As alternativas são impressas com os deltas
medidos e os trade-offs; a troca é do humano.

**Consequência.** Uma pessoa ainda precisa editar o arquivo. É o correto:
atualizar um digest preserva libc, shell, usuário e gerenciador de pacotes,
enquanto trocar a família muda todos os quatro. As duas coisas cabem no mesmo
comando; não cabem na mesma automação.

## D-033 — A auditoria de registry para no que o OCI revela

**Contexto.** Uma "auditoria de endurecimento de registry" completa leria
políticas de retenção, IAM e content trust de ACR, GAR e GHCR — cada um com
sua API e sua credencial.

**Decisão.** O comando usa só o protocolo OCI, sem credencial de nuvem, e a
saída declara o que não leu.

**Consequência.** O relatório é menor e roda em qualquer lugar, inclusive
contra um registry de terceiro. A parte que depende de credencial continua sem
resposta — e dizer isso é melhor do que uma checagem por provedor que ninguém
consegue exercitar e que apodrece na primeira mudança de API.

## D-034 — Acesso público é relatado, nunca alertado

**Contexto.** O comando descobre, como efeito de conseguir resposta anônima,
que uma imagem é legível por qualquer pessoa.

**Decisão.** O achado entra no relatório marcado como informativo, e não conta
como alerta nem afeta o exit code.

**Consequência.** "Público" é o estado correto de uma imagem base oficial e o
estado errado de um artefato interno. A diferença é a intenção de quem
publicou, e essa esta ferramenta não tem como medir. Alertar seria afirmar uma
intenção; relatar entrega o fato a quem sabe qual era.

## D-035 — "Mais estrito" é o limiar mais baixo, não a palavra mais grave

**Contexto.** D-025 decidiu que, entre o `fail_on` da política e o da linha de
comando, vence o mais estrito. A implementação ordenava as severidades por
gravidade e escolhia o mínimo — devolvendo `critical` quando um dos lados
pedia `high`.

**Decisão.** A ordenação do portão é a que vale: `--fail-on low` reprova em LOW
e em tudo acima, então `low` é o limiar mais exigente e `critical` o mais
brando. A escolha passa a ser o índice máximo em `GATE_THRESHOLDS`.

**Consequência.** Uma política `fail_on: high` deixa de ser silenciosamente
relaxada por um pipeline que passa `--fail-on critical`. Era o caso exato que
D-025 existia para impedir, invertido — e nada na saída acusava, porque o
build passava.

## D-036 — Sem os dois scans não há atribuição

**Contexto.** `--attribute` divide os achados entre os que vieram da base e os
que vieram das suas camadas. Se a base não escaneia, seria fácil listar tudo
como "seu".

**Decisão.** O relatório fica `UNAVAILABLE` com o motivo, e nenhuma contagem é
apresentada.

**Consequência.** Quem quer a divisão precisa de uma base escaneável. Em troca,
o relatório nunca acusa o Dockerfile de alguém por causa de um scanner que não
rodou — nem, na direção oposta, absolve o build atribuindo tudo à base.

## D-037 — O perfil de produção tem nome, e diz o que ligou

**Contexto.** Uma imagem publicada precisa de sete coisas ao mesmo tempo. A
alternativa a nomeá-las é uma lista de flags que cada pipeline redigita.

**Decisão.** `--production` liga o conjunto e **imprime cada regra que ligou**;
um `.dockerls-policy.yaml` do contexto é somado, sempre pelo lado mais estrito.

**Consequência.** A omissão vira uma decisão visível (`--no-policy`,
`--fail-on` explícito) em vez de um esquecimento invisível. E um perfil que
muda o comportamento em silêncio seria descoberto pelo build reprovando — cuja
primeira reação é desligar o portão.

**Alternativa recusada.** `fail_on: high` no perfil. Um perfil que ninguém
consegue cumprir é um perfil que as pessoas desligam inteiro, e `high` reprova
praticamente toda base Debian num dia qualquer. O teto de HIGH fica declarado à
parte, onde se enxerga e se discute.

## D-038 — A poda do contexto acontece na descida

**Contexto.** `hash_context` percorria a árvore com `rglob("*")` e descartava
depois o que o `.dockerignore` excluía.

**Decisão.** Diretórios ignorados não são percorridos; a ordenação final
continua sobre os caminhos completos.

**Consequência.** Num contexto de 52.400 arquivos em que 401 são enviados ao
daemon, 0,84 s viraram 0,013 s — e o digest é byte a byte o mesmo, o que é o
que torna a mudança segura: documentos de procedência antigos continuam
comparáveis com novos.

## D-039 — Origem sem "tem correção?" ainda não é um plano

**Contexto.** A atribuição divide os achados entre os que vieram da base e os
que vieram das suas camadas. Parecia resposta suficiente.

**Decisão.** Não é. O plano cruza origem com a existência de correção
publicada, produzindo quatro grupos com quatro ações distintas.

**Consequência.** "41 vêm da base" leva a "atualize a base" — que é trabalho
perdido se nenhuma das 41 tiver correção publicada. Só a segunda dimensão
separa "atualizar" de "trocar", e são semanas de trabalho diferentes.

## D-040 — "Pode resolver", nunca "resolve"

**Contexto.** Um achado herdado com `fixed_version` preenchido convida a dizer
que atualizar a base o elimina.

**Decisão.** O texto diz que atualizar **pode** resolver, e explica por quê: a
correção existir upstream não significa que quem publica a base já reconstruiu
com ela.

**Consequência.** O conselho fica menos vendável e continua verdadeiro. É como
uma ferramenta perde a confiança de quem seguiu a recomendação, reconstruiu, e
viu o mesmo número — uma vez basta para ninguém mais ler a seção.

## D-041 — O portão só fala de origem quando mediu origem

**Contexto.** A linha que reprova o build é o texto mais lido de toda a
ferramenta, e enriquecê-la com a origem dos achados é tentador mesmo sem
`--attribute`.

**Decisão.** Sem atribuição disponível, a linha não menciona origem.

**Consequência.** Quem não pediu `--attribute` vê a mensagem antiga. Em troca,
a frase sobre origem, quando aparece, é sempre medida — um portão que insinua
uma origem que não mediu é pior do que um portão calado, porque manda alguém
mexer no lugar errado com a autoridade de quem mediu.
