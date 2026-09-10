# DockerLs Security Decision Engine — auditoria de estado

**Data:** 2026-09-10  
**Método:** leitura estática dos fluxos Python/Go, testes, benchmarks e workflows,
antes da alteração P0 descrita no fim deste documento. “Parcialmente” significa
que existe uma implementação útil, mas não cobre todo o contrato solicitado.

## Arquitetura e fluxos encontrados

| Área | Estado | Evidência e lacuna principal |
|---|---|---|
| `dockerls analyze` | **EXISTE** | CLI em `cli/commands/analyze.py`; `AnalyzeImageUseCase` obtém metadata, escaneia, enriquece, consulta EOL, pontua, coleta hardening/histórico e aplica o verdict. |
| Recomendação | **EXISTE** | `RecommendImagesUseCase`: prepara DB e descobre tags em paralelo, limita o plano, resolve digests, consulta cache, escaneia/deduplica, enriquece, filtra baseline, valida finalistas e produz evidência. |
| Trivy | **EXISTE** | Scanner Python e orquestração Go, argv sem shell, timeout, limite de saída, parser defensivo, evidence store, DB compartilhada e batch. |
| Grype | **EXISTE** | Scanner Python e Go, fallback/cross-validation, timeout, parser defensivo e atualização única da DB. |
| Cache SQLite (L2) | **PRECISA SER REFATORADO** | Upsert concorrente, TTL, schema e validação existem; a chave aceitava referência mutável quando o digest faltava e não incluía plataforma. Corrigido neste grupo P0. |
| Engine Go | **EXISTE** | Hot path restrito ao fan-out de scanners; protocolo JSON, deduplicação, testes/race e benchmark próprios. Python mantém regras de negócio. |
| OCI/digest | **EXISTE PARCIALMENTE** | Resolve manifestos, seleciona `linux/amd64`, verifica digest do config e deduplica. Plataforma é fixa no inspector e ainda não é opção explícita do usuário. |
| Rate limiting | **EXISTE PARCIALMENTE** | Limitador e retries existem; não há controlador AIMD adaptativo por provider com telemetria de latência. |
| Circuit breaker | **EXISTE PARCIALMENTE** | Clientes hardened reutilizam retry/limites, mas não há uma máquina de estados uniforme por provider cobrindo todos os clientes. |
| Evidence store | **EXISTE** | Evidência e manifesto são limitados, redigidos, atômicos e vinculam scanner/digest quando conhecidos. |
| HostGuard / rede | **EXISTE** | Resolução DNS, políticas para loopback/link-local/private, validação a cada hop e clientes guardados; scanners também validam o alvo antes do subprocesso. |
| SBOM | **EXISTE PARCIALMENTE** | Comando/geração Trivy, CycloneDX/SPDX e validação existem; não há cache reutilizável por digest+plataforma+gerador+versão. |
| KEV / EPSS / EOL | **EXISTE** | Tri-state para ausência de KEV/EOL, EPSS com proveniência, parsing defensivo e freshness de DB separado. |
| Policy engine | **EXISTE PARCIALMENTE** | Gates, build policy e policy file validado existem; ainda não há DSL única de `block/warn/require` para todas as evidências. |
| Testes | **EXISTE** | Unitários, integração, aceitação, adversariais e Hypothesis cobrem parsers, SSRF, subprocessos, falhas e cache. |
| Benchmarks | **EXISTE PARCIALMENTE** | Discovery, multi-source, fan-out e recursos existem; falta baseline versionada com mediana e thresholds de regressão em CI. |
| CI | **EXISTE PARCIALMENTE** | Ruff, mypy, pytest/coverage, Go race/vet, Bandit, pip-audit, CodeQL e Trivy. Nem todas as Actions estão pinadas por SHA e faltam dependency-review/proveniência de release. |

## Matriz das fases solicitadas

| Fase / requisito | Estado antes deste grupo | Prioridade / conclusão |
|---|---|---|
| 1. Identidade canônica e cache determinístico | **PRECISA SER REFATORADO** | **P0:** digest já dominava quando presente, mas fallback por tag e ausência de plataforma quebravam a identidade. Implementado neste grupo. DB fingerprint ainda precisa granularidade maior. |
| 2. Cache L1 + L2 e métricas separadas | **EXISTE PARCIALMENTE** | **P1:** inspector tem L1 por execução e SQLite é L2; métricas não separam L1 hit/miss de L2 hit/miss. |
| 3. Single-flight | **EXISTE** | Locks por chave no inspector e no scan impedem trabalho duplicado e são removidos com o ciclo do objeto; testes concorrentes existem. |
| 4. Pipeline cheap → expensive | **EXISTE** | Planejamento, pin/dedup/cache precedem scan; inspeção/cross-validation só ocorre em finalistas, sem declarar candidatos não medidos seguros. |
| 5. Modos fast/balanced/paranoid | **EXISTE PARCIALMENTE** | Scanner primário, fallback e cross-validation existem, mas não como contrato CLI explícito de três modos. **P1**. |
| 6. Finding normalizado | **EXISTE PARCIALMENTE** | `Vulnerability` normaliza ambos scanners e conserva fontes; identidade ainda precisa ecossistema/distribuição na chave. **P1**. |
| 7. Reconciliação | **EXISTE** | Compara CVE+pacote, conserva secondary scan, classifica divergência determinística e alimenta confiança. |
| 8. Estados precisos | **EXISTE PARCIALMENTE** | Scan operacional tem OK/ERROR/TIMEOUT/PARTIAL; confidence/readiness são separados. Vocabulário final ainda não expõe exatamente PASS/BLOCK/REVIEW/UNKNOWN. |
| 9. Freshness da DB | **EXISTE PARCIALMENTE** | FRESH/AGING/STALE/UNKNOWN e metadata limitada existem e o doctor reporta; freshness ainda não integra consistentemente cache/verdict. **P0/P1 remanescente**. |
| 10. Concorrência adaptativa | **NÃO EXISTE** | Há semáforos, retry/backoff e 429 classificado, mas não AIMD por provider nem `Retry-After` integrado em todos os caminhos. |
| 11. SBOM reutilizável | **NÃO EXISTE** | Geração existe, reutilização segura por identidade não. |
| 12. Security diff incremental | **EXISTE PARCIALMENTE** | `compare` e recipe/base diff existem; não há diff completo de pacotes/CVE/KEV/risk por dois digests. |
| 13. Supply-chain trust | **EXISTE PARCIALMENTE** | Digest pinning, Cosign, provenance, audit, official/publisher/hardening existem; lineage e estados uniformes de assinatura não dominam todo verdict. |
| 14. Policy dominante | **EXISTE PARCIALMENTE** | Readiness central e hard gates impedem recommendation sem scan; schema declarativo global ainda falta. |
| 15. Security score explicável | **EXISTE** | Penalidades/caps e readiness independente impedem média bonita de vencer hard gates; razões e blockers são emitidos. |
| 16. Métricas de performance | **EXISTE PARCIALMENTE** | RunMetrics expõe discovery/dedup/cache/scans/workers; faltam duração por etapa, requests, subprocessos e pico. |
| 17. Subprocess hardening | **EXISTE** | `create_subprocess_exec`, argv, timeout, teto por stream, terminate/kill/reap e classificação fail-closed. |
| 18. Network hardening | **EXISTE PARCIALMENTE** | HostGuard, TLS, timeout, limites e redirect guardado existem; políticas de Retry-After/content-type não são uniformes. |
| 19. Benchmark regression | **NÃO EXISTE** | Benchmarks manuais existem, mas não baseline/mediana/gate de 10%/20%. |
| 20. Testes de segurança | **EXISTE PARCIALMENTE** | A maioria dos casos pedidos está em unit/adversarial/integration; faltam matrizes explícitas para reset/DNS/retry e cancelamento single-flight. |
| 21. Mutation testing | **NÃO EXISTE** | Sem mutmut/workflow semanal. |
| 22. CI/supply chain do DockerLs | **EXISTE PARCIALMENTE** | Controles principais existem; pin total por SHA, dependency review, assinatura/proveniência/SBOM de release são dívida. |
| Go somente após benchmark | **EXISTE** | Escopo permanece no batch/fan-out e há benchmark comparativo; sem migração de domínio/CLI. |
| Dependências mínimas | **EXISTE** | Engine usa stdlib; esta mudança adiciona zero dependências. |
| Compatibilidade | **EXISTE** | CLI/modelos/exportadores mantidos; a mudança apenas deixa de reutilizar cache inseguro sem digest. |

## Grupo implementado: P0 — identidade canônica

**Problema/gargalo.** A chave persistente usava digest quando disponível, mas
caía para `name:tag` quando a resolução falhava. Assim, uma indisponibilidade
do registry podia fazer `latest` virar identidade por 24 horas. A plataforma
também não participava da chave.

**Solução.** `ImageIdentity` normaliza registry/repository, exige digest SHA-256
canônico e inclui `os/architecture`. O cache L2 agora só lê/grava análises com
essa identidade e valida novamente a identidade contida no payload. Tag é
preservada apenas como metadata de apresentação.

**Comportamento de segurança.** Falha de resolução passa a ser cache miss e
scan real, nunca cache hit por tag. Payload corrompido ou transplantado entre
digests/plataformas é descartado. HostGuard, execução argv, timeouts, evidência
e gates de scan não foram alterados.

**Risco residual.** O inspector ainda seleciona `linux/amd64` implicitamente;
a opção de plataforma deve ser propagada pela CLI/OCI antes de suportar
variantes. A versão/freshness exata da DB deve entrar no fingerprint antes de
permitir TTLs mais longos. O custo seguro é mais scans quando não se consegue
resolver um digest.

**Microbenchmark da chave (mediana de 5 × 100.000 operações).** O acesso antigo
ao campo custou 0,0083 s; normalizar e validar a identidade custou 0,5953 s
(aproximadamente 5,95 µs por chave). É uma regressão local deliberada e
irrelevante diante de I/O de SQLite/registry/scanner: ela compra validação de
digest e plataforma. Não foi alegado ganho de throughput; o ganho desta fase é
correção e invalidação determinística. Uma otimização futura pode memoizar a
identidade imutável, mas só depois de benchmark do pipeline completo.
