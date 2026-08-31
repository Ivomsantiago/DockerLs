# Changelog

Todas as mudanças relevantes do DockerLs são documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
e este projeto segue o [Versionamento Semântico](https://semver.org/spec/v2.0.0.html).

## [1.0.2] -- 2026-08-30

### Changed
- Fixed README images not rendering on PyPI: they used relative paths
  (docs/assets/*.svg) that only resolve inside the GitHub repo tree, so
  the PyPI project page showed broken image placeholders. Switched to
  absolute raw.githubusercontent.com URLs.

## [1.0.1] -- 2026-08-30

### Changed
- Fixed a Windows portability bug in the Go engine client (os.killpg/os.getpgid
  guarded with a sys.platform check).
- Fixed a cross-Python-patch-version SSRF classification instability in
  NetworkPolicy (removed reliance on ipaddress.is_reserved for IPv4-mapped
  addresses).
- Fixed a bug in the release workflow where Sigstore signature bundles were
  left in dist/, breaking the PyPI publish step.
- Fixed stale Portuguese example output in README.md and docs/REFERENCE.md.

## [1.0.0] -- 2026-08-30

**Primeira versão pública.** A numeração interna usada durante o
desenvolvimento chegou a `3.0.0` antes deste projeto jamais ter sido
publicado no PyPI ou taggeado no git (`git tag -l` estava vazio, e o nome
`dockerls` nunca foi reservado no índice) -- então essa numeração nunca foi
uma versão real que alguém instalou. O contador público de SemVer começa
aqui, em `1.0.0`. Nada abaixo desta seção foi apagado: o `## [1.0.0] --
2024-01-01` mais adiante neste arquivo é o registro do que foi de fato a
*primeira* entrada do desenvolvimento interno, renomeado para
`[1.0.0-internal]` só para não colidir com este.

### Corrigido -- a política de rede só julgava o primeiro salto

O `HostGuard` era consultado sobre o host da referência e sobre mais nada. Duas
coisas escolhidas pela outra ponta acontecem depois desse teste, e as duas
emitem requisição:

- **Redirecionamentos.** `OCIRegistryClient` e `DockerHubClient` seguem
  redirect (`follow_redirects=True`). Um registry respondendo `302 Location:
  http://169.254.169.254/latest/meta-data/` fazia essa requisição sair de
  dentro do runner com o veredito sobre o host *original* ainda valendo.
- **`WWW-Authenticate`.** A dança de token do OCI tira de um cabeçalho a URL
  contra a qual vai autenticar (`Bearer realm="..."`). Isso é a outra ponta
  nomeando uma URL que este processo busca -- a mesma primitiva de um open
  redirect, entrando por outra porta. Não havia validação nenhuma: `realm`
  podia ser `file://` ou apontar para a rede interna.

O guard agora viaja com o cliente e roda **por salto**, via event hook do
`httpx`, e o `realm` precisa ser uma URL http(s) absoluta antes de ser pedido.
Uma recusa é um `httpx.HTTPError`, então cai nos tratadores que já existem e
vira "não deu para determinar" -- nunca um traceback e nunca uma lista vazia
fingindo ser resposta.

### Corrigido -- três grafias de um endereço proibido passavam

O classificador de endereços deixava passar:

- **`0.0.0.0/8` inteiro.** `is_unspecified` só é verdadeiro para o `0.0.0.0`
  exato, e o Linux roteia o bloco todo para a própria máquina.
- **Encapsulamentos IPv6 que carregam um IPv4**: 6to4 (`2002:7f00:1::`),
  NAT64 (`64:ff9b::7f00:1`) e Teredo alcançam 127.0.0.1 num host com a
  tradução configurada, e nenhum é reconhecido por `is_loopback`.
- **CGNAT (`100.64.0.0/10`)**, onde a Alibaba Cloud serve credenciais de
  instância em `100.100.100.200`, além de multicast e faixas reservadas.

Registries internos em RFC1918 continuam funcionando exatamente como antes.

### Corrigido -- um NaN vindo de um feed certificava a imagem como perfeita

`float()` aceita `"nan"`, `"inf"` e `"-1"`, e o EPSS chega como JSON de
terceiro. O NaN se propagava pela soma de penalidades, e o
`max(0.0, min(100.0, score))` final responde **100.0** para uma entrada NaN --
toda comparação com NaN é falsa, então o clamp devolvia o próprio limite. Uma
imagem cheia de CRITICAL pontuava 100 porque um feed respondeu mal. Uma
probabilidade negativa tinha a versão branda do mesmo efeito: subtraía da
penalidade, comprando pontos de volta.

Limitado em três lugares, porque o valor entra por três: o parser do feed
descarta, a entidade valida (a mesma linha é reconstruída do SQLite, onde um
valor ruim já pode estar gravado) e o score se recusa a reportar um resultado
não-finito como qualquer coisa que não o fundo da escala.

O catálogo KEV ganhou o piso de plausibilidade que o próprio comentário já
prometia. Um 200 carregando três entradas -- página de erro de proxy,
transferência truncada -- era aceito como o feed, e todo CVE fora daquelas três
passava a ser reportado como "conferido, não consta como explorado".

### Corrigido -- uma release que muda a política continuava servindo o veredito antigo

A impressão digital do cache cobria as regras de ignore, a chave de threat
intel e a identidade do scanner, mas não a versão deste pacote -- e um
`ImageAnalysis` em cache carrega score, tier e veredito de produção, todos
decididos por política que mora aqui. `CACHE_SCHEMA_VERSION` não pega isso: a
*forma* do payload não muda, então a validação aceita e só o significado se
moveu.

### Corrigido -- uma assinatura que falha na verificação era relatada como "sem assinatura"

`cosign verify --certificate-identity-regexp ...` anuncia uma assinatura feita
pela parte errada como `Error: no matching signatures`, e `CosignClient.verify`
testava `_looks_unsigned` primeiro -- esse texto casa com o helper errado, e uma
imagem assinada por um atacante voltava como `UNSIGNED`. A única falha que
restringir a identidade existe para pegar era relatada como o veredito mais
brando: ninguém assinou. Novo `SignatureStatus.VERIFICATION_FAILED` (conclusivo,
nunca confiável), a ordem dos testes é invertida, `dockerls verify` imprime em
vermelho negrito com a razão e sai com `EXIT_POLICY` -- veredito, não falha de
medição.

### Corrigido -- um catálogo inalcançável respondia igual a um catálogo vazio

`DhiCatalog._resolve_index` devolvia (e memoizava) `{}` tanto para "imagem
ausente" quanto para "catálogo ilegível", então um único 403 desligava o DHI
para o processo inteiro. Novo `IndexState` (NOT_LOADED/COMPLETE/TRUNCATED/
UNAVAILABLE) com `is_conclusive`.

### Corrigido -- uma linha em branco em .dockerls-ignore.yaml silenciava todo achado sem nome

`IgnoreRule.cve` aceitava `""`, e como o filtro é
`vuln.cve_id.upper() not in ignored_cves`, uma única entrada em branco
descartava do score e do veredito de produção todo achado sem advisory ID
publicado -- e o Trivy emite alguns assim. `VexStatement` também passa a
recusar `not_affected` sem justificativa.

### Corrigido -- o validador de Dockerfile

- **DF001 (base pinada).** `":" not in image` decidia "sem tag", então
  `FROM registry.local:5000/app` (porta de registry, sem tag -- resolve para
  `:latest`) passava. Passa a reusar `split_repository_and_tag`.
- **Falsos positivos por substring.** `sudo` casava dentro de `pseudo`, `apt`
  dentro de `adapt`, `pip` dentro de `pipeline`.
- **DF004 (segredo em ARG).** O catálogo já afirmava que a regra olhava `ARG`;
  o código nunca olhou. Passa a inspecionar de verdade.
- **Três regras novas**, cada uma com detecção, severidade, rationale,
  remediação e teste: DF013 (`ADD` para o que deveria ser `COPY`), DF014
  (`curl | sh` / `wget | sh` sem verificação), DF015 (bit setuid/setgid
  deixado na imagem).

### Corrigido -- ReDoS na regex de detecção de shell do validador de Dockerfile

O CodeQL sinalizou (alta severidade) `_SHELL_AT_HEAD`: o ramo `env` usava dois
`\S+` sem limite compartilhando um espaço de busca sem limite ao redor de um
único `=` (`\S+=\S+`) -- a forma clássica de backtracking catastrófico, já que
`\S` inclui o próprio `=` e os dois lados podem renegociar onde cai a divisão.
Multiplicado pela repetição externa `(?:...)*`, uma linha `RUN` malformada
podia travar a análise. Corrigido excluindo `=` da metade da chave
(`[^\s=]+=\S+`): agora só existe um lugar onde a atribuição pode se dividir.

### Corrigido -- um score não-finito invalidava o documento SARIF inteiro

`json.dumps` aceita `NaN`/`Infinity` por padrão e escreve o token bruto --
que não é JSON válido pela RFC 8259. Um `security_score` (ou score de
hardening/attack-surface) não-finito em qualquer achado fazia o GitHub code
scanning, que analisa com rigor, rejeitar o **upload inteiro**: todo achado
descartado em silêncio, sem aviso nenhum na tela. Corrigido com um
`_json_safe` recursivo (não-finito vira `null`) e `allow_nan=False` como
verificação de guarda. Junto: `security-severity` podia sair como a string
`"inf"` (GitHub lê esse campo como número; agora cai para a banda de
severidade fora de `0 < s <= 10`, a mesma regra que o EPSS já aplica na
entrada); `artifactLocation.uri` podia ser só `":"` quando nome e tag vinham
vazios (agora cai para `scan.image_reference` ou `"unknown-image"`); e
`$schema` apontava para uma URL que hoje devolve 404 (o repositório upstream
renomeou a branch padrão). Validado contra o JSON Schema oficial do SARIF
2.1.0 (OASIS, vendorizado em `tests/fixtures/`).

### Corrigido -- dois defeitos achados por fuzzing dos parsers

- **`EXPOSE <4301+ dígitos>` ou `USER app:<4301+ dígitos>` abortava a
  validação inteira.** A partir do Python 3.11, `int()` recusa strings com
  mais de 4300 dígitos e a recusa é um `ValueError` que o parser não
  capturava -- uma única linha retirava o Dockerfile de **todas** as regras
  de uma vez. Corrigido com limite explícito de porta/UID antes de
  converter.
- **`split_repository_and_tag` violava o próprio contrato documentado** em
  referências como `a.io/b.io:5000/app`: fazia `rsplit(":", 1)` sobre a
  cauda inteira em vez do último segmento, lendo `5000/app` como tag. Uma
  tag não pode conter `/` nem `:`, então a base ficava marcada como
  "pinada" quando na verdade não carrega tag nenhuma -- a mesma classe do
  DF013 (porta de registry escondendo base sem tag), um nível mais fundo.

Achado por Hypothesis, ~210 mil casos por propriedade (`DOCKERLS_HYPOTHESIS_EXAMPLES`
ajusta o orçamento). A varredura confirmou negativo em duas frentes: nenhum
dos 30+ padrões compilados do validador de Dockerfile reabre o ReDoS
corrigido acima, e o invariante tag/digest (F13) não diverge sob fuzzing.

## [2.10.1] -- 2026-08-22

### Corrigido -- os alertas abertos no code scanning do próprio repositório

Uma ferramenta de segurança com a lista de alertas vermelha ensina todo mundo
a ignorar a lista. Os onze alertas abertos em `Master` foram triados um a um.

- **`pip` sai da imagem publicada (5 alertas Trivy: #571-#575).** A
  `python:3.12-alpine` embute `pip 25.0.1`, que carrega seis advisories
  abertos segundo o OSV -- corrigidos ao longo de 25.3, 26.0, 26.1, 26.1.2 e
  26.2. Atualizar resolveria as seis de hoje e não a próxima: pip é alvo
  grande e recebe advisory novo com regularidade, então `--upgrade` vira
  imposto recorrente. Numa imagem de **execução** um instalador de pacotes não
  é conveniência, é superfície -- o mesmo argumento que este projeto já usa
  para tirar o npm de uma base Node. `setuptools`, `pkg_resources` e `wheel`
  saem junto: nenhuma dependência de runtime deste projeto os importa,
  conferido uma a uma. O passo tem portão: se `import pip` continuar
  funcionando, o build falha em vez de publicar a imagem.
- **Seis alertas de "Incomplete URL substring sanitization" (CodeQL: #1, #2,
  #559, #560, #566, #567).** Todos em teste e benchmark -- `"cgr.dev" in url`
  e `"api.github.com" in request.url.host`. Nenhum era explorável ali, e o
  padrão é o mesmo que seria confusão de host em produção. Trocados por
  igualdade de host, e o teste de aceitação passa a usar `registry_host_of` --
  a mesma função que a produção usa -- em vez de redefinir a regra por conta
  própria. **A varredura confirmou que o padrão não existe em `dockerls/`.**

### Corrigido -- duas afirmações que a auto-remediação não podia fazer

- `"Upgraded bundled npm CLI to latest patched release"` e `"Upgraded
  pip/setuptools to secure versions"` eram afirmações sobre o resultado de
  comandos que ainda não tinham rodado. As mensagens passam a descrever a
  ação e a dizer que o veredito é do scan seguinte -- e a do pip menciona que,
  num estágio de execução, remover costuma ser melhor que atualizar.

## [2.10.0] -- 2026-08-22

### Adicionado -- do "de quem é" para o "o que eu faço"

- **Plano de trabalho: origem cruzada com "existe correção?".** Dizer que 41
  vulnerabilidades vêm da base ainda não diz se **atualizar** a base adianta --
  e a resposta muda tudo: se nenhuma tem correção publicada upstream,
  atualizar é trabalho perdido e trocar a base é o único caminho. `--attribute`
  passa a imprimir os quatro grupos (herdada/sua × com/sem correção), cada um
  com a ação correspondente e os CVEs mais graves de amostra.
- **Os grupos são ordenados por CRITICAL, não por total.** É onde a primeira
  hora de trabalho rende mais; ordenar por total faria um monte de LOW passar à
  frente de dois CRITICAL sem correção.
- **A linha do portão carrega a origem.** Quando a atribuição rodou,
  `Vulnerabilities exceed threshold` passa a dizer quantas vieram da base,
  quantas dessas têm correção publicada, e quantas são das suas camadas. Quem
  lê o log do CI está decidindo naquele segundo se mexe no Dockerfile ou na
  base. A base é escaneada **uma vez só** nesse caminho.

### Corrigido

- **Uma imagem limpa cujo build removeu CVEs da base dizia "nenhuma
  vulnerabilidade a atribuir"**, escondendo o melhor resultado possível. Agora
  diz que a imagem está limpa *e* que as da base não sobreviveram ao build.
- **Concordância verbal na atribuição:** "1 vêm da base" virou "1 vem".

### Notas

- O grupo "da base, com correção" diz **"pode resolver"**, não "resolve": uma
  correção existir upstream não significa que quem publica a base já
  reconstruiu com ela. Prometer o contrário é como uma ferramenta perde a
  confiança de quem seguiu o conselho e não viu o número cair.
- Quando a atribuição não rodou ou não fechou, o portão fica calado sobre
  origem. Um portão que insinua uma origem que não mediu é pior do que um
  portão calado.

## [2.9.1] -- 2026-08-22

### Corrigido -- duas mensagens que se contradiziam na mesma tela

- **`DF001` dizia "Base image tag is pinned" para `node:22`**, na mesma tela em
  que a política reprovava a mesma linha com "não está fixada por digest". As
  duas frases eram verdadeiras -- PASS ali significa apenas "não é `latest`" --
  e lidas juntas pareciam contradição. A mensagem agora distingue os dois casos
  e o `details` carrega `pinned_by_digest`.
- **A sugestão de base era uma string fixa** (`"FROM node:22-alpine or FROM
  chainguard/node:latest-dev"`), devolvida igual para qualquer Dockerfile --
  inclusive um de Python, onde nomear uma imagem Node é simplesmente errado.
  Nomear uma imagem que ninguém mediu é o oposto do que esta ferramenta faz em
  todo o resto; a sugestão passa a apontar para `dockerls base` e `dockerls base
  --alternatives`, que medem.

### Documentação

- **Seção "Do zero à imagem em produção"**: percurso completo com dois
  Dockerfiles reais, do `fleet` ao `verify`, com **saídas capturadas verbatim**
  e uma tabela do que cada passo custa.
- `--production`, `--attribute` e o preflight de política documentados com
  saída real; o único bloco ilustrativo do README está marcado como tal.
- A seção Performance passa a trazer os números medidos e a metodologia,
  incluindo o que foi medido e **não** implementado (hashing paralelo: 0,20 s
  -> 0,13 s com 4 threads, pior com 8 e 16 -- não se paga).

## [2.9.0] -- 2026-08-22

### Corrigido -- o portão podia ser afrouxado em silêncio

- **`effective_fail_on` escolhia o limiar mais permissivo, não o mais
  estrito.** `--fail-on low` reprova em LOW *e em tudo acima*, enquanto
  `--fail-on critical` só olha para CRITICAL -- ou seja, `low` é o mais
  exigente que existe e `critical` o mais brando. A função ordenava pela
  "gravidade da palavra" e devolvia `critical` quando um dos lados pedia
  `high`, afrouxando um portão que alguém tinha apertado. A decisão D-025
  ("vence a mais estrita") estava certa; a implementação fazia o contrário.
- **`fail_on: unknown` era aceito pelo arquivo de política e o portão não sabe
  avaliá-lo**, então o build morria com erro técnico no meio do caminho em vez
  de ser recusado na leitura do arquivo. `unknown` segue válido como teto em
  `max_vulnerabilities`: um achado sem severidade ainda é um achado.

### Adicionado -- de quem é cada CVE

- **`dockerls build --attribute`.** Um relatório que diz "47 vulnerabilidades"
  manda consertar sem dizer o quê, e quem lê passa a tarde descobrindo que nada
  no Dockerfile dela resolve o problema. A base declarada passa a ser escaneada
  junto da imagem, e os achados são divididos em `INHERITED` (da base -- só
  atualizar ou trocar resolve), `INTRODUCED` (das suas camadas) e `REMOVED` (o
  que o seu endurecimento comprou). Sem os dois scans não há atribuição: o
  relatório diz `UNAVAILABLE` e o motivo, nunca "tudo é seu".
- **`dockerls build --production`.** O conjunto que uma imagem publicada
  precisa, sob um nome só, em vez de sete flags que cada pipeline digita de
  novo esquecendo uma diferente por vez. Diz na saída o que ligou. Um
  `.dockerls-policy.yaml` do contexto continua valendo e só pode apertar.
- **Preflight de política no `--validate-only`.** O que dá para reprovar sem
  construir passa a reprovar em segundos. Descobrir um rótulo obrigatório
  faltando depois de dez minutos de build e um scan é o atrito que faz as
  pessoas pararem de rodar o portão.

### Desempenho

- **Digestão do contexto de build: 65x mais rápida em contexto real.** A poda
  do `.dockerignore` acontecia *depois* de percorrer a árvore inteira, então
  `.git` e `node_modules` eram abertos arquivo por arquivo só para serem
  descartados. Num contexto de 52.400 arquivos em que 401 são enviados ao
  daemon: **0,84 s -> 0,013 s**, com o digest byte a byte idêntico (a
  ordenação final continua sobre os caminhos completos, então um documento de
  procedência antigo segue comparável com um novo).
- **Arranque do CLI ~1,5x mais rápido:** mediana de **0,58 s -> 0,39 s** para
  `dockerls version`. O SQLAlchemy era importado no arranque de toda invocação
  por causa de dois imports de módulo, e comandos que nunca tocam o cache
  pagavam por ele.

## [2.8.0] -- 2026-08-21

### Adicionado -- `dockerls registry-audit`

- **O que o registry conta sobre uma imagem publicada, sem credencial de
  nuvem.** Auditar retenção, IAM e content trust exige acesso administrativo e
  uma API por provedor -- e um relatório que precisa disso para existir é um
  relatório que ninguém roda. Este usa só o protocolo OCI: resolve a
  referência, diz se ela é digest ou tag, procura assinatura e atestação cosign
  nas tags derivadas do digest, e mede se o registry respondeu sem credencial.
- **`TAG_STABLE` mede mutabilidade em vez de ler configuração.** A
  imutabilidade declarada no registry é uma declaração; o histórico de digests
  é uma observação, e quando as duas discordam é a observação que descreve o
  que aconteceu.

### Decidido

- **`PUBLICLY_READABLE` é relatado e nunca alerta.** "Público" é o estado
  correto de uma imagem base oficial e o estado errado de um artefato interno,
  e a diferença é a intenção de quem publicou -- que a ferramenta não mede.
  Transformar o fato em alerta seria afirmar uma intenção.
- **Todo achado é tri-estado.** "O registry não respondeu sobre a assinatura"
  nunca vira "não há assinatura".

## [2.7.0] -- 2026-08-21

### Adicionado -- assinatura e alternativas medidas

- **`dockerls verify` e `dockerls build --sign`.** O scan diz o que há dentro
  de uma imagem e a procedência diz de onde ela veio; nenhum dos dois impede
  alguém com acesso de escrita ao registry de sobrescrever a tag. A assinatura
  responde a pergunta que faltava: quem publicou estes bytes.
- **`dockerls base --alternatives`.** O `base` atualizava o digest, o que
  resolve a data e não resolve a escolha: trocar `node:22` por `node:22` de
  ontem continua sendo `node:22`. Agora cada `FROM` distinto é escaneado junto
  das candidatas, e a melhor medida aparece com o custo da troca ao lado. Nada
  é aplicado -- trocar a família da base muda libc, shell e usuário, e isso é
  revisão de arquitetura, não atualização de digest.

### Decidido

- **`cosign` ausente nunca vira "não assinado".** Três estados e três exit
  codes: `VERIFIED` (0), `UNSIGNED` (2, veredito sobre a imagem) e
  `SIGNER_MISSING`/`FAILED` (1, falha do medidor). Sem essa distinção um
  pipeline trataria "não deu para conferir" como "não está assinada".
- **Só se assina por digest, e só com procedência verificada.** Assinar uma tag
  assinaria o que ela aponta agora, e ela pode mover no instante seguinte -- a
  assinatura seguiria válida cobrindo outros bytes.
- **Uma alternativa pior é reportada, não filtrada.** Esconder o que ficou pior
  transformaria a lista num argumento em vez de uma medição.

## [2.6.0] -- 2026-08-21

### Adicionado -- `dockerls fleet`

- **O retrato de todos os Dockerfiles de uma vez.** Cada comando desta
  ferramenta olhava para um artefato, o que resolve a pergunta de quem está com
  o arquivo aberto e nenhuma das perguntas de quem responde por trinta
  repositórios. A saída é uma fila de trabalho ordenada por violações, com o
  empate resolvido pelo caminho para que duas varreduras sejam comparáveis.
- **A política estática é aplicada por arquivo.** Só as regras decidíveis sem
  build (`require_pinned_bases`, `require_nonroot`, `required_labels`,
  `allowed_base_registries`); as que dependem de scan continuam no `build`,
  porque uma violação idêntica por arquivo não distingue nada.
- **"root" e "usuário indeterminado" são colunas separadas.** Juntá-los
  transformaria ausência de medida em acusação, e a fila de trabalho de cada um
  é diferente.

### Notas

- A varredura **não segue symlink** (um link para `/` transformaria a varredura
  de um repositório numa varredura da máquina), pula diretórios de dependência,
  e **diz quando foi truncada** -- um retrato parcial que se apresenta como
  completo é pior do que nenhum retrato.
- As bases são lidas com expansão de `ARG`: `FROM python:3.12@${PY}` conta como
  fixado, porque é a forma correta de fixar e uma varredura que reprova quem fez
  certo ensina a fazer errado.
- A saída diz, ela mesma, que leu Dockerfiles e não escaneou imagem nenhuma.

## [2.5.0] -- 2026-08-21

### Adicionado -- política como código

- **`.dockerls-policy.yaml`.** `--fail-on critical` é um portão que mora na
  linha de comando, e uma regra que mora na linha de comando é uma regra que
  cada pipeline reescreve à mão: bastava um `--fail-on high` esquecido num
  repositório para a política da organização deixar de valer ali, sem que nada
  acusasse. Agora ela é dado versionado junto do código, conferido em todo
  `dockerls build` do contexto. Oito regras, todas mensuráveis a partir do que
  o build mediu: `fail_on`, `max_vulnerabilities`, `require_scan`,
  `require_pinned_bases`, `require_nonroot`, `required_labels`,
  `allowed_base_registries` e `require_provenance`.
- **`dockerls policy`** mostra e valida o arquivo sem precisar de um build.
  Descobrir uma chave errada no meio de um build de dez minutos é caro;
  descobrir aqui custa um segundo.
- **`--policy` e `--no-policy` no `build`.** O segundo registra na saída que a
  política foi ignorada -- desligar um portão em silêncio seria o mesmo
  problema que ele existe para resolver.

### Decidido

- **Arquivo de política malformado é erro, não ausência de política.** É a
  única diferença de comportamento em relação ao `.dockerls-ignore.yaml`, e ela
  vem da direção da falha: uma regra de ignore que não carrega deixa de esconder
  uma CVE (mais alarme, e alarme a mais é seguro); uma regra de política que não
  carrega deixa de exigir alguma coisa, e o build passa parecendo ter sido
  conferido. `require_non_root` no lugar de `require_nonroot` viraria um portão
  aberto com cara de fechado.
- **A política nunca afrouxa o que a linha de comando apertou.** Entre os dois
  `fail_on` vence o mais estrito: senão bastaria commitar um YAML para publicar
  o que não passaria.
- **Não medir nunca aprova.** Teto de severidade sem scan é violação, não
  silêncio; `require_nonroot` sem a checagem é violação, e a mensagem distingue
  "roda como root" de "não foi possível determinar".

## [2.4.0] -- 2026-08-21

Segundo lote da lista de melhorias: fecha a cadeia entre o documento de
procedência e a assinatura, e transforma duas mensagens vagas em medidas.

### Adicionado

- **`dockerls provenance`.** O `build --provenance` arquivava um JSON que
  ninguém lia — e um documento que ninguém confere descreve com precisão uma
  imagem que ninguém sabe se deveria ter sido publicada. O comando recalcula o
  veredito a partir dos digests em vez de acreditar no campo `status` gravado
  (que é editável por qualquer um com um editor de texto) e **reprova por
  código de saída** quando a cadeia não fecha, o que o torna portão de CI.
- **`--github-output` e o workflow de exemplo.** `subject-name` e
  `subject-digest` saem do próprio documento para o
  `actions/attest-build-provenance`. Redigitar o digest no YAML é onde a
  cadeia arrebenta sem ninguém perceber: uma assinatura perfeitamente válida
  apontando para bytes que ninguém escaneou. O workflow completo está em
  `examples/github/image-release.yml`.
- **Histórico de digests por tag no `dockerls base`.** "Esta base mudou" e
  "esta base muda toda semana" pedem decisões opostas, e as duas produziam
  exatamente o mesmo `PINNED_STALE`. Cada digest observado é guardado com a
  data (TTL de um ano — um histórico é o passado, não fica obsoleto), e a linha
  passa a dizer quantas vezes a tag mudou e desde quando. O histórico começa na
  primeira vez que a ferramenta olhou, e a mensagem diz isso em vez de fingir
  que o silêncio anterior era estabilidade. Se o cache falhar, o diagnóstico
  segue sem a linha: um extra não pode derrubar o principal.
- **`dockerls base-image --compare <família>`.** Responder "alpine ou debian
  para isto?" exigia gerar os dois Dockerfiles e contar pacotes na mão. O diff
  mostra o que entra, o que sai e o que cada troca custa — com destaque para a
  mudança de libc, a única que quebra binário compilado. Não escreve arquivo
  nenhum e **não elege vencedora**: contar pacotes não mede CVE, e a resposta
  vem de escanear as duas.

## [2.3.0] -- 2026-08-20

Primeiro lote da lista de melhorias: três itens de baixo esforço, todos
fechando inconsistências reais.

### Corrigido

- **O relatório do `build` perdia as citações.** O terminal cita o controle
  publicado atrás de cada regra (CIS 4.1, NIST 4.1.2, OWASP RULE #2) e o
  relatório serializava só `check`, `status`, `message`, `severity` e `line` —
  exatamente onde a citação vale mais, que é o arquivo que vai para auditoria.
  Passa a carregar `rule_id`, `references` e `rationale`.
- **Core dumps do scanner ficavam ligados.** Um scanner que falha um pull
  autenticado tem o token na memória; um SIGSEGV com core dump gravaria esse
  token em disco, num arquivo que ninguém redige. `RLIMIT_CORE` vai a zero
  antes do `exec`. `RLIMIT_AS` continua deliberadamente de fora, e há teste
  fixando isso: o Trivy é um binário Go, e o runtime do Go reserva um espaço
  de endereçamento virtual enorme na largada — limitar mataria o processo na
  inicialização, virando falha de scan em vez de defesa.

### Adicionado

- **`dockerls base-image --build`.** Gerar e construir em dois comandos deixava
  um vão onde a receita existe e ninguém a mediu — e receita não medida é
  intenção, não afirmação sobre segurança. O portão entra em `critical`, e os
  rótulos da receita seguem para a imagem.

## [2.2.1] -- 2026-08-20

### Corrigido — o npm embutido era quase toda a superfície de uma base Node

Uma `base-node` recém-gerada reprovava no portão com `CVE-2026-59873
(CRITICAL) em tar 7.5.11`, e o Docker Scout mostrou de onde: a camada
`node:22-alpine` trazia 1 CRITICAL e 7 HIGH, enquanto **todas as camadas
geradas por este comando traziam zero**. Os pacotes afetados eram
`npm/tar`, `npm/brace-expansion`, `npm/ip-address`, `npm/picomatch` e
`npm/sigstore` — as dependências que o npm carrega dentro de si, em
`node_modules`, fora do alcance do `apk upgrade` porque não são pacotes da
distribuição.

`dockerls base-image` passa a remover o gerenciador embutido (npm, npx, yarn)
por padrão nas bases Node. A pergunta certa numa base de **execução** é o que
justifica mantê-lo: as dependências da aplicação são instaladas no estágio de
build de quem consome, e nada na imagem final precisa instalar mais nada. Quem
tem um `npm start` que resolve pacotes na subida passa `--keep-manager`, e o
comando diz em voz alta o que isso implica.

A remoção roda como `root` e a imagem volta ao usuário não-root antes de
terminar — terminar como root anularia o ponto da base.

## [2.2.0] -- 2026-08-19

### Adicionado — `dockerls base-image`

Gera o Dockerfile de uma imagem base a partir de um menu: você escolhe o
sistema operacional, o runtime, e marca os pacotes. O resultado não tem
aplicação nenhuma — é feito para outros projetos consumirem com `FROM`.

O menu mostra, para cada pacote, **o que ele serve e o que ele custa**. Numa
imagem base essa segunda metade é a que importa: cada pacote marcado existe em
toda aplicação que a consome, e toda CVE dele vira triagem para times que nem
sabem que ele está lá. O catálogo é curto de propósito — uma lista com tudo que
a distribuição publica faria as pessoas marcarem tudo "por via das dúvidas".

A base sai fixada por digest resolvido no registry na hora da geração; quando o
registry não responde, o Dockerfile sai sem digest e **diz isso num comentário**
em vez de fingir que está fixado.

Três recusas estão codificadas: `sudo`, `su-exec` e o cliente `docker` não são
oferecidos (numa imagem que roda sem privilégio, existem para cruzar a fronteira
que ela acabou de estabelecer); pacotes em distroless são recusados com a
explicação em vez de gerarem um Dockerfile que falha; e o cache do gerenciador
sai sempre na mesma camada que o criou, sem ser opção.

O resultado não tem `ENTRYPOINT`, `EXPOSE` nem `HEALTHCHECK` — uma imagem base
não sabe em que porta a aplicação escuta, e declarar isso seria herdado errado
por todo consumidor.

### Corrigido

- **`libc6-compat` seria instalado no Debian.** O nome do pacote por família
  caía num fallback para a chave quando a família não tinha nome declarado, e
  `libc6-compat` só existe no Alpine — o `apt-get install` quebraria o build. O
  vazio passa a significar "não se aplica", e o menu não oferece o pacote onde
  ele não cabe.

## [2.1.0] -- 2026-08-19

### Adicionado — `dockerls base`

A metade que lia o seu projeto não media nada, e a metade que media não lia o
seu projeto: o `analyze-dockerfile` sugeria base por string fixa (respondia
`"FROM node:22-alpine"` até para um Dockerfile de Python), e o `recommend` só
funcionava se alguém digitasse a referência na mão. Este comando é a ponte.

Ele lê cada `FROM`, pergunta ao registry qual digest a tag aponta **agora**, e
classifica em quatro estados: `PINNED_CURRENT`, `PINNED_STALE` (fixada num
digest que a tag deixou para trás), `UNPINNED` e `UNRESOLVED`. Por padrão
aplica a correção; `--dry-run` mostra sem escrever e sai com código `2` quando
sobra o que corrigir, o que o torna portão de CI.

`PINNED_STALE` é o caso que este comando existe para pegar, e ele não é
hipotético: a base deste próprio projeto ficou meses fixada num digest de
meados de 2024, carregando duas CVEs CRITICAL do `libexpat1` que já tinham
correção publicada. O Dockerfile estava "corretamente" fixado o tempo todo —
fixar sem nunca reavaliar é trancar a porta e jogar fora o calendário.

Detalhes que a implementação leva a sério:

- quando o digest vem de um `ARG`, a atualização vai para **a linha do `ARG`**,
  onde o digest realmente mora — escrever no `FROM` quebraria o contrato do
  arquivo em vez de atualizá-lo, e num Dockerfile com dois `FROM` usando o
  mesmo `ARG` sai uma substituição, não duas;
- `--platform`, `AS <estágio>`, comentários e indentação sobrevivem intactos:
  um upgrade de base que reformata o arquivo transforma uma revisão de uma
  linha numa revisão de trinta;
- estágios de build são conferidos junto com o final, porque um `golang` velho
  compila com toolchain velho;
- registry que não responde dá `UNRESOLVED` e **nunca** "em dia" — o mesmo
  princípio que rege o scan que não completou.

## [2.0.2] -- 2026-08-19

### Documentação

- **As 31 opções do `build` estão documentadas.** Nove não apareciam em lugar
  nenhum do README: `--interactive`, `--scan`/`--no-scan`, `--auto-fix`,
  `--zero-vulns`, `--max-iterations`, `--report`, `--acr`. Uma opção que existe
  e não está escrita é uma opção que ninguém usa.
- **Seção de requisitos por comando.** Dizia apenas "Python, Trivy, Grype", sem
  mencionar que o **daemon do Docker é necessário só para o `build`** — e que
  todo o resto funciona sem ele. A tabela agora diz, para cada requisito, o que
  deixa de funcionar na ausência dele, e a nota sobre o `build` inclui a
  autenticação no registry de destino.
- **Seis exemplos práticos com a saída real do comando**: validação reprovando
  com os três erros nomeados, build passando no portão com o placar do scan,
  base inexistente recusada antes de construir, publicação sem responsável
  recusada com o comando de login já nomeado, o caminho completo de produção, e
  a forma usada em pipeline.

### Corrigido

- **O help do `--base` estava desatualizado.** Anunciava "(node, python, go,
  rust, java, php)" quando existem 39 templates, incluindo `alpine`, `ubuntu`,
  `distroless`, `maven-alpine` e `go-scratch`. Quem lia o help concluía que
  metade das opções não existia.

## [2.0.1] -- 2026-08-19

### Adicionado

- **Templates de Maven e Gradle** (`maven`, `maven-alpine`, `gradle`,
  `gradle-alpine`). `--base maven` respondia que o template não existe,
  mandando a pessoa escrever o multi-stage na mão — justamente onde um projeto
  Java de verdade começa o Dockerfile. Os quatro são multi-stage: a ferramenta
  de build fica no primeiro estágio e o runtime carrega só o JRE. São 39
  templates no total, cobrindo alpine, debian, ubuntu, distroless e scratch.

### Corrigido

- **`--list-templates` era uma lista plana de quase quarenta nomes**, sem dizer
  o sistema operacional de cada um. Ela não respondia a pergunta que a pessoa
  tem — "qual serve para a minha aplicação, e sobre qual SO ela roda". Agora sai
  agrupada por stack, com o SO e o que distingue cada variante (musl vs glibc,
  com shell ou sem), e com exemplos de build reais.
- **A saída não dizia de onde vinha a base.** `dockerls build` sem `--base` nem
  `--hardened` usa o Dockerfile que já está no diretório — ele não escolhe base
  nenhuma. Num projeto Python isso produz uma imagem Python, e nada na saída
  explicava que os templates existem e não estavam sendo usados.
- **`--base` aceitava nome inexistente.** A validação perguntava se algum
  template era *substring* do que foi digitado, então `--base alpine-qualquer`
  passava (por conter "alpine") e só explodia lá dentro, na geração. Agora é
  nome exato, com a lista completa na mensagem de erro.

## [2.0.0] -- 2026-08-18

Primeiro release publicado. As versões 1.3.0 a 1.7.1 abaixo documentam o
caminho até aqui, mas nenhuma delas chegou a virar tag -- este é o corte que
sai de verdade, e por isso ele consolida todas.

### MUDANÇAS QUE QUEBRAM COMPATIBILIDADE

Três, e as três são deliberadas:

1. **A imagem publicada não embute mais um scanner.** O binário do Trivy
   respondia por ~330 das 339 vulnerabilidades reportadas contra a imagem, e
   nenhuma delas era do código deste projeto. Quem rodava `dockerls recommend`
   *dentro* do container passa a receber `SCANNER_MISSING`, que a política
   reporta como **não verificado** e nunca como "limpo". Para escanear, rode o
   `dockerls` num host com trivy ou grype instalado.
2. **A base virou Alpine, e a libc virou musl.** As seis CRITICAL que sobravam
   na base Debian não tinham correção publicada -- quatro delas no `perl-base`,
   um pacote que este projeto nunca invoca e que o Debian marca como
   `Essential: yes`. Trocar a base resolve; silenciar as CVEs num arquivo de
   ignore só esconderia.
3. **`--push` passou a exigir veredito.** Publicar liga o portão em `critical`
   por padrão, e `--push --no-scan` é recusado. Quem tinha um pipeline
   publicando sem `--fail-on` vai ver o build reprovar onde antes passava --
   que é exatamente o ponto: era publicação sem medição.

### O que este release entrega

- **Motor multi-source de decisão**: Docker Hub, Chainguard, Distroless e DHI
  como *fontes de dados*, com o veredito pertencendo ao DockerLs. Catálogos
  endurecidos com repositórios verificados contra o registry -- o mapa 1:1
  anterior respondia `recommend node` com `distroless/nodejs`, cujas tags são
  10, 12 e 14.
- **Evidência acima de reputação**: fatos tri-estado (TRUE/FALSE/UNKNOWN),
  modelo de confiança com piso `UNVERIFIED`, e a política central
  `ProductionReadiness` com códigos estáveis de bloqueio.
- **Referências documentais nas regras**: cada achado do `analyze-dockerfile`
  cita o controle publicado que implementa (CIS, NIST SP 800-190, OWASP, OCI),
  todos conferidos na fonte primária. Comando `dockerls controls` para ler o
  catálogo inteiro.
- **Publicação com responsabilidade**: destino e rótulos perguntados **antes**
  do build, com suporte a Azure ACR, Google Artifact Registry, Google GCR,
  Docker Hub, GitHub GHCR e registries privados -- cada um com sua regra real
  de validação e o comando de login que o destrava.
- **Supply chain**: hash do Dockerfile, do contexto e das bases antes do build;
  id da imagem e digest do manifesto depois. A entrada é digerida de novo ao
  final, e uma entrada que mudou durante o build **barra a publicação**.
- **Segurança do próprio processo**: política de rede aplicada também ao pull
  do scanner, redação central de segredos, escape de marcação vinda de
  terceiros, teto na saída do scanner, e YAML com defesa contra bomba de
  aliases.
- **Desempenho medido**: `redact()` de 19 445 ms para 245 ms, e paralelismo
  derivado da máquina (ciente de cgroup) em vez de um número fixo.

Os detalhes de cada item, com o caminho de código e o motivo, estão nas
entradas abaixo e em `AUDIT.md`, `DECISIONS.md`.

## [1.7.1] -- 2026-08-18

Fechamento para produção: três lacunas que só apareceram ao olhar a versão
como algo que vai ser publicado, não como código em progresso.

### Corrigido

- **Publicar não exigia veredito.** O portão dependia de alguém lembrar de
  passar `--fail-on`: `--push` sozinho publicava qualquer coisa. Agora `--push`
  ou `--registry` ligam o portão em `critical` por padrão, e `--fail-on`
  continua valendo quando o limiar é outro. `--push` com `--no-scan` é recusado
  de saída — uma imagem não medida não é uma imagem segura, é uma imagem
  desconhecida. Era a contradição mais direta que restava numa ferramenta cuja
  tese é que ausência de medição nunca vira afirmação de segurança.
- **A publicação ignorava a procedência quebrada.** Se o Dockerfile ou o
  contexto mudaram durante o build, a imagem existe mas não corresponde ao que
  foi medido — e ela era publicada assim mesmo. Agora o push é recusado com
  `EXIT_POLICY`, porque distribuir esse artefato seria distribuir algo cuja
  procedência a própria ferramenta acabou de declarar quebrada.
- **`--provenance` não existia.** O registro de supply chain era montado e
  tinha um caminho de arquivamento no caso de uso, mas nenhuma opção de linha
  de comando chegava até ele: na prática, não dava para guardar o documento em
  lugar nenhum.

### Documentação

O README passa a documentar o fluxo de publicação (as perguntas antes do build,
os seis destinos suportados com a regra de cada um, `--non-interactive` para
pipeline) e o registro de supply chain, com a saída real. As opções
`--registry`, `--owner`, `--security-contact`, `--source`, `--provenance` e
`--non-interactive` não estavam documentadas em lugar nenhum fora do CHANGELOG.

## [1.7.0] -- 2026-08-18

### Adicionado — procedência: hash antes, hash depois, e a comparação entre eles

O `build` media o resultado sem registrar nada sobre o que entrou: dois builds
do mesmo `--tag` produziam relatórios indistinguíveis mesmo partindo de
Dockerfiles diferentes, e nada ligava o scan ao artefato que ele mediu. Numa
cadeia de fornecimento, "nós escaneamos essa imagem" sem digest é uma frase
sobre nada.

Cada build passa a produzir um registro com duas metades:

- **antes** — digest do Dockerfile, digest determinístico do contexto (com o
  número de arquivos), digest de cada base declarada nos `FROM`, commit e se a
  árvore estava suja;
- **depois** — id da imagem, digest do manifesto publicado (que só existe após
  o push, e é o único identificador que outra máquina consegue usar para puxar
  exatamente esta imagem), e qual scanner atestou.

**A verificação é o que faz disso controle e não decoração:** a entrada é
digerida de novo depois do build e comparada com a de antes. Se mudou no meio
do caminho, o registro sai como `INPUT_CHANGED` — a imagem existe, mas não
corresponde à entrada que foi medida. Entrada ou saída que não puderam ser
digeridas dão `INCOMPLETE`, que é ausência de prova e nunca vira prova de
integridade: o mesmo princípio que rege o scan que não completou.

O digest do contexto é determinístico por construção — caminhos ordenados e
relativos, e o nome de cada arquivo entrando no digest junto do conteúdo, de
modo que renomear muda o contexto tanto quanto editar. O `.dockerignore` é
respeitado porque ele decide o que o daemon realmente recebe: hashear o que
fica de fora produziria um digest que muda sem a imagem mudar, e um controle
que dispara à toa é um controle que as pessoas desligam. Um contexto acima de
50 000 arquivos é recusado em vez de digerido pela metade — quase sempre
significa `.dockerignore` ausente.

O registro aparece no terminal, entra no `--format json` sob `provenance`, e é
arquivado em disco quando se pede.

## [1.6.0] -- 2026-08-18

### Adicionado — destino e responsabilidade perguntados antes do build

`dockerls build` passa a resolver, **antes** de validar/construir/escanear:
para onde a imagem vai, quem responde por ela, e para quem se avisa quando ela
tiver uma vulnerabilidade. Perguntar depois desperdiça o trabalho inteiro — e é
exatamente quando alguém publica em qualquer lugar só para não repetir a espera.

Novas opções: `--registry` (também aceita `--acr`), `--owner`,
`--security-contact`, `--source` e `--non-interactive`. O que faltar é
perguntado no terminal; com `--non-interactive` ou `--ci-mode` vira erro, porque
um pipeline não tem quem responda e travar esperando entrada é o pior
comportamento possível num runner.

**Compatibilidade de registries**, cada um com sua regra real de validação e o
comando de login que o destrava:

| Provedor | Formato | Login |
|---|---|---|
| Azure ACR | `registro.azurecr.io/apps/app` (também `.azurecr.cn` / `.azurecr.us`) | `az acr login --name <registro>` |
| Google Artifact Registry | `regiao-docker.pkg.dev/projeto/repo/app` | `gcloud auth configure-docker` |
| Google GCR | `gcr.io/projeto/app` (e espelhos `eu.gcr.io`) | `gcloud auth configure-docker gcr.io` |
| Docker Hub | `minhaorg/app` | `docker login` / `dockerls login` |
| GitHub GHCR | `ghcr.io/org/app` | `docker login ghcr.io` |
| Registry privado | `registry.interna:5000/time/app` | `docker login <host>` |
| DHI | — | **recusado**: `dhi.io` distribui imagens endurecidas, não aceita push |

As regras não são decorativas: o Artifact Registry exige `projeto/repo/imagem`
no caminho e o Docker Hub exige um namespace que não seja `library`. As duas
coisas falhavam só na hora do push, minutos depois do build.

### Corrigido

- **`--push` publicava a tag local como está.** Numa tag sem host —
  `dockerls:1.5.0`, que é a forma que todo mundo digita — isso vira uma
  tentativa de publicar em `docker.io/library/dockerls`, recusada com um
  "denied" que não explica nada. A imagem passa a ser reetiquetada para o
  destino antes do push: era o passo que faltava entre escolher o registry e
  publicar nele.
- **O assistente interativo perguntava o registry e ignorava a resposta.** Ele
  oferecia `dockerhub`, `ghcr` e `harbor`, e nenhuma das escolhas mudava o
  destino do push.
- **O `build` publicava imagens sem `maintainer` nem `security.scanner`** — os
  dois rótulos que a regra DF007 deste projeto cobra de todo Dockerfile que ele
  analisa. Cobrava dos outros o que não fazia. Os rótulos agora são derivados
  das respostas, com as chaves `org.opencontainers.image.*` da especificação
  OCI, e rótulos vazios são omitidos em vez de gravados em branco: uma chave
  presente e vazia é pior que ausente, porque um inventário a lê como
  respondida.

Um build local para experimentar continua não exigindo nada: os rótulos só são
cobrados de quem vai publicar. Transformar um teste local em formulário faria
as pessoas desligarem a checagem inteira.

## [1.5.0] -- 2026-08-18

### Corrigido — o catálogo endurecido recomendava runtimes mortos

`dockerls recommend node` respondia com `gcr.io/distroless/nodejs`, cujas tags
publicadas são `10`, `12` e `14` — Node em fim de vida há anos, apresentado
como "alternativa endurecida" com o carimbo desta ferramenta. O mesmo com
`distroless/java`, que só publica Java 11. A causa era o mapa de apelidos ser
**1:1**: os runtimes atuais do Distroless vivem em repositórios com o nome
versionado (`nodejs22-debian12`), que nenhum alias único alcançava.

O mapa passa a ser 1:N, com os repositórios verificados contra o registry em
2026-08-18, e os legados ficam de fora. Consequências medidas:

| Consulta | Antes | Agora |
|---|---|---|
| `node` | `distroless/nodejs` (10, 12, 14) | `distroless/nodejs22-debian12`, `nodejs20-debian12` |
| `java` | Chainguard **403** — nenhuma alternativa | `chainguard/jdk`, `chainguard/jre`, `distroless/java21-debian12` |
| `maven` | só Docker Hub | `chainguard/maven` |
| `gradle` | nada | `chainguard/gradle` |

`chainguard/java` não existe (responde 403); as imagens reais são `jdk` e
`jre`, e as duas são oferecidas porque escolher entre elas depende de a
aplicação compilar em runtime — não é decisão de quem escaneia. O Distroless
não publica ferramenta de build, e isso é declarado como ausência em vez de
mapeado para algo parecido.

### Corrigido — nomes ilegíveis na tabela

Com treze colunas e `overflow="fold"`, `gcr.io/distroless/nodejs22-debian12`
era quebrado no meio da palavra e saía em duas ou três linhas, enquanto a
coluna `Source` encostada já dizia "Distroless". O prefixo redundante sai da
coluna `Image`; o nome que identifica o runtime fica. Um registry que a tabela
não identifica (`ghcr.io/org/app`) continua inteiro, porque ali o host **é** a
identidade. A referência completa segue no `--format json`, na linha `Pin to:`
e na evidência — que é o que alguém copia para um Dockerfile.

### Corrigido — detecção de ecossistema

`maven`, `gradle`, `tomcat` e `jetty` caíam em `generic` e não recebiam
conselho nenhum, apesar de serem exatamente onde um projeto Java de verdade
começa o Dockerfile. A detecção passa a casar o **nome do repositório**, sem
registry e sem tag: `cgr.dev/chainguard/go` não era reconhecido como Go (o
"go" estava no caminho, não na tag), e qualquer tag contendo "go"
classificava a imagem errada.

## [1.4.0] -- 2026-08-18

### Alterado — a imagem passa a partir de Alpine

Sobre a base Debian slim, o `trivy` reportava **seis CRITICAL, nenhuma com
versão de correção publicada** — `apt-get upgrade` não resolvia uma sequer:

| CVE | Pacote | bookworm | trixie |
|---|---|---|---|
| CVE-2025-7458 | libsqlite3-0 | vulnerável | corrigida |
| CVE-2023-45853 | zlib1g | vulnerável | corrigida |
| CVE-2026-13221 | perl-base | vulnerável | vulnerável |
| CVE-2026-42496 | perl-base (Archive::Tar) | vulnerável | vulnerável |
| CVE-2026-57433 | perl-base (Storable) | vulnerável | vulnerável |
| CVE-2026-8376 | perl-base | vulnerável | vulnerável |

(estado conferido no rastreador de segurança do Debian, não deduzido)

As quatro do `perl` são o caso decisivo: o DockerLs não invoca perl em lugar
nenhum. Ele está na imagem porque `perl-base` é `Essential: yes` no Debian —
nem `apt-get purge` o remove sem quebrar o `dpkg` — e segue vulnerável também
no trixie, com correção só no `sid`. Numa distribuição sem dpkg o pacote não
existe, e com ele somem quatro das seis; as outras duas somem porque o Alpine
carrega `zlib` e `sqlite-libs` mais novos que os do bookworm.

A alternativa era silenciar as quatro no `.dockerls-ignore.yaml`. Trocar a base
resolve de verdade em vez de esconder — numa ferramenta que recusa apresentar
como segura uma imagem que não pôde medir, fazer o próprio portão passar por
supressão seria o pior precedente possível.

**O custo, declarado:** a libc passa a ser musl. É aceitável porque toda
dependência compilada deste projeto (`pydantic-core`, `sqlalchemy`, `pyyaml`,
`greenlet`, `rpds-py`) publica wheel `musllinux` — verificado no PyPI —, então
nada é compilado no build e nenhuma toolchain entra na imagem. `useradd` /
`groupadd` viram `adduser` / `addgroup`, e `apt-get upgrade` vira
`apk upgrade --no-cache`.

## [1.3.3] -- 2026-08-18

### Corrigido

- **O portão `--fail-on` reprovava anunciando "0 finding(s)"** *(alta —
  correção)*. O portão em si estava certo: `_should_fail` lê as contagens do
  scan completo. Quem mentia era o resumo, que procurava os culpados na
  amostra do relatório — `vulnerabilities[:100]`, cortada na ordem em que o
  scanner devolveu, que é ordem de pacote e não de gravidade. Numa imagem com
  mais de cem achados, as CRITICAL caíam inteiramente fora da amostra e o
  build reprovava com a frase autocontraditória *"Vulnerabilities exceed
  threshold (critical): 0 finding(s) at or above CRITICAL"* — sem nenhum CVE
  para investigar. A amostra passa a ser ordenada por severidade antes do
  corte, então o que decide o portão é o que sobrevive nela; e o número
  exibido passa a vir das contagens do scan, nunca da amostra. O número que
  reprova e o número que se lê têm de ser o mesmo número.

## [1.3.2] -- 2026-08-18

### Alterado — a imagem publicada não embute mais um scanner

O binário do Trivy era copiado para o stage final (127,92 MB) e as dependências
Go dele (`golang.org/x/crypto`, `stdlib`, `go-git`) respondiam por ~330 das 339
vulnerabilidades que o Docker Scout reportava contra a imagem. Nenhuma delas era
do código Python deste projeto: eram do scanner que viajava dentro dela, pinado
em `aquasec/trivy:0.55.2`, de setembro de 2024.

**Isto é uma perda real de capacidade, e está declarada no próprio Dockerfile.**
Dentro do container, `recommend`, `analyze`, `compare`, `advisor`,
`alternatives`, `sbom` e o passo de scan do `build` não conseguem medir nada: o
`ScannerFactory` não encontra `trivy` nem `grype` no PATH e devolve
`SCANNER_MISSING`, que pela política deste projeto vira "não verificado" e nunca
"limpo". Os comandos que não dependem de scanner (`analyze-dockerfile`,
`controls`, `search`, `version`, `cache`, `login`) seguem funcionando. Para
escanear, rode o `dockerls` num host com trivy ou grype instalado. O CI não é
afetado: `security.yml` escaneia com a `aquasecurity/trivy-action`, que nunca
dependeu do binário embutido.

### Corrigido

- **`libexpat1` desatualizado na base** *(2 CVEs CRITICAL)*. `CVE-2024-45491` e
  `CVE-2024-45492`, versão instalada `2.5.0-1`, corrigidas em
  `2.5.0-1+deb12u1` — era isto que derrubava `dockerls build --fail-on
  critical`. O stage final passa a rodar `apt-get update && apt-get upgrade -y`
  antes de qualquer outra coisa, com a lista de índices removida na mesma
  camada. `upgrade` em vez de fixar a versão na mão de propósito: fixar corrige
  o pacote que o scan de hoje viu e trava a atualização dos que ele ainda não
  viu.
- **Digest da base subido.** O pin apontava para `python:3.12.4-slim-bookworm`
  de meados de 2024, que é a causa de a base chegar velha a cada build. Agora
  aponta para o digest de manifest-list de `python:3.12-slim-bookworm`
  resolvido em 2026-08-18 (`sha256:a116514e…`), verificado como OCI index
  cobrindo amd64, arm64, arm, 386 e ppc64le.
- **Os LABELs estavam no stage errado.** `maintainer` e `security.scanner`
  ficavam no stage `builder`, que não vira imagem nenhuma — a imagem publicada
  saía sem nenhum dos dois, que são exatamente os rótulos que a regra DF007
  deste projeto cobra. Foram para o stage final, junto das anotações
  `org.opencontainers.image.*`.
- **Falso positivo em DF007** *(defeito no validador, encontrado rodando o
  próprio `analyze-dockerfile` contra este Dockerfile)*. O padrão de LABEL era
  `^LABEL\s+([^=]+)=(.*)$`: casava até o primeiro `=` e engolia o resto da
  linha como *valor*. Numa instrução idiomática com vários pares, só a primeira
  chave existia — então um Dockerfile que declara `security.scanner` era
  reprovado por não declarar `security.scanner`. O parser passa a ler todos os
  pares (com `shlex`, porque valores entre aspas contêm espaços) e a forma
  legada `LABEL chave valor` continua funcionando. Um falso positivo é pior que
  nenhuma checagem: ele ensina o leitor a ignorar o aviso.

## [1.3.1] -- 2026-08-18

### Corrigido — segurança

- **O pull do próprio scanner agora passa pela política de rede** *(alta)*. A
  política de SSRF guardava o inspector de registry, que é *uma* das portas:
  `trivy image X` e `grype X` abrem o próprio socket e puxam a imagem
  sozinhos. Uma referência como `169.254.169.254/latest:v1` — sintaticamente
  válida e chegando de uma variável de CI, de um arquivo de config ou de um
  pull request — mirava a conexão do scanner no endpoint de metadados da nuvem
  enquanto a porta guardada continuava fechada. A verificação agora acontece
  **antes** do binário ser invocado, e a recusa é um `ScanResult` com status
  `ERROR` e `error_kind=BLOCKED_BY_POLICY` — nunca uma lista de achados vazia,
  que seria indistinguível de uma imagem limpa.
- **`localhost/evil` era lido como um usuário do Docker Hub.** A regra "o
  primeiro componente é um host de registry" testava só ponto-ou-dois-pontos,
  e `localhost` não tem nenhum dos dois — justamente o host interessante para
  quem ataca. A regra passa a viver num único lugar
  (`domain/value_objects/image_reference.py`), com `localhost` explícito, e
  `DockerImage.registry_host` delega para ela: duas cópias de "o que conta
  como host" é como um caso acaba guardado num lugar e não no outro.

`BLOCKED_BY_POLICY` é deliberadamente **não** `is_scanner_fault`: um segundo
scanner puxaria do mesmo host recusado, então o fallback só gastaria o dobro do
tempo para chegar à mesma recusa. Docker Hub nunca é julgado e registries
internos em RFC1918 continuam escaneáveis — nada de legítimo foi fechado.

## [1.3.0] -- 2026-08-18

### Adicionado

- **Referências documentais nas regras do `analyze-dockerfile`.** Cada achado
  passa a citar o controle publicado que a regra implementa — CIS Docker
  Benchmark, NIST SP 800-190, OWASP Docker Security Cheat Sheet, documentação
  da Docker e especificação OCI — em vez de apenas um código opaco. O motivo é
  prático: `DF002` não significa nada fora deste repositório, então quem
  recebia o achado só podia obedecer ou ignorar. Um achado que cita *CIS Docker
  Benchmark 4.1* pode ser discutido, escalado, dispensado com justificativa e
  mapeado para um programa de auditoria. As citações aparecem no terminal
  (abaixo da tabela, só para `FAIL` e `WARN`) e nos campos `references` e
  `rationale` do `--format json`.
- **Comando `dockerls controls`.** Lista o catálogo inteiro sem exigir que
  alguém produza antes um Dockerfile que falhe, e explica uma regra específica
  com `dockerls controls DF002`. Também tem `--format json`, e falha com exit
  code `1` numa regra desconhecida em vez de responder uma lista vazia.

### Notas sobre a exatidão das citações

Todo identificador e todo título foi conferido na fonte primária, não
recuperado de memória: a seção 4 do CIS Docker Benchmark contra a
implementação da própria Docker (`docker/docker-bench-security`,
`tests/4_container_images.sh`), o OWASP Docker Security Cheat Sheet contra a
página publicada, e o NIST SP 800-190 contra o sumário da publicação oficial.
A conferência mudou o conteúdo: **três das quatro citações rascunhadas de
memória estavam erradas** — `NIST SP 800-190 4.4.2` é *Unbounded network access
from containers*, não "least privilege", e `OWASP RULE #8` é *Set filesystem
and volumes to read-only*, não "minimal base images". Uma citação errada é pior
que nenhuma, porque um leitor que confere e encontra outro assunto passa a
duvidar do relatório inteiro.

Onde nenhum controle publicado cobre a regra, isso é dito explicitamente em vez
de esticado: `controls_for` devolve tupla vazia e os renderizadores dizem que a
orientação é do próprio DockerLs. Inventar um número plausível seria pior que
não ter nenhum, porque é o tipo de erro que sobrevive à revisão.

## [1.2.0] -- 2026-08-18

Release de correções. Reúne duas auditorias -- uma de evidência, outra de
desempenho -- e o motor multi-source construído sobre elas. O relatório
completo de cada achado, com severidade e caminho de código, está em
`AUDIT.md`.

### Desempenho — auditoria de CPU e memória (relatório em `AUDIT.md`)

Segunda auditoria, dirigida a consumo de recursos. Tudo foi medido antes de
ser alterado, e o perfil do pipeline inteiro mostrou que ele não é limitado
por CPU — os dois custos reais estavam fora dele.

- **`redact()` levava 19 segundos por imagem escaneada** *(crítico)*. O padrão
  de chave começava com `[\w.-]*`, então numa descrição de CVE com centenas
  de caracteres de texto corrido o motor de regex tentava cada divisão
  possível em cada posição — backtracking catastrófico. Numa execução de 100
  tags isso é meia hora de CPU só mascarando. A correção inverte a ordem: a
  alternância literal vem primeiro, o motor varre atrás da palavra-chave e só
  então expande para os lados. **19 445 ms → 245 ms (79x)**, com a saída
  idêntica caractere por caractere e teste de equivalência sobre doze
  formatos.
- **A contagem de workers ignorava a máquina.** Cada worker segura um
  *processo de scanner*, não uma corrotina: o Trivy carrega uma base de
  centenas de MB e consome um núcleo inteiro. Dez deles num runner de dois
  núcleos terminam mais devagar, despejam o page cache e podem levar o job a
  ser morto por falta de memória. Pior: esta ferramenta analisa containers e
  costuma rodar dentro de um, onde `os.cpu_count()` reporta os núcleos do
  *host* enquanto o cgroup permite uma fração de um núcleo. `workers` passa a
  ter padrão `0` = "dimensione para esta máquina", derivado da cota de cgroup
  (v2 e v1), da máscara de afinidade e da memória disponível.
  `cross_validate_workers` segue a mesma regra e é limitado pelo pool
  primário. Valor explícito continua sendo honrado, com aviso quando excede o
  que a máquina comporta.

### Alterado

- **`--workers 0` passou a significar "dimensione para esta máquina"** em vez
  de ser recusado. O deadlock que a recusa protegia (um zero chegando a um
  `asyncio.Semaphore`) é hoje impossível por construção: o resolvedor nunca
  devolve zero e o caso de uso continua validando o argumento. Valores
  negativos ou acima de 50 seguem recusados.
- Novo `benchmarks/bench_resources.py`, que fixa o orçamento de redação, o
  dimensionamento de workers e a memória de uma execução — as três medidas
  cujas regressões são invisíveis num teste funcional, porque a saída não
  muda, só o custo.

### Corrigido — auditoria de evidência (relatório completo em `AUDIT.md`)

Uma auditoria dirigida ao princípio "uma imagem que não pôde ser medida nunca
é apresentada como segura" encontrou treze pontos onde a ferramenta o
violava. Quatro eram reproduzíveis contra o pacote instalado.

- **`production_ready` ignorava a confiança** *(crítico)*. `SecurityTier`
  decide com o score e nada mais, então um scan `PARTIAL` sem achados nos
  alvos que conseguiu ler produzia tier A e `production_ready = True` — na
  **mesma análise** que reportava `confidence = UNVERIFIED`. Agora existe uma
  política central (`ProductionReadiness`) que é a única escritora do campo,
  consumindo tier, confiança, verificação do scan, EOL, contagens e
  divergência; o default do campo passou a ser `False`, para que uma análise
  que nunca chegou à política não seja "pronta por omissão".
- **EOL desconhecido virava "não EOL"**. Todo caminho de falha do
  `EndOfLifeChecker` — produto fora do catálogo, rede indisponível, versão
  não extraída — devolvia `False`, e o score tratava isso como confirmação de
  que a release estava dentro do suporte. Agora `eol_status` é tri-state:
  `UNKNOWN` não penaliza, não credita, aparece nos trade-offs e limita a
  confiança.
- **Feed de threat intel fora do ar virava "não explorado"**. Com o catálogo
  CISA KEV inacessível, todo CVE ficava `exploit_known=False` e o relatório
  imprimia, afirmativamente, `no known-exploited (CISA KEV) vulnerabilities`.
  A frase mais forte que esta ferramenta produz sobre exploração real era
  emitida exatamente quando nada havia sido consultado. `kev_status` passa a
  ser tri-state, `epss_known`/`epss_percentile` acompanham o EPSS, e a
  afirmação só sai nomeando quantos achados foram de fato checados.
- **SSRF por referência de imagem** *(demonstrado)*. `dockerls analyze
  169.254.169.254/latest` é uma referência bem formada, e resolvê-la
  significava requisitar o endpoint de metadados da nuvem — num runner de CI,
  a partir de um nome que veio de um PR ou de uma variável de ambiente.
  Agora há `NetworkPolicy` (regra, no domínio) e `HostGuard` (resolução, na
  infraestrutura): loopback e link-local bloqueados por padrão, RFC1918
  permitido porque registry interno é caso legítimo, allowlist explícita
  vencendo os dois, e decisão por **resolução** — todos os endereços de um
  nome precisam passar, o que fecha também o rebinding.
- **Injeção de markup no terminal** *(demonstrado)*. Descrições de CVE, nomes
  de pacote e stderr de scanner iam para o Rich sem escape, e
  `[red]FIXED - no action needed[/red]` era *interpretado*: quem controla um
  advisory upstream ou os metadados de um pacote controlava a formatação do
  relatório. `cli/text.safe()` escapa toda interpolação de terceiros.
- **Saída de scanner sem teto**. `communicate()` acumulava stdout inteiro em
  memória. Passa a haver limite por fluxo (256 MiB); o excesso é classificado
  como `INVALID_OUTPUT`, que já é um estado não verificado. Junto veio um
  vazamento de recurso: um processo morto por timeout deixava o transporte
  para o coletor de lixo, e o `__del__` rodava depois do event loop fechar.
- **Evidência bruta gravada sem redação**. O mascaramento existia só no sink
  de log — a porta que ninguém usa. Extraído para `infrastructure/redaction.py`
  e aplicado também aos artefatos de scan e ao manifesto, com teste afirmando
  que CVE, pacote e versões sobrevivem intactos.
- **Cache reusava medição incompatível**. A chave não incluía qual scanner
  produziu os números nem em que versão, então uma troca de Trivy para Grype,
  ou um upgrade de scanner, continuava servindo o resultado antigo dentro do
  TTL. A identidade do scanner entra no fingerprint, e `CACHE_SCHEMA_VERSION`
  foi para `v4`.
- **EPSS era binário**. `epss_score >= 0.5` fazia 0.97 e 0.51 custarem o
  mesmo e 0.49 custar zero. O degrau foi preservado (é o que o operador
  entende) e ganhou um termo contínuo por cima, com teto abaixo de um único
  HIGH. Há teste de monotonicidade.
- **Cross-validation comparava contagens**. Dois scanners reportando um
  CRITICAL cada, para CVEs diferentes, "concordavam". A comparação passa a
  ser por identidade (`CVE|pacote`) e o desfecho é classificado em
  `AGREEMENT` / `MINOR_DIVERGENCE` / `MATERIAL_DIVERGENCE` /
  `NO_SECOND_SCANNER`. Divergência menor não disputa o score, mas impede
  `HIGH`.

### Adicionado

- **Proveniência da execução**: versão do DockerLs, identidade do scanner
  (nome e versão, lidas do próprio binário), timestamp e fingerprint da
  análise no manifesto de evidência — uma análise que ninguém consegue
  reconstruir é uma afirmação, não evidência.
- **Veredito explícito na CLI**: nível de confiança, o que foi verificado (ou
  o que falta), e se a imagem pode ir a produção com os bloqueios nomeados.
  A saída passou a tornar impossível ler uma coluna de achados vazia como
  "limpa".
- **Novos campos nos exporters**, todos aditivos: `production_ready`,
  `readiness_blockers` (códigos estáveis), `eol_status`, `cross_validation`.
- **87 testes novos**: invariantes de propriedade (falha nunca vira
  segurança, `UNKNOWN` nunca vira `FALSE`, hardening nunca compensa
  CRITICAL, EOL confirmado nunca é production ready, EPSS monotônico) e
  adversariais (SSRF, rebinding, injeção de markup, saída ilimitada,
  vazamento de credencial na evidência).

### Adicionado — motor de decisão multi-source

- **Abstração de fontes de imagem** (`application/services/source_registry.py`).
  Catálogos se registram com nome, rótulo e construtor; os comandos resolvem uma
  *seleção* em vez de ramificar em nomes de fornecedor. Adicionar um provedor é
  um `register()` na camada de wiring — nenhum comando muda, e nenhum
  `if source == ...` cresce um braço novo. Expõe `--source` (repetível) e
  `--all-sources` em `search`, `recommend`, `advisor` e `alternatives`;
  `--no-hardened` mantém o significado que sempre teve.
- **Docker Hardened Images como fonte** (`integrations/dhi/`). O catálogo é
  público, o registry (`dhi.io`) não é: sem credencial os candidatos DHI ficam
  `UNVERIFIED` e **nunca** são ranqueados. Por isso a fonte é opt-in
  (`--source dhi` / `include_dhi_source`). O catálogo é lido com **uma**
  requisição à API do GitHub por TTL (árvore recursiva reduzida a um índice
  compacto e cacheado) e depois só as definições da imagem consultada, via CDN —
  nunca um clone, nunca uma varredura de diretórios. Medido: 1 requisição a frio
  sobre 11 mil blobs, **0** a quente.
- **Metadados declarados, separados do que foi medido**
  (`domain/entities/declared_metadata.py`). Uma definição de build é uma
  *declaração* do fornecedor: útil, auditável, e não uma medição. Quando uma
  declaração contradiz o config OCI da imagem publicada, a contradição vira
  achado em vez de ser resolvida em silêncio.
- **Digest-first** (`integrations/registry/inspector.py`). Toda tag sem digest é
  resolvida no registry antes do scan. Isso fixa a recomendação em bytes
  imutáveis (`Pin to: node@sha256:...`) e faz a deduplicação valer **entre**
  catálogos: 40 tags apontando para 12 manifestos custam 12 scans e 40 `HEAD`,
  não 40 scans. O blob de config é hasheado e conferido contra o digest que o
  endereçava; divergência descarta o config em vez de confiar na rede.
- **Hardening Score** (`domain/value_objects/hardening.py`), pontuado sobre os
  fatos **determinados** e reportando `coverage`. Fatos são de três estados:
  `unknown` nunca ganha crédito em direção nenhuma, e abaixo de 25% de cobertura
  o número aparece como `n/a` em vez de fingir ser uma medição. O score não entra
  no `SecurityScore` e no ranking só é consultado *depois* da posição de
  vulnerabilidade — é a razão estrutural de nunca poder mascarar um CRITICAL.
- **Attack Surface Score** (`domain/value_objects/attack_surface.py`), escala
  invertida (maior é pior), rotulada como tal em toda renderização. Tamanho não
  pontua: pacotes, shell, gerenciador de pacotes, ferramentas de debug, SUID e
  privilégio pontuam.
- **Confidence** (`domain/value_objects/confidence.py`):
  `HIGH`/`MEDIUM`/`LOW`/`UNVERIFIED`. `UNVERIFIED` é um piso — nenhum outro sinal
  tira um candidato dele, e o ranking nunca o coloca acima de algo medido.
- **`dockerls alternatives <image:tag>`**: alternativas mais seguras para a
  imagem que você já roda. A imagem atual é escaneada pelo mesmo pipeline dos
  candidatos, então a comparação é entre duas medições. Se ela não puder ser
  escaneada, o comando termina em `1` — sem linha de base não há melhoria a
  afirmar.
- **Inteligência de migração** (`application/services/migration.py`), usada por
  `alternatives` e pelo `advisor`: troca de libc (musl/glibc), troca de
  gerenciador de pacotes, ausência de shell, arquiteturas perdidas, mudança de
  publicador — cada uma levantada sempre que a evidência **permite** o problema.
  Compatibilidade nunca é afirmada; o checklist existe porque essa pergunta só
  se responde executando.
- **`dockerls advisor node:22-alpine`**: com uma tag no argumento, o advisor
  passa a explicar a migração a partir dela. Sem tag, comportamento inalterado.
- **Distribuição base reportada pelo scanner** (`ScanResult.os_family`), lida do
  `Metadata.OS` do Trivy e do bloco `distro` do Grype. É o que torna a análise de
  libc uma medição em vez de um palpite a partir do nome da tag.
- **Rate limiting e circuit breaker** reutilizáveis (`utils/rate_limit.py`) para
  provedores externos, e **`doctor`** agora lista as fontes disponíveis, quais
  são opt-in e quais exigem credencial.
- **Observabilidade**: `digests_resolved` e `images_inspected` em `RunMetrics`,
  ao lado dos contadores que já existiam.
- **`benchmarks/bench_multi_source.py`**: mede deduplicação por digest, custo do
  índice do catálogo (frio/quente) e ranqueamento de até 10 mil candidatos.

### Segurança

- **Parsing YAML com limites explícitos** (`utils/safe_yaml.py`) para todo
  documento vindo da rede: teto de bytes, teto de profundidade e — o ponto que
  importa — **medição da expansão antes da construção**. A primeira versão deste
  guard contava aliases, e o teste adversarial mostrou que isso não basta: nove
  níveis de aliasing nônuplo são ~70 aliases (abaixo de qualquer limite
  razoável) e expandem para 387 milhões de nós. Agora o documento é *composto*
  num grafo (onde um alias é uma aresta compartilhada e custa nada), o tamanho
  expandido é calculado sobre esse grafo com memoização e clamp, e só então o
  documento é construído. A bomba clássica é recusada em 2 ms, e o teste afirma
  o tempo — um guard que recusa só depois de expandir executou o ataque em vez
  de impedi-lo.
- **Conteúdo de catálogo nunca vira URL sem validação**: caminhos de definição
  são casados contra um padrão ancorado (nada de `..`, nada fora de `image/`), o
  cliente não segue redirects, e uma definição que publique para um registry que
  não seja `dhi.io` não produz candidato — conteúdo remoto não redireciona um
  scan para um host arbitrário.
- **Índice de catálogo em cache é revalidado na leitura**: o cache é um arquivo
  que outro processo pode escrever, e uma entrada com caminhos fora do formato é
  rejeitada por inteiro, nunca filtrada.
- **Casamento de pacote é exato, não por substring**: `libcurl4` não é `curl`, e
  tratá-lo como tal inventaria uma capacidade que a imagem não tem.
- Suíte adversarial nova (`tests/adversarial/`): bombas YAML, documentos
  gigantes, aninhamento profundo, tags e repositórios maliciosos, referências que
  parecem flags de scanner, respostas de registry inválidas, blob de config com
  digest divergente, cache adulterado, rate limit e circuit breaker.

### Corrigido

- **`CACHE_SCHEMA_VERSION` foi para `v3`.** Uma entrada `v2` ainda *validaria*
  contra o modelo novo — o pydantic preencheria os campos ausentes com os
  padrões — e é justamente esse o problema: os padrões são "nada determinado" e
  `UNVERIFIED`, então uma linha velha apresentaria a imagem como não
  inspecionada em vez de não escaneada. Órfãs as linhas antigas custa uma
  execução fria e elimina a ambiguidade.
- **Tokens fine-grained do GitHub (`github_pat_...`) são mascarados nos logs.**
  O formato clássico (`ghp_...`) já era; o novo não casava com o mesmo padrão.
  Nada registra o token em log, mas o mascaramento existe para o caso em que
  ele chega lá por uma mensagem de exceção, sem chave que o identifique.
- **`--format json` podia sair inválido** em `alternatives` e `advisor`: quando a
  imagem atual não podia ser escaneada, o aviso legível era impresso no stdout,
  na frente do documento JSON. Diagnósticos agora vão para o stderr — um formato
  legível por máquina só é legível por máquina se nada mais cair no fluxo.

### Alterado

- `recommend` ganhou as colunas `Hard`, `Surf` e `Conf` e uma seção
  **"Why this image?"** com trade-offs; nenhuma coluna existente saiu ou mudou de
  posição.
- Exportadores: JSON, CSV, HTML, Markdown e SARIF carregam as dimensões novas.
  Em CSV as colunas foram **acrescentadas ao fim** (um consumidor que indexa por
  posição continua funcionando); em SARIF elas vão em `properties` por resultado,
  que é o ponto de extensão da especificação.
- O ranqueamento final passou a ser multi-source e explícito: confiança →
  vulnerabilidade medida → hardening (só com cobertura suficiente) → superfície →
  remediabilidade. A ordem *é* a política, e está documentada num único lugar
  (`application/services/verdict.ranking_key`).

### Adicionado

- **Um contrato de exit code documentado** (`dockerls/exit_codes.py`, seção
  "Exit codes" no README), aplicado em toda a CLI: `0` sucesso, `1` erro de
  execução (dependência ausente, rede, Dockerfile inexistente, erro do `docker
  build`), `2` política violada (validação com `errors > 0`, `--fail-on`
  acionado). Antes os números eram literais espalhados pelos comandos e não
  concordavam entre si — `build --validate-only` devolvia `2` para uma falha
  que o teste esperava como `1`, e nada estava escrito em lugar nenhum. A
  distinção entre `1` e `2` é o que permite a um pipeline separar "o scanner
  não rodou" de "a imagem reprovou".
- **`dockerls analyze --wide`**, que renderiza a tabela de vulnerabilidades na
  largura que ela pedir, sem truncar coluna alguma.
- **`dockerls build --list-templates`**, que expõe os templates hardened
  aceitos por `--base`. `list_templates()` existia na interface de domínio
  desde o início e nada o chamava.
- Documentação de `build` e `analyze-dockerfile` no README — os dois comandos
  eram inteiramente ausentes dele.

- **Uma proteção estrutural contra a classe de bug que continuava
  reaparecendo** (`tests/unit/test_no_dead_configuration.py`). Cinco vezes esta
  base de código entregou algo declarado, documentado e nunca alcançado em
  tempo de execução, e duas vezes a própria correção foi parcial. Pegar isso
  lendo o código já falhou repetidamente, então virou teste: todo campo de
  `Settings` precisa ser lido fora de `settings.py`, todo símbolo público
  precisa ser alcançável a partir de algum ponto do pacote, e nenhum módulo
  pode ficar órfão. Ele encontrou mais oito casos já na primeira execução.

### Corrigido (auditoria completa: o hardening que nunca era aplicado)

- **`--hardened`/`--base` nunca leram os templates versionados no repositório**
  (`infrastructure/dockerfile_validator.py`). `TEMPLATES_DIR` subia dois níveis
  a partir de `dockerls/infrastructure/` e reentrava em `infrastructure/
  templates`, resolvendo para `<raiz-do-repo>/infrastructure/templates` — um
  diretório que nunca existiu, e que numa instalação por wheel apontava para
  dentro de `site-packages/`. `exists()` dava `False` em toda execução, então
  os três templates caíam num gerador genérico que abria com
  `FROM <base>:latest`: a ferramenta reprovava base flutuante nas imagens dos
  outros (regra DF001) e emitia uma na própria saída "hardened". Esse gerador
  foi removido; uma base sem template agora falha alto, dizendo quais existem.
- **Os templates não iam para a wheel.** São arquivos de dados, e
  `packages.find` sozinho não os inclui: `build --hardened` funcionava num
  checkout e falhava a partir de um `pip install`. Declarados em
  `[tool.setuptools.package-data]`.
- **`list_templates()` anunciava `java`**, para o qual nunca houve arquivo.
  `--base java` caía calado numa base diferente da pedida; agora a lista é
  derivada do que existe em disco e `--base` é validado antes do build.
- **O template Go rodava como root** (`FROM scratch` sem `USER`) e trazia um
  `HEALTHCHECK ... || exit 0` — inerte na forma exec e, se valesse, um portão
  que nunca reprova. Corrigidos para `USER 65534:65534` e healthcheck real.
- **`FROM scratch` era reportado como tag flutuante** (severidade HIGH). É a
  imagem vazia embutida no Docker: não tem tag alguma para pinar. A regra
  reprovava justamente os Dockerfiles mais enxutos que existem.
- **`USER 0` e `USER 0:0` passavam na regra `non_root_user`**, que só comparava
  com a string `"root"`. Um container rodando como uid 0 recebia PASS.
- **Uma diretiva final terminada em `\` desaparecia** do parser: um `RUN sudo
  ...` na última linha do arquivo nunca era verificado. Os números de linha
  relatados passam a apontar para o início da diretiva, não para o fim.

### Corrigido (auditoria completa: robustez, concorrência e segurança)

- **Referências que na verdade eram flags do scanner passavam pela validação**
  (`utils/validation.py`). O hífen é legal no meio de um nome, então
  `--ignore-unfixed` ou `--offline-scan` satisfaziam o padrão e chegavam ao
  `trivy`/`grype` como opção em vez de alvo — controle sobre como, ou se, o
  scan rodava, a partir de uma referência vinda de variável de CI.
- **Um keyring quebrado derrubava qualquer comando** (`utils/auth.py`). O
  backend SecretService é uma extensão Rust: quando a instalação está
  quebrada ele levanta `pyo3_runtime.PanicException`, que herda de
  `BaseException` e portanto escapava do `except Exception`. Ler credenciais
  opcionais nunca pode abortar a execução; `KeyboardInterrupt` e `SystemExit`
  seguem propagando.
- **Uma falha de cache descartava um scan válido**
  (`use_cases/recommend_images.py`). O erro de escrita subia até o handler que
  reporta falhas de *scan*, então uma imagem inteiramente escaneada e
  pontuada era registrada como `ERROR`/não verificada — bastava o SQLite estar
  travado, o que é rotina sob a concorrência que este caso de uso cria.
- **Rajada de requisições idênticas contra CISA KEV e endoflife.date.** Os
  memos só fechavam a janela *depois* da resposta chegar, e `recommend`
  enriquece todas as tags em paralelo: uma execução de 100 tags disparava 100
  downloads simultâneos do catálogo KEV (megabytes) e até 200 consultas
  idênticas ao endoflife.date — a rajada que provocava o rate limiting e fazia
  tags do mesmo produto receberem vereditos de EOL diferentes na mesma
  execução. Serializados por lock, com dupla checagem.
- **Corrida na escrita do cache SQLite** (`cache/sqlite_cache.py`): o
  select-then-insert tinha janela real para duas threads inserirem a mesma
  chave única. Trocado por um upsert atômico (`ON CONFLICT DO UPDATE`).
- **Injeção de HTML no relatório de build** (`cli/commands/build.py`). `--tag`,
  o caminho do Dockerfile e o tier eram interpolados crus na página; uma tag
  como `x"><script>` transformava um relatório que alguém abre no navegador em
  vetor de execução. O caminho `export --format html` já escapava — este não.
- **`"metrics": null` do Grype quebrava o parse inteiro** de um scan bom.
- **Escritas de arquivo sem tratamento de erro** (`build --report`,
  `build --output`, `sbom --output`) devolviam traceback em vez de mensagem.
- **`search` e `sbom` respondiam com stack trace** a uma referência malformada,
  enquanto todos os outros comandos já reportavam mensagem.
- **`advisor --workers` tinha default fixo `10`**, que anulava
  `Settings.workers` — a mesma classe de configuração morta já corrigida no
  resto da CLI. E um `--format` desconhecido caía calado na tabela do Rich,
  entregando prosa decorada a quem esperava JSON.
- `DockerHubClient.authenticate()` tratava um 200 com corpo não-JSON (portal
  cativo, página de erro de proxy) como exceção não capturada.
- Um `.dockerignore` presente mas ilegível derrubava a validação inteira por
  causa de um check opcional; agora é reportado como SKIP.

### Removido

- Quatro pacotes vazios e sem referência alguma (`dockerls/models/`,
  `repositories/`, `scanners/`, `services/`) — restos de uma estrutura que
  nunca foi usada.
- `Dockerfile.hardened` na raiz do repositório: saída gerada pelo próprio
  caminho de código defeituoso acima, versionada por acidente, com
  `FROM node:latest` e reprovando nas regras da própria ferramenta. Adicionado
  ao `.gitignore`, junto com `logs/` e `.dockerls/` — e o `.gitignore` estava
  literalmente embrulhado numa cerca de markdown (```` ``` ````).
- `dockerls.egg-info/` do controle de versão: metadado de build, já declarado
  em `.gitignore` mas versionado mesmo assim, que reaparecia como ruído em
  todo diff depois de qualquer `pip install -e`.

### Corrigido (revisão final: veredito falso-positivo de segurança)

Seis defeitos da mesma classe, a pior possível numa ferramenta de segurança:
**dizer que está seguro quando não está**. Um falso FAIL custa o tempo de
quem lê; um falso PASS entrega a imagem em produção com o carimbo da
ferramenta.

- **O fallback do Grype devolvia um scan zerado.** O código era
  `return ScanResult(scan_tool="grype")` sob um comentário `# Parse similar
  ao Trivy...`. Numa máquina sem Trivy e com Grype — a configuração de
  fallback que a própria ferramenta anuncia — **todo build era reportado com
  zero vulnerabilidades** e `--fail-on critical` nunca reprovava nada. O
  parser foi implementado (incluindo a faixa `NEGLIGIBLE`, que só o Grype
  tem e que virava `UNKNOWN`).
- **`--fail-on` passava em silêncio quando o scan não rodava.** Sem scanner
  instalado, `scan_result` era `None`, a condição do portão era pulada e o
  build terminava com exit 0. Um portão que não pôde ser avaliado não é um
  portão aprovado: agora é erro de execução (exit 1).
- **`--fail-on medium` e `--fail-on low` nunca reprovavam.** Só `critical` e
  `high` eram tratados; o resto caía num `return False`. Os quatro níveis
  agora funcionam, cada um reprovando também o que é pior que ele, e um
  limiar desconhecido é rejeitado na CLI antes do build começar em vez de
  virar um portão aberto que parece fechado.
- **`non_root_user` dava PASS num container que sobe como root.** A regra
  aceitava qualquer `USER` do arquivo, então um `USER node` num estágio de
  build satisfazia a verificação enquanto o estágio final rodava como root.
  O parser passou a rastrear estágios e resolver o estágio final, inclusive
  seguindo a herança de `FROM <alias>`.
- **`minimal_base` dava PASS com um runtime gordo.** Mesmo defeito: um
  builder em Alpine fazia um runtime em Ubuntu passar. Agora avalia a base
  do estágio final.
- **`secrets_not_in_env` não via a maioria dos segredos.** A regex
  `^ENV\s+(\S+)=(.*)$` lia só o primeiro par de uma linha, então
  `ENV NODE_ENV=production DOCKER_TOKEN=...` passava batido, e a forma
  legada `ENV KEY value` não casava com nada — nunca era verificada. As duas
  formas do Docker agora são cobertas.
- **`shell_usage` era um check que sempre passava** — não olhava nada,
  apenas adicionava um `PASS` incondicional. Uma regra assim é pior que
  regra nenhuma: afirma ao usuário que o ponto foi verificado e ainda infla
  o score. Agora verifica de fato a forma do `CMD`, e devolve `SKIP` quando
  não há o que verificar. `entrypoint_exec_form` também virou `SKIP`
  explícito em vez de sumir da tabela.

- **O cache guardava supressões de CVE já revogadas.** As regras de ignore e
  o enriquecimento de threat intel são aplicados *antes* de gravar o
  `ImageAnalysis`, mas a chave era só a referência da imagem. Um CVE que
  deixava de ser ignorado — porque a regra foi removida, ou porque o
  `expires` dela venceu — continuava suprimido do score e da tabela até o
  TTL expirar (24h no padrão). O próprio arquivo de ignore promete que uma
  isenção vencida deixa de valer, e o cache desfazia essa promessa em
  silêncio. A chave agora carrega um fingerprint das entradas que mudam a
  análise.
- **O sinal de EPSS sumia nas imagens que mais precisavam dele.** Todos os
  CVEs iam num único GET, e a API do FIRST pagina o resultado — de 200 CVEs
  voltava calada só a primeira página. Quanto mais CRITICAL/HIGH a imagem
  tinha, mais sinal se perdia. Agora vai em lotes, com `limit` explícito em
  vez de confiar no default do serviço, e um lote que falha não descarta os
  que já vieram.
- **Vereditos de EOL inconsistentes dentro da mesma execução.** Um 404 do
  endoflife.date (produto fora do catálogo) não era cacheado, então cada uma
  das ~100 tags repetia a consulta perdida — duas, contando `is_eol` e
  `is_lts`. O volume provocava rate limiting, e aí parte das tags recebia
  dados e parte recebia lista vazia: tags do mesmo produto saíam com
  vereditos de EOL diferentes na mesma tabela. O 404 passou a ser cacheado
  (resposta definitiva); falhas transitórias continuam não sendo.
- **Candidatos promovidos escapavam da cross-validation.** Ela rodava sobre
  o top N *antes* do filtro de tags no registry, então um candidato
  promovido para o lugar de um descartado entrava na tabela sem nunca ter
  passado pelo segundo scanner — com a pontuação apresentada sem contestação
  justamente por não ter sido checada, que é o oposto da garantia descrita
  no README. A ordem foi invertida: filtra as tags primeiro, cross-valida
  quem sobrou. De quebra, deixa de gastar um scan secundário em quem vai
  cair.

### Alterado

- **`--push` passou a funcionar.** A flag era aceita e silenciosamente
  ignorada. Agora publica a tag depois de um build bem-sucedido — e depois
  dos portões, porque publicar uma imagem que reprovou no scan derrota o
  propósito de ter portão.
- **`--config` foi removida.** Era aceita, não tinha formato definido e
  nada a consumia.

### Corrigido (auditoria: o que é afirmado versus o que o código faz)

- **`build --validate-only` não imprimia nada de útil.**
  `_format_validation_response()` descartava o resultado da validação e
  devolvia só `success` e `exit_code`, então a CLI imprimia literalmente
  `None` — sem tabela de checks, sem dizer qual regra falhou, em sucesso e em
  falha. Agora a resposta carrega o `DockerfileValidationResult` completo
  (checks, contagens, score) mais um resumo textual das regras violadas em
  `error`, e a CLI renderiza a **mesma** tabela que `analyze-dockerfile`,
  extraída para `dockerls/cli/rendering.py` em vez de duplicada. Em
  `--ci-mode` a saída é JSON estruturado em stdout, sem cores e sem tabela, e
  o relatório entra também quando a validação reprova. Nenhum caminho imprime
  `None`.
- **Uso normal da CLI vazava log `INFO` (e `DEBUG`) no stderr.** `build` nunca
  tocava em `Settings`, então rodava com o sink padrão do loguru ainda
  ligado — que despeja tudo a partir de DEBUG no terminal. A configuração de
  logging virou um callback de raiz do Typer, que roda antes de qualquer
  subcomando, e o sink de console tem piso `WARNING` independente de
  `DOCKERLS_LOG_LEVEL`; `--verbose` o reabre no nível configurado.
- **Uma validação reprovada não barrava o build.** O portão era
  `if not validation_result`, e um objeto é sempre verdadeiro, então a
  condição nunca disparava: o build seguia adiante com o Dockerfile reprovado.
  Agora `errors > 0` barra o build (com `--force` para ignorar), e uma falha
  em *rodar* a validação (Dockerfile inexistente) é `1`, não `2`.
- **`--fail-on` devolvia `1`** para uma imagem que reprovou no scan, o mesmo
  código de uma falha de infraestrutura. Passou a devolver `2`.
- **O relatório de build lia `analysis.recommendations`**, atributo que
  `DockerfileAnalysis` nunca teve. Só não explodia porque `analysis` era
  `None` em todo teste que exercitava esse caminho. As recomendações vêm das
  sugestões de hardening.
- **`_generate_hardened_dockerfile()` escrevia arquivo direto do caso de
  uso**, furando a interface `HardeningTemplateProvider`. A geração passou
  para trás de `generate_hardened_dockerfile()` na infraestrutura — que
  existia e nada chamava. Escrita em disco é responsabilidade de
  infraestrutura.
- `datetime.utcnow()` (deprecado, sem timezone) e `subprocess.os.environ`
  (acesso a `os` por dentro de outro módulo) em `build_image.py`.
- **Todo `subprocess` invocava o binário pelo nome puro** (`docker`, `trivy`,
  `grype`, `git`), entregando a escolha do que executar ao `$PATH` — qualquer
  diretório gravável mais cedo na ordem de busca decidia. É PATH hijacking, a
  mesma classe de achado que esta ferramenta reporta nas imagens dos outros, e
  um scanner de segurança é um alvo especialmente bom porque é o veredito dele
  que o pipeline confia. Agora tudo passa por `resolve_executable()`
  (`dockerls/utils/executables.py`), que resolve para caminho absoluto via
  `shutil.which` e falha nomeando a ferramenta ausente.
- **Dois `try/except/pass` silenciosos** em `build_image.py` engoliam
  exatamente o erro que se quer ver quando o metadado do relatório sai vazio.
  Passaram a logar em DEBUG, com a exceção capturada estreitada.
- **`analyze-dockerfile --format json` emitia JSON inválido** num terminal
  estreito: a saída ia pelo console do Rich, que quebra a linha na largura do
  terminal, e uma quebra no meio de uma string do documento o torna
  imparseável. Em 80 colunas era o caso comum. Passou a sair por
  `typer.echo`. (`recommend` e `advisor` já haviam sido corrigidos com
  `soft_wrap=True`; este ficou para trás.)
- **A tabela do `analyze` truncava o ID da CVE** num terminal de 80 colunas
  (`CVE-2026…`), que é justamente o campo que não pode ser encurtado — sem
  ele o achado não é consultável em lugar nenhum. A coluna passou a reservar
  largura para `CVE-YYYY-NNNNN`, e pacote/versões viraram as colunas
  flexíveis que cedem espaço. De quebra, a tabela deixou de ser cortada na
  borda direita quando não cabia.
- **Os testes de `build_image` mockavam a camada errada.** Os fixtures
  faziam `validator.validate()` devolver um objeto no formato de
  `AnalyzeDockerfileResponse`, mas a interface devolve um
  `DockerfileValidationResult` direto — e como o caso de uso instancia um
  `AnalyzeDockerfileUseCase` internamente, esse retorno era envelopado numa
  segunda camada e `response.validation.errors` caía num `MagicMock`, que
  nunca é igual a `0`. Todo cenário "sem erros" chegava reprovado. Os
  fixtures passaram a devolver os tipos de domínio corretos.
- `--hardened --validate-only` deixou de ser esperado escrevendo em disco:
  dry-run não tem efeito colateral. O teste antigo cobrava o oposto; agora
  há um caso verificando que **nada** é escrito com `--validate-only` e
  outro, sem a flag, verificando a geração de verdade.

- **`logout` não existia**, então `login` conseguia armazenar credenciais sem
  nenhuma forma suportada de removê-las, e `clear_credentials` era inalcançável.
- **`search` passava por cima da camada de aplicação** e falava direto com um
  repositório, deixando `SearchImagesUseCase` órfão. Agora ele passa pelo seu
  caso de uso como todos os outros comandos.
- **`SecurityTier.production_ready` é calculado pelo domínio e carregado em
  `ImageAnalysis`**, então a CLI e o `--format json` afirmam o veredito do
  domínio em vez de re-derivar a regra a partir da letra do tier.
- Removidos cinco símbolos que nada alcançava: `build_search_use_case` (morto
  depois que `search` passou a ignorá-lo), `RichScanObserver.failed`,
  `DockerImage.is_slim`, `ScanResult.is_usable` (substituído por
  `is_verified`), `EvidenceStore.root` e `with_retry` — este último adicionado
  neste mesmo branch e nunca usado.

- **`export` repetia o bug de configuração sombreada** que havia sido corrigido
  apenas em `recommend`: seu `--workers` carregava um default fixo de 10 e ele
  nunca passava limite de tags, então `DOCKERLS_WORKERS` e `DOCKERLS_MAX_TAGS`
  não tinham efeito nenhum ali. Ele também escrevia em disco sem tratamento de
  erro, então um destino não gravável produzia um traceback. Agora delega os
  dois à configuração, cria diretórios pai ausentes e reporta falha de escrita
  como mensagem com saída 1.
- **`cache clear` / `cache cleanup` não tinham testes nem tratamento de erro.**
  Um banco de cache corrompido derrubava justamente o comando que o usuário
  procura para consertá-lo. Erros de armazenamento agora são reportados com
  saída 1.

- **Um rate limit sustentado do Docker Hub derrubava o comando.** O decorador
  `@retry` usava o default do tenacity, então esgotar as tentativas levantava
  `tenacity.RetryError` — que *não* é um `httpx.HTTPError`, de modo que os
  blocos `except httpx.HTTPError` em `search_tags` e `tag_exists` nunca o
  capturavam. A política de retry agora relança o erro original, e esses
  handlers degradam para resultados parciais como foram escritos para fazer. O
  teste anterior verificava `RetryError` e portanto codificava o bug.
- **As três configurações sombreadas restantes estão conectadas.**
  `cache_ttl_seconds`, `retry_max_attempts` e `retry_backoff_base` ainda não
  eram lidos por ninguém: o TTL era um `86400` fixo e a política de retry vivia
  em um decorador avaliado uma única vez na importação, onde nenhuma
  configuração jamais chegaria. A política agora é construída por chamada a
  partir das settings. Adiciona `tag_cache_ttl_seconds`, que antes era um valor
  fixo de 6 horas.
- **O `mypy strict` era nominal.** O `pyproject.toml` declarava `strict = true`
  enquanto tolerava 20 erros, 13 deles do tipo "cannot subclass BaseModel",
  vindos da ausência do plugin do pydantic. Com `plugins = ["pydantic.mypy"]` e
  `types-PyYAML`, a base de código passa na checagem de tipos sem erros: de 20
  para 0. O CI roda `python -m mypy` para que o plugin seja resolvido no mesmo
  interpretador.

- **Nenhum CI jamais havia rodado neste repositório.** Todos os quatro
  workflows disparavam em `pull_request: branches: [main]`, e não existe branch
  `main` — o default é `claude/docker-secure-finder-q7ikdh`. Lint, mypy e a
  matriz de testes nunca haviam executado em um único commit ou pull request,
  então toda afirmação de qualidade se apoiava apenas em execuções locais. O
  filtro de branch foi removido do `pull_request` (dispara em qualquer base e
  sobrevive à renomeação do branch default), `push` ignora branches do
  dependabot, e um grupo de concorrência colapsa as execuções duplicadas de
  push/PR.
- **A integração com o NVD foi removida em vez de anunciada.** `NVDClient` só
  era instanciado em testes e nada sob `dockerls/` o importava, então
  `NVD_API_KEY` nunca teve efeito algum. Seu único sinal real — status de
  exploração conhecida — já é fornecido pelo `ThreatIntelClient` (CISA KEV +
  EPSS), que *está* conectado e testado; conectar o NVD também teria adicionado
  uma dependência de rede redundante só para tornar verdadeira uma linha de
  documentação. O módulo, sua configuração e suas entradas no README foram
  removidos. Ele continua no histórico do git caso venha a ser desejado.
- **`health` sondava um serviço que a ferramenta não usa mais e deixava de fora
  os que ela usa.** Agora verifica Docker Hub, Chainguard, Distroless,
  endoflife.date, CISA KEV e EPSS — os catálogos que alimentam o pipeline de
  scan e os feeds que ponderam a pontuação.

- **A ocultação de credenciais vazava em 10 de 17 formatos realistas de log.**
  O padrão de chave/valor exigia que o nome da chave fosse seguido
  *imediatamente* por `=` ou `:`, e toda linha em formato JSON tem uma aspa no
  meio (`"token": "..."`) — ou seja, os formatos que um cliente HTTP mais
  provavelmente produz passavam direto. A ocultação agora cobre JSON (aninhado,
  compacto, com aspas simples, multilinha), TOML, querystrings, corpos
  multipart, userinfo em URL, `curl -u`, reprs de `Settings(...)` e esquemas de
  autenticação, além de formatos de credencial autoidentificáveis (PAT do
  Docker, token do GitHub, JWT, chave AWS, token do Slack) que aparecem sem
  chave alguma. São 60 casos adversariais em `test_secret_masking.py`, cada um
  verificando que o segredo está *ausente*, e não que alguma forma mascarada
  está presente.
- **`health` reportava a API do Docker Hub como degradada em toda execução
  saudável** — ela sondava `https://hub.docker.com/v2/`, que responde 404 por
  design. Um alarme sempre ligado não informa nada. Ela também sempre saía com
  0, então não podia servir de gate para nada; agora sai com 1 quando qualquer
  serviço está inacessível ou retorna status de erro.
- **A penalidade por idade não tinha teto**, crescendo um ponto por ano, então
  uma imagem de 10 anos perdia tanto quanto duas descobertas HIGH só por estar
  desatualizada. Limitada a 3 pontos, onde ainda consegue ordenar imagens
  igualmente limpas sem competir com severidade medida.

Uma auditoria de cada afirmação do README/CHANGELOG contra o código que a
implementa, verificando que cada uma é alcançada no caminho real de execução.
Achados:

- **A configuração documentada não fazia nada.** `Settings` declarava
  `max_tags`, `workers`, `max_critical`, `max_high` e `max_medium`, e o README
  documentava `DOCKERLS_<SETTING>` e `config.toml` como a forma de alterá-los —
  mas a CLI carregava defaults fixos de `typer.Option` que sombreavam `Settings`
  por completo. O próprio exemplo do README (`DOCKERLS_MAX_TAGS=200`,
  `max_tags = 200` no config.toml) era um no-op. As flags agora têm default
  `None` e caem para o valor configurado; uma flag explícita continua vencendo.
  Coberto por `test_settings_are_wired.py`, que falha em 11 testes contra o
  código anterior.
- **`validate_threshold` nunca era chamada.** `--max-critical -5` e
  `--max-medium 999999` eram aceitos silenciosamente. Os limiares agora são
  validados, e um valor inválido imprime uma mensagem e sai com 1 em vez de
  levantar um traceback.
- **`SecurityTier.production_ready` nunca era lido** e o "Tier B = condicional"
  vivia apenas no README, então uma linha Tier B no terminal não trazia
  nenhuma indicação de que precisa de revisão humana. A CLI agora imprime uma
  seção `Requires review` nomeando cada imagem afetada.
- **A integração com o NVD não está conectada a nenhum comando** — `NVDClient`
  só é instanciado em testes, então `NVD_API_KEY` não tinha efeito apesar de o
  README anunciar um benefício de rate limit. Documentado como reservado em vez
  de removido; conectá-lo é um trabalho separado.
- O exemplo `--max-medium 10` do README parecia contradizer o default
  documentado de 5; ele é uma sobrescrita, e agora diz isso.

Continuação da reformulação do `recommend`, motivada por uma execução real de
`dockerls recommend node`.

### Corrigido
- **A pontuação de segurança não conseguia diferenciar imagens.** Os bônus
  somavam +19 contra uma base de 100, então qualquer coisa razoavelmente
  decorada batia no teto: uma imagem limpa, uma com 1 HIGH, uma com 2 HIGH e
  uma com 5 MEDIUM reportavam exatamente `100.0` — o número afirmava que uma
  imagem vulnerável era tão segura quanto uma limpa. A pontuação agora começa
  em 96 com bônus qualitativos limitados a 4,0, estritamente abaixo da
  penalidade de um único HIGH, de modo que nenhuma combinação de "oficial +
  minimal + assinada + LTS + recente" consegue elevar uma imagem com um HIGH ou
  CRITICAL a mais acima de uma mais limpa. Os bônus ainda podem superar um ou
  dois MEDIUM, o que é intencional. O bônus redundante de "zero
  vulnerabilidades" foi removido — zero descobertas já significa zero
  penalidade.
- **A validação cruzada estava patologicamente lenta** (~4m12s para cinco
  imagens). Duas causas, ambas tratadas: o Grype revalida seu banco de
  vulnerabilidades a cada invocação, então o lote agora roda `grype db update`
  uma vez e escaneia com `GRYPE_DB_AUTO_UPDATE=false`; e as validações rodavam
  em um `for` sequencial apesar de serem independentes, então agora rodam
  concorrentemente sob um teto de workers
  (`DOCKERLS_CROSS_VALIDATE_WORKERS`, default 5).
- Imagens de registries que listam apenas nomes de tag eram cobradas com a
  penalidade máxima de idade e ficavam sem o bônus de recência por causa de
  metadados que o registry simplesmente não publica. A idade agora só move a
  pontuação quando a fonte de fato reportou uma data.

### Adicionado
- **Catálogos endurecidos e gratuitos são pesquisados junto com o Docker Hub**:
  Chainguard (`cgr.dev/chainguard/<imagem>`) e Distroless
  (`gcr.io/distroless/<imagem>`). Suas tags passam pelo mesmo pipeline de scan,
  então uma imagem endurecida vence por vulnerabilidades medidas e não por
  reputação. Uma nova coluna `Source` nomeia a origem de cada linha, e o resumo
  da execução lista quais catálogos responderam. `--no-hardened` desativa.
- As listagens de registry são filtradas para imagens de verdade: artefatos
  cosign `.sig`/`.att`/`.sbom` (~1000 por repositório do Chainguard), aliases
  de arquitetura única e duplicatas fixadas em commit são descartados.
- "No image found matching baseline" agora imprime os critérios exatos que não
  foram atendidos.
- O bloco `Details` dá a cada imagem seus próprios caminhos de evidência,
  marcando `(shared digest)` onde tags que compartilham um manifesto foram
  escaneadas uma única vez.
- `AnalysisResult.sources_searched` e `AnalysisResult.baseline` expõem os dois
  fatos ao `--format json`.
- Suíte de aceitação (`tests/acceptance/`) verificando o orçamento
  ponta-a-ponta (<30s para cinco imagens), uma única exibição de progresso sem
  vazamento para o fluxo de resultados, evidência por imagem em disco, e que
  ambas as fontes endurecidas são consultadas.

### Alterado
- A exibição de progresso é renderizada em **stderr**, os resultados em
  **stdout**, de modo que os dois fluxos não podem se intercalar e redirecionar
  o stdout mantém o spinner no terminal. O observer é de uso único e rejeita
  reentrada; um teste verifica que o pacote contém exatamente uma exibição ao
  vivo do Rich.
- A verificação de tags foi generalizada para além do Docker Hub: cada tag é
  confirmada pelo registry que a possui. A coluna `Hub` da tabela agora é `Tag`.



Reformulação do `dockerls recommend`: saída de terminal limpa, causa raiz dos
erros de scan do Trivy removida, e nenhuma imagem recomendada sem prova de que
foi escaneada e de que sua tag existe.

### Corrigido
- **Contenção de lock no cache do Trivy (causa raiz dos erros de scan).** Scans
  paralelos compartilhavam um único `--cache-dir` e disputavam o lock exclusivo
  do Trivy, fazendo com que os perdedores saíssem com código diferente de zero
  com `cache may be in use by another process: timeout`. O banco agora é baixado
  uma vez no início, e então cada worker concorrente recebe seu próprio
  diretório de cache com o banco vinculado por hardlink (sem cópias de centenas
  de MB), desmontado ao fim da execução. Onde o hardlink não está disponível, o
  pool degrada para um único slot compartilhado, o que serializa os scans em vez
  de deixá-los colidir.
- A ocultação de segredos vazava credenciais quando um esquema de autenticação
  estava aninhado em um par chave-valor: em `auth: Bearer <token>` o padrão de
  chave-valor consumia apenas a palavra `Bearer`, deixando o token exposto. Os
  padrões de esquema agora rodam primeiro.
- Um acerto de cache não é mais tomado como prova de um scan bem-sucedido; uma
  análise em cache cujo scan não está verificado é descartada e reescaneada.

### Adicionado
- **Portão de verificação.** `ScanResult.is_verified` exige um scan concluído
  (`OK`) com timestamp. Qualquer outra coisa — erro, timeout, parcial, ou um
  placeholder construído por default — é reportada em uma seção separada
  `Unverified (technical error)` sem pontuação e sem tier, e `_assert_verified`
  levanta `UnverifiedRecommendationError` se uma imagem não verificada chegar
  aos resultados.
- **Validação cruzada entre scanners.** Os principais candidatos são
  reescaneados com o scanner secundário; uma divergência material nas contagens
  de CRITICAL/HIGH substitui a pontuação numérica por `!disputed` mais a
  discrepância.
- **Evidência de scan.** O JSON bruto do scanner é gravado em `.dockerls/scans/`,
  com um manifesto por execução ligando cada pontuação exibida à saída de onde
  ela veio (`DOCKERLS_EVIDENCE_DIR`).
- **Links do Docker Hub.** `build_dockerhub_url()` emite a forma correta para
  imagens oficiais (`/_/<repo>?tab=tags&name=<tag>`) e de terceiros
  (`/r/<ns>/<repo>/tags?name=<tag>`), pulando registries fora do Hub. As tags
  são confirmadas contra a API do Hub (com cache TTL para ficar dentro do limite
  anônimo de requisições) e descartadas se confirmadamente ausentes.
- Novas flags: `--verbose`, `--no-progress`, `--no-cross-validate`,
  `--no-hub-check`. Novas configurações: `DOCKERLS_LOG_DIR`,
  `DOCKERLS_EVIDENCE_DIR`, `DOCKERLS_TRIVY_CACHE_DIR`,
  `DOCKERLS_CROSS_VALIDATE`, `DOCKERLS_VERIFY_HUB_TAGS`.

### Alterado
- O logging é somente para arquivo por default (`logs/dockerls_<timestamp>.log`);
  o sink do loguru para stderr foi removido para que nada se intercale com a
  exibição de progresso do Rich. `--verbose` o reativa.
- O progresso do scan é renderizado como uma única linha transitória de spinner
  do Rich (`Scanning node:26.7-slim... [3/24]`), seguida de um resumo da
  execução (`OK 12/24 analyzed | X 12 skipped (technical error)`) antes da
  tabela.
- A tabela de resultados foi estreitada para caber em um terminal de 80 colunas
  sem truncar referências de imagem: as contagens de severidade colapsam em uma
  única célula `C/H/M`, e as URLs completas do Hub são listadas abaixo da tabela
  em vez de dentro dela.
- Esquema de cache elevado para `v2` por causa dos novos metadados de
  verificação.

## [1.1.0]

Rodada de preparação para produção cobrindo correções de corretude, melhorias
funcionais, novos recursos de produção e endurecimento de engenharia.

### Corrigido (bloqueadores)
- Scans que falham ou dão timeout não são mais tratados como imagens "limpas".
  Um `ScanStatus` (OK/ERROR/TIMEOUT/PARTIAL) é rastreado ponta a ponta e o
  `SecurityScore` se recusa a pontuar qualquer coisa que não seja um scan
  OK/PARTIAL.
- A autenticação no Docker Hub agora é de fato usada: `build_repository()`
  carrega as credenciais do keyring e chama `authenticate()`, e o `dockerls
  login` valida as credenciais antes de armazená-las.
- Tags que compartilham o mesmo digest de manifesto são escaneadas uma vez e
  compartilham o resultado, em vez de serem reescaneadas por tag.
- O banco de vulnerabilidades do Trivy é atualizado uma vez por execução e os
  scans individuais passam `--skip-db-update`.
- O cache SQLite não bloqueia mais o event loop (`asyncio.to_thread`); as
  chaves de cache são versionadas por esquema e um payload em cache
  obsoleto/incompatível é tratado como miss em vez de causar um crash.
- A detecção de EOL agora mapeia nomes de imagem do Docker Hub para os slugs
  corretos de produto do endoflife.date e usa comparação de versão ciente de
  SemVer em vez de prefixos ingênuos de string.

### Adicionado / Alterado (recursos funcionais e de produção)
- Cliente do Docker Hub: retry por requisição (não por lote inteiro),
  tratamento de `Retry-After` em 429, degradação graciosa para resultados
  parciais em erros de rede, e relatório multi-arquitetura
  (`available_architectures`).
- A validação de nome de imagem aceita referências por digest e prefixos de
  registry privado com porta.
- Seleção determinística de CVSS (NVD > fabricante > primeiro disponível, CVSS
  v4 preferido sobre v3) tanto no parser do Trivy quanto no do Grype.
- Ocultação completa de segredos nos logs (nenhum valor parcial vazado).
- `recommend`/`advisor` ganham códigos de saída amigáveis a CI, `--fail-on`,
  `--format json` e `--no-color`; `analyze`/`compare` ganham `--no-color`.
- Novo comando `sbom` (CycloneDX/SPDX via Trivy) e `export --format sarif`
  (SARIF 2.1.0).
- Suporte a `.dockerls-ignore.yaml` para ignorar CVEs com justificativa e
  expiração.
- Sinal de threat intel CISA KEV + EPSS incorporado ao `SecurityScore`
  (best-effort, degrada graciosamente se inacessível).
- Imagens de fornecedores endurecidos (Chainguard, Wolfi, Bitnami) contam para
  o bônus de pontuação de "base minimal".

### Engenharia
- `mypy --strict` passa em todo o pacote (não apenas na camada de domínio); os
  ignores genéricos `S603`/`S607` do `ruff` foram removidos em favor de `noqa`s
  estreitos por local de chamada nas duas chamadas de subprocesso comprovadamente
  seguras.
- Suíte de testes expandida para mais de 190 testes cobrindo caminhos de
  erro/timeout do scanner, versionamento de cache, modo de fallback, tratamento
  de resultados parciais em HTTP, parsing de EOL e todos os comandos da CLI;
  cobertura elevada do piso de 80% para ~89%.
- Dockerfile endurecido: imagens base fixadas por digest, Trivy copiado da sua
  imagem oficial em vez de `curl | sh`.
- O workflow de release agora anexa uma atestação nativa de proveniência de
  build SLSA do GitHub e artefatos assinados com Sigstore.
- `__version__` agora lê os metadados do pacote instalado
  (`importlib.metadata`) em vez de uma string mantida à mão.
- Settings migradas para `pydantic-settings` com variáveis de ambiente
  prefixadas com `DOCKERLS_` e um `~/.config/dockerls/config.toml` opcional.
- Suporte a chave de API do NVD (`NVD_API_KEY`) com rate limiting correto (5
  versus 50 requisições/30s).
- Removido o stub da integração com Docker Scout, que nunca foi usado nem
  conectado.

## [1.0.0-internal] - 2024-01-01

> Renomeado de `[1.0.0]`: esta é a primeira entrada do desenvolvimento
> interno, de antes deste projeto ser publicado -- não a versão pública
> `1.0.0`, que é a seção mais recente no topo deste arquivo.

### Adicionado
- Lançamento inicial
- Comando `search`: pesquisa tags no Docker Hub
- Comando `recommend`: recomenda imagens seguras com pontuação
- Comando `advisor`: consultor de segurança com planos de remediação
- Comando `analyze`: análise profunda de uma tag específica
- Comando `compare`: comparação lado a lado de imagens
- Comando `export`: exporta relatórios em JSON, CSV, HTML, Markdown
- Comando `login`: autenticação no Docker Hub via keyring
- Comando `doctor`: verificação de dependências do sistema
- Comando `health`: verificação de conectividade com serviços externos
- Subcomandos `cache`: gerenciamento de cache (clear, cleanup)
- Integração com Trivy (scanner primário)
- Integração com Grype (scanner de fallback)
- Integração com Docker Scout (complementar)
- Integração com a API do NVD
- Integração com endoflife.date
- Algoritmo de pontuação de segurança (0-100)
- Classificação em níveis de segurança (S/A/B/C)
- Cálculo de pontuação de remediação
- Fallback inteligente quando nenhuma imagem atende à baseline
- Cache de scan baseado em SQLite com TTL
- Logging estruturado com ocultação de segredos
- Validação e sanitização de entrada
- Dockerfile seguro (multi-stage, não-root, somente leitura)
- Workflows de CI/CD (lint, test, security, CodeQL)
- Configuração do Dependabot
