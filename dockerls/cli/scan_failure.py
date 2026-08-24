"""A causa de um scan que não completou, em uma linha legível.

O terminal mostrava o stderr cru do scanner. Para uma tag inexistente o
Trivy responde com um bloco de várias linhas que menciona o socket do
Docker -- um daemon que este modo de scan nem usa --, e o leitor tinha
que garimpar nesse texto a única informação que importa: a tag não existe
no registry.

A causa já vem classificada em `ScanErrorKind` (ver
`integrations/scan_errors.py`). Aqui ela vira a frase que o usuário lê. O
texto bruto continua indo para o arquivo de log e para `--format json`
via `ScanResult.error_message`: resumir na tela não é esconder, é parar
de despejar num lugar onde ninguém consegue ler.

Uma função só, usada por `analyze`, `compare`, `advisor` e `alternatives`,
porque quatro cópias da mesma frase divergem na primeira vez que uma
delas for corrigida.
"""

from __future__ import annotations

from dockerls.domain.entities.scan_result import ScanErrorKind

#: O que cada causa classificada significa, nos termos de quem lê. São
#: afirmações sobre o que aconteceu, não instruções -- a ação sugerida é
#: assunto de quem renderiza (`recommend` tem a sua própria tabela de
#: dicas, que responde "o que fazer" em vez de "o que houve").
_CAUSES: dict[ScanErrorKind, str] = {
    ScanErrorKind.NOT_FOUND: "tag not found on the registry",
    ScanErrorKind.AUTH_REQUIRED: "the registry requires credentials",
    ScanErrorKind.RATE_LIMITED: "rate limited by the registry",
    ScanErrorKind.DB_INIT_FAILED: "the vulnerability database could not be prepared",
    ScanErrorKind.TIMEOUT: "the scan exceeded its timeout",
    ScanErrorKind.SCANNER_MISSING: "no scanner executable was found",
    ScanErrorKind.INVALID_OUTPUT: "the scanner produced output that could not be parsed",
    ScanErrorKind.BLOCKED_BY_POLICY: "the network policy refused this host",
}

#: Quanto do stderr cru sobrevive quando não há causa classificada. O
#: texto inteiro está no log e no JSON; aqui só cabe o suficiente para
#: distinguir uma falha da outra.
REASON_MAX_LEN = 90


def short_reason(reason: str) -> str:
    """Colapsa um stderr de várias linhas em uma linha legível."""
    collapsed = " ".join(reason.split())
    if len(collapsed) <= REASON_MAX_LEN:
        return collapsed
    return collapsed[: REASON_MAX_LEN - 3] + "..."


def describe_scan_failure(kind: ScanErrorKind | str, message: str = "") -> str:
    """`KIND -- causa em português claro`, sem o dump do scanner.

    Sem classificação (UNKNOWN, ou um scanner cuja saída ninguém mapeou
    ainda) sobra o começo do stderr, colapsado numa linha: é pior que uma
    frase, e ainda assim melhor que nada.
    """
    try:
        classified = ScanErrorKind(kind)
    except ValueError:
        # Um `kind` que não é um membro do enum vem de dado externo
        # (cache antigo, JSON de outra versão). Não é motivo para o
        # comando morrer: o rótulo é mostrado como veio.
        return f"{kind} -- {short_reason(message) or 'no details'}"

    cause = _CAUSES.get(classified)
    if cause:
        return f"{classified.value} -- {cause}"
    return f"{classified.value} -- {short_reason(message) or 'no details'}"
