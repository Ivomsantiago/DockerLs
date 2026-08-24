"""Classificação do stderr dos scanners em causas estáveis.

Trivy e Grype relatam falhas como texto livre em stderr. Guardar só um
prefixo cortado desse texto -- que era o que a tabela mostrava, produzindo
coisas como `error in v...` -- não nomeia causa nenhuma e não permite agrupar
93 falhas para descobrir que todas são a mesma.

Aqui o texto vira um `ScanErrorKind`. A mensagem completa continua em
`ScanResult.error_message`, indo para o arquivo de log e para `--format json`;
esta classificação é o que aparece no terminal, e é o que decide se vale a
pena tentar o mesmo alvo com o outro scanner.
"""

from __future__ import annotations

import re

from dockerls.domain.entities.scan_result import ScanErrorKind

# Ordem importa: a primeira regra que casar vence, então as causas mais
# específicas vêm antes das genéricas. "db error" aparece dentro de mensagens
# que também mencionam "failed to download", por exemplo.
_RULES: tuple[tuple[ScanErrorKind, re.Pattern[str]], ...] = (
    (
        ScanErrorKind.RATE_LIMITED,
        re.compile(r"rate limit|too many requests|429|toomanyrequests", re.IGNORECASE),
    ),
    (
        ScanErrorKind.AUTH_REQUIRED,
        re.compile(
            r"unauthorized|authentication required|forbidden|401|403|denied: requested access",
            re.IGNORECASE,
        ),
    ),
    (
        ScanErrorKind.NOT_FOUND,
        re.compile(
            r"manifest unknown|not found|no such image|repository does not exist"
            r"|name unknown|could not find the image|unable to find the specified image",
            re.IGNORECASE,
        ),
    ),
    (
        ScanErrorKind.DB_INIT_FAILED,
        re.compile(
            r"db error|database error|init error|failed to download (?:vulnerability )?db"
            r"|failed to initialize|unable to open database|bad database|db\.metadata"
            r"|cache may be in use|database is locked|failed to open db",
            re.IGNORECASE,
        ),
    ),
    (
        ScanErrorKind.TIMEOUT,
        re.compile(r"timeout|timed out|deadline exceeded|context deadline", re.IGNORECASE),
    ),
)


def classify_scanner_error(message: str) -> ScanErrorKind:
    """Map a scanner's stderr onto a stable, groupable cause code."""
    text = (message or "").strip()
    if not text:
        return ScanErrorKind.UNKNOWN
    for kind, pattern in _RULES:
        if pattern.search(text):
            return kind
    return ScanErrorKind.UNKNOWN
