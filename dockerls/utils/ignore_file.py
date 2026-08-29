from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml
from loguru import logger
from pydantic import BaseModel, field_validator

from dockerls.domain.value_objects.vex import VexJustification, parse_justification

DEFAULT_IGNORE_FILENAME = ".dockerls-ignore.yaml"

#: A forma mínima de um identificador de aviso. Larga o bastante para
#: `CVE-2024-1234`, `GHSA-xxxx-yyyy-zzzz`, `DSA-5555-1`, `RUSTSEC-2024-0001`
#: e `ALAS2-2024-2500`; estreita o bastante para recusar o vazio, que casa
#: com todo achado que o scanner reportou sem identificador.
_ADVISORY_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9]+)+$")


class IgnoreRule(BaseModel):
    cve: str
    justification: str = ""
    expires: date | None = None
    #: A justificativa **do padrão VEX**, quando quem escreveu a regra
    #: souber declarar uma. Opcional de propósito: `not_affected` é uma
    #: afirmação técnica com vocabulário fechado, e a maioria das isenções
    #: é decisão de risco ("aceito até o Q3"), que não é nenhuma delas.
    #:
    #: Sem ela, o documento OpenVEX sai como `affected` com a justificativa
    #: em texto -- o consumidor vê a exceção e o motivo, sem receber uma
    #: alegação técnica que ninguém fez. Ver `domain/value_objects/vex.py`.
    vex_justification: str = ""

    @field_validator("vex_justification")
    @classmethod
    def _known_vex_justification(cls, v: str) -> str:
        """Recusa um valor que não existe no padrão.

        Aceitá-lo produziria um documento VEX que outra ferramenta rejeita
        na leitura -- e o erro apareceria longe daqui, sem dizer que veio
        de uma linha do arquivo de isenções.
        """
        text = v.strip().lower()
        if not text:
            return ""
        if parse_justification(text) is None:
            allowed = ", ".join(str(j) for j in VexJustification)
            raise ValueError(f"unknown VEX justification {v!r}; expected one of: {allowed}")
        return text

    @field_validator("cve")
    @classmethod
    def _upper_cve(cls, v: str) -> str:
        """Normaliza o identificador, e recusa um que não identifica nada.

        Um `cve: ""` passava por aqui e entrava no conjunto de isenções como
        a string vazia. As isenções são aplicadas com
        `vuln.cve_id.upper() not in ignored`, e um scanner **deixa
        `cve_id` vazio** quando o aviso não tem identificador publicado --
        o Trivy faz exatamente isso, como o exportador SARIF documenta. Uma
        única linha em branco no arquivo de isenções apagava portanto
        *todos* os achados sem identificador do relatório, e com eles do
        score, do tier e do veredito de produção: vulnerabilidades reais
        somem e a imagem sobe de nota.

        A forma exigida é frouxa de propósito -- `GHSA-...`, `DSA-...`,
        `RUSTSEC-...` e `ALAS-...` são identificadores legítimos e não
        parecem com `CVE-`. O que ela recusa é o que não identifica: vazio,
        espaço em branco, e qualquer coisa curta demais para ser um
        identificador de aviso.
        """
        text = v.strip().upper()
        if not _ADVISORY_ID.match(text):
            raise ValueError(
                f"{v!r} does not name an advisory. An exemption has to say which "
                "vulnerability it exempts: a blank id matches every finding the "
                "scanner reported without one, and silently drops them from the scan"
            )
        return text

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return date.today() > self.expires


def load_ignore_rules(path: Path | None = None) -> list[IgnoreRule]:
    """Load CVE ignore rules from a `.dockerls-ignore.yaml` file. Expired
    rules are dropped (a vulnerability whose exemption lapsed is no longer
    ignored). Missing or malformed files degrade to "no rules" rather than
    failing the scan."""
    target = path or Path.cwd() / DEFAULT_IGNORE_FILENAME
    if not target.exists():
        return []

    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        logger.warning(f"Could not parse {target}: {e}")
        return []

    entries = raw.get("ignores", []) if isinstance(raw, dict) else []
    rules: list[IgnoreRule] = []
    for entry in entries:
        try:
            rule = IgnoreRule.model_validate(entry)
        except Exception as e:
            logger.warning(f"Skipping invalid ignore rule {entry}: {e}")
            continue
        if rule.is_expired:
            logger.info(f"Ignore rule for {rule.cve} expired on {rule.expires}, no longer applied")
            continue
        rules.append(rule)
    return rules


def active_ignored_cve_ids(rules: list[IgnoreRule]) -> set[str]:
    """Identificadores isentos e ainda válidos.

    A string vazia é filtrada de novo aqui, e não só no validador: este
    conjunto é comparado contra `vuln.cve_id`, que é vazio nos achados sem
    identificador publicado, e um `""` que escapasse -- por uma `IgnoreRule`
    construída em código, sem passar pelo arquivo -- apagaria todos eles do
    relatório sem deixar rastro. Duas guardas para um erro que some em
    silêncio é o preço certo.
    """
    return {r.cve for r in rules if not r.is_expired and r.cve.strip()}
