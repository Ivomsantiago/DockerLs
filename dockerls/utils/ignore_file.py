from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml
from loguru import logger
from pydantic import BaseModel, field_validator

from dockerls.domain.value_objects.vex import VexJustification, parse_justification

DEFAULT_IGNORE_FILENAME = ".dockerls-ignore.yaml"


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
        return v.strip().upper()

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
    return {r.cve for r in rules if not r.is_expired}
