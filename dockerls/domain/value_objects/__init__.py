"""Os objetos de valor do domínio, resolvidos sob demanda.

Este pacote reexportava tudo no topo do arquivo, e o preço não era o
import em si: cada símbolo aqui é um modelo pydantic, e o pydantic compila
o modelo *no momento do import*. Como `import
dockerls.domain.value_objects.image_reference` -- uma função de parsing de
strings, sem dependência nenhuma -- executa o `__init__` do pacote antes de
chegar no submódulo, todo comando da CLI pagava essa compilação. Eram 82ms
em `dockerls --help`, que não pontua imagem nenhuma.

O `__getattr__` de módulo (PEP 562) mantém `from dockerls.domain.value_objects
import SecurityScore` funcionando exatamente como antes; o submódulo só é
importado quando alguém realmente pede o nome.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dockerls.domain.value_objects.remediation_score import RemediationScore
    from dockerls.domain.value_objects.security_score import SecurityScore
    from dockerls.domain.value_objects.security_tier import SecurityTier

#: Nome público -> submódulo que o define.
_EXPORTS = {
    "RemediationScore": "remediation_score",
    "SecurityScore": "security_score",
    "SecurityTier": "security_tier",
}

__all__ = ["RemediationScore", "SecurityScore", "SecurityTier"]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(f"{__name__}.{module}"), name)
    # Cacheado no próprio módulo: `__getattr__` só é consultado quando o
    # nome não está no namespace, então o segundo acesso não paga nada.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
