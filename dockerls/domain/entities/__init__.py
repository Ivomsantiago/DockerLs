"""As entidades do domínio, resolvidas sob demanda.

Mesmo motivo do `value_objects`: são todos modelos pydantic, que o pydantic
compila no import, e o `__init__` do pacote roda antes de qualquer
`from dockerls.domain.entities.image import DockerImage`. Reexportar tudo
no topo cobrava 116ms de cada comando -- inclusive dos que não tocam em
imagem nenhuma.

`__getattr__` de módulo (PEP 562) preserva a API pública: quem importa
daqui continua importando daqui, e só o submódulo do nome pedido é
carregado.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dockerls.domain.entities.dockerfile_analysis import (
        DockerfileAnalysis,
        DockerfileInfo,
        DockerfileValidationResult,
        HardeningRule,
        SeverityLevel,
        ValidationCheck,
        ValidationStatus,
    )
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.entities.recommendation import Recommendation
    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.domain.entities.vulnerability import Vulnerability

#: Nome público -> submódulo que o define.
_EXPORTS = {
    "DockerfileAnalysis": "dockerfile_analysis",
    "DockerfileInfo": "dockerfile_analysis",
    "DockerfileValidationResult": "dockerfile_analysis",
    "HardeningRule": "dockerfile_analysis",
    "SeverityLevel": "dockerfile_analysis",
    "ValidationCheck": "dockerfile_analysis",
    "ValidationStatus": "dockerfile_analysis",
    "DockerImage": "image",
    "Recommendation": "recommendation",
    "ScanResult": "scan_result",
    "Vulnerability": "vulnerability",
}

__all__ = [
    "DockerImage",
    "DockerfileAnalysis",
    "DockerfileInfo",
    "DockerfileValidationResult",
    "HardeningRule",
    "Recommendation",
    "ScanResult",
    "SeverityLevel",
    "ValidationCheck",
    "ValidationStatus",
    "Vulnerability",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
