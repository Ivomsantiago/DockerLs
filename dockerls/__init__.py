"""DockerLs: Enterprise Docker Image Security Advisor."""

from __future__ import annotations

from typing import Any

__all__ = ["__version__"]


def __getattr__(name: str) -> Any:
    """Resolve `__version__` sob demanda.

    `importlib.metadata` custa ~24ms para importar, e este `__init__` roda
    antes de qualquer `dockerls.*` -- ou seja, todo comando da CLI pagava
    esse preço, inclusive os que nunca mostram a versão. Com o
    `__getattr__` de módulo (PEP 562) quem escreve
    `from dockerls import __version__` continua funcionando igual, e quem
    não escreve não paga.
    """
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from importlib.metadata import PackageNotFoundError, version

    try:
        resolved = version("dockerls")
    except PackageNotFoundError:
        # Editable/dev checkout without an installed distribution record.
        resolved = "0.0.0+dev"
    globals()["__version__"] = resolved
    return resolved
