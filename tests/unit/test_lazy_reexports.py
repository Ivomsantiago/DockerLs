"""Guard: os reexports preguiçosos continuam sendo reexports.

Três `__init__.py` do pacote passaram a resolver seus nomes sob demanda,
via `__getattr__` de módulo (PEP 562). O motivo é medido: cada símbolo de
`domain.entities` e `domain.value_objects` é um modelo pydantic, e o
pydantic compila o modelo no momento do import -- de modo que
`from dockerls.domain.value_objects.image_reference import ...`, uma
função de parsing de string, arrastava a compilação de todos eles porque o
`__init__` do pacote roda primeiro. `dockerls/__init__.py` fazia o mesmo
com `importlib.metadata`, ~24ms em todo comando da CLI.

Preguiça silenciosa é onde um `ImportError` se esconde até o dia do
release. Estes testes exercem exatamente o caminho que deixou de ser
exercido pelo import: pedir cada nome público e recebê-lo.
"""

from __future__ import annotations

import importlib

import pytest

MODULES = ("dockerls", "dockerls.domain.entities", "dockerls.domain.value_objects")


@pytest.mark.parametrize("module_name", MODULES)
class TestEveryDeclaredNameResolves:
    def test_all_of_dunder_all_is_reachable(self, module_name):
        module = importlib.import_module(module_name)
        for name in module.__all__:
            assert getattr(module, name) is not None

    def test_an_unknown_name_still_raises_attribute_error(self, module_name):
        """`__getattr__` de módulo é consultado para *qualquer* nome
        ausente. Devolver algo -- ou levantar outra coisa -- quebraria
        `hasattr`, `inspect` e o próprio import."""
        module = importlib.import_module(module_name)
        missing = "definitely_not_defined_here"
        with pytest.raises(AttributeError):
            getattr(module, missing)

    def test_dir_lists_the_public_names(self, module_name):
        module = importlib.import_module(module_name)
        assert set(module.__all__) <= set(dir(module))


class TestTheNamesAreTheSameObjects:
    """Reexport preguiçoso que devolve uma *cópia* seria pior que o
    problema: `isinstance` passaria a mentir."""

    def test_entities_match_their_defining_modules(self):
        from dockerls.domain import entities
        from dockerls.domain.entities.image import DockerImage
        from dockerls.domain.entities.scan_result import ScanResult

        assert entities.DockerImage is DockerImage
        assert entities.ScanResult is ScanResult

    def test_value_objects_match_their_defining_modules(self):
        from dockerls.domain import value_objects
        from dockerls.domain.value_objects.security_score import SecurityScore

        assert value_objects.SecurityScore is SecurityScore

    def test_the_version_matches_the_installed_distribution(self):
        import dockerls

        assert isinstance(dockerls.__version__, str)
        assert dockerls.__version__
