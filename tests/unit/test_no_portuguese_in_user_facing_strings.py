"""Nada em português deve vazar para o que o usuário vê: help do Typer,
mensagens impressas no console, ou texto que vai parar num Dockerfile gerado.

Duas rodadas seguidas de revisão manual encontraram a mesma classe de bug --
uma palavra portuguesa perdida no meio de uma frase em inglês (`"Java com
Maven"`, `"Exemplos"` num `console.print`) -- porque revisão visual não
escala e o mesmo erro se repete. Isto vira teste: varre os literais de string
em `dockerls/cli/` e `dockerls/domain/`, ignora docstrings e chamadas de
`logger.*()` (que são deliberadamente em português, documentação para quem
mexe no código), e falha se sobrar uma palavra-função portuguesa inconfundível.

A lista de palavras é deliberadamente pequena e sem ambiguidade com inglês.
"so", "do", "da", "de" também são palavras (ou muito comuns dentro de
frases) inglesas -- `"so is empty"`, `"how do I"`, `"do not deploy"` -- e
geram falso positivo demais para servir de sinal mesmo delimitadas por
espaço; por isso ficaram de fora, e só entraram as conectivas do pedido
original que não colidem (" com ", " para "), delimitadas por espaço para
não pegar substring de palavra inglesa, junto de palavras e acentos sem
equivalente em inglês.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "dockerls"
_SCAN_ROOTS = (PACKAGE / "cli", PACKAGE / "domain")

#: Palavras e conectivas portuguesas sem par ambíguo em inglês. Espaços ao
#: redor das conectivas curtas evitam pegar substrings de palavras inglesas
#: (ex.: "da" dentro de "data"); os acentos por si só já são inconfundíveis.
_PT_MARKERS = re.compile(
    "("
    r" com | para | não | são | está | então | após "
    r"| só | porém | também | isso | isto | onde | até | ainda | sempre | nunca "
    r"| depois | antes | dentro | sobre | quando | usar | criar "
    r"| gerar | apenas | validar | detalhado | imagem | imagens | segurança "
    r"| seguro | segura | construído | construir | padrão | opcional "
    r"| obrigatório | completo | completa | arquivo | diretório | caminho "
    r"| senha | usuário | escolha | escolher | mostrar | listar | exibir "
    r"| salvar | remover | adicionar | verificar | confirmar | cancelar "
    r"| comando | opção | opções | argumento | resultado | erro | aviso "
    r"| sucesso | falha | tentar | esperar | iniciar | finalizar | executar "
    r"| disponível | necessário | atualizar | instalar | configuração "
    r"| válido | inválido | vazio | vazia | exemplo | exemplos"
    ")",
    re.IGNORECASE,
)

#: Arquivos ou trechos legitimamente bilíngues: mensagens de log
#: (`logger.*`) e docstrings, tratados à parte no walk abaixo.
_LOG_CALL_NAMES = {"debug", "info", "warning", "error", "critical", "exception"}


def _docstring_node_ids(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    candidates: list[ast.AST] = [tree]
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            candidates.append(node)
    for node in candidates:
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            ids.add(id(first.value))
    return ids


def _is_logger_call_arg(node: ast.AST, parent_call: ast.Call | None) -> bool:
    if parent_call is None or not isinstance(parent_call.func, ast.Attribute):
        return False
    return parent_call.func.attr in _LOG_CALL_NAMES


def _string_literals(path: pathlib.Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstring_ids = _docstring_node_ids(tree)

    parent_call_of: dict[int, ast.Call] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for arg in (*node.args, *[kw.value for kw in node.keywords]):
                if isinstance(arg, ast.Constant):
                    parent_call_of[id(arg)] = node

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in docstring_ids:
            continue
        if _is_logger_call_arg(node, parent_call_of.get(id(node))):
            continue
        found.append((node.lineno, node.value))
    return found


def _python_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


_ALL_FILES = [f for root in _SCAN_ROOTS for f in _python_files(root)]


class TestUserFacingStringsAreEnglish:
    def test_there_are_files_to_scan(self) -> None:
        """Um teste que não vê arquivo nenhum passa por engano -- e passaria
        para sempre."""
        assert _ALL_FILES

    @pytest.mark.parametrize("path", _ALL_FILES, ids=lambda p: str(p.relative_to(PACKAGE)))
    def test_no_portuguese_markers_outside_docstrings_and_logs(self, path: pathlib.Path) -> None:
        offenders = [
            (lineno, text)
            for lineno, text in _string_literals(path)
            if _PT_MARKERS.search(f" {text} ")
        ]
        assert not offenders, (
            f"{path.relative_to(PACKAGE)}: Portuguese word(s) found in a "
            f"user-facing string literal (help text, console output, or "
            f"generated Dockerfile content): {offenders}"
        )
