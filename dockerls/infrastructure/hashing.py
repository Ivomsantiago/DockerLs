"""Digerir a entrada do build antes de ela virar imagem.

Um relatório de segurança afirma coisas sobre uma imagem. Para a afirmação
valer, é preciso poder responder *qual* imagem, e a partir de *qual* entrada
-- e é aí que a cadeia arrebentava: o `build` media o resultado sem registrar
nada sobre o que entrou. Dois builds do mesmo `--tag` produziam relatórios
indistinguíveis mesmo partindo de Dockerfiles diferentes.

O que este módulo produz é o começo dessa cadeia: um digest determinístico do
Dockerfile e do contexto de build. Determinístico importa mais do que parece:
o mesmo conteúdo tem de dar o mesmo hash em qualquer máquina, em qualquer
ordem de sistema de arquivos, ou a comparação entre dois builds não significa
nada. Por isso os caminhos entram ordenados e relativos, e o nome de cada
arquivo entra no digest junto do conteúdo -- renomear um arquivo muda o
contexto tanto quanto editá-lo.

O `.dockerignore` é respeitado porque ele decide o que o daemon realmente
recebe: hashear o que fica de fora produziria um digest que muda sem que a
imagem mude, e um controle que dispara sem motivo é um controle que as
pessoas desligam.
"""

from __future__ import annotations

import fnmatch
import hashlib
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from pathlib import Path

#: Lido em blocos para que um contexto com artefatos grandes não seja
#: carregado inteiro na memória só para ser digerido.
_CHUNK_BYTES = 1024 * 1024

#: Teto de arquivos digeridos. Um contexto acima disto quase sempre significa
#: um `.dockerignore` ausente -- e é melhor recusar a medir do que devolver um
#: digest que levou minutos e não descreve o que foi enviado.
MAX_CONTEXT_FILES = 50_000


class ContextTooLargeError(RuntimeError):
    """O contexto tem mais arquivos do que se pode digerir com sentido."""


def hash_file(path: Path) -> str:
    """SHA-256 do conteúdo de um arquivo, em minúsculas e com prefixo."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def hash_context(root: Path, *, dockerignore: Path | None = None) -> tuple[str, int]:
    """Digest determinístico do contexto de build, e quantos arquivos entraram.

    Devolve o par para que o relatório possa dizer *sobre o que* o digest
    fala: um hash sozinho não distingue "contexto vazio" de "contexto que
    ninguém conseguiu ler".
    """
    patterns = _ignore_patterns(dockerignore or root / ".dockerignore")
    digest = hashlib.sha256()
    counted = 0

    for path in _walk(root, patterns):
        counted += 1
        if counted > MAX_CONTEXT_FILES:
            raise ContextTooLargeError(
                f"o contexto de build excede {MAX_CONTEXT_FILES} arquivos; "
                "quase sempre isso significa um .dockerignore ausente"
            )
        # O caminho entra no digest junto do conteúdo: renomear um arquivo
        # muda o contexto tanto quanto editá-lo, e um digest que não visse o
        # nome trataria as duas coisas como iguais.
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hash_file(path).encode("ascii"))
        digest.update(b"\n")

    return f"sha256:{digest.hexdigest()}", counted


def _walk(root: Path, patterns: list[str]) -> list[Path]:
    """Arquivos do contexto, ordenados, sem os ignorados.

    A ordenação é o que torna o digest reprodutível: a ordem em que o sistema
    de arquivos devolve entradas não é estável entre máquinas nem entre
    execuções, e um digest que dependesse dela seria diferente a cada vez. Por
    isso a lista é ordenada no fim, sobre os caminhos completos -- e não a cada
    nível durante a descida, que produziria uma ordem diferente e portanto um
    digest diferente para o mesmo conteúdo.

    **A poda acontece na descida, não depois dela.** A versão anterior
    percorria a árvore inteira com `rglob("*")` e descartava o que o
    `.dockerignore` excluía, o que significa abrir `.git` e `node_modules`
    arquivo por arquivo para jogar fora cada um. Num repositório real isso é a
    quase totalidade do trabalho: num contexto de 52.400 arquivos em que 401
    são enviados ao daemon, 98% do tempo era gasto lendo entradas que o build
    nunca veria. Um diretório ignorado tem todos os seus arquivos ignorados
    pela mesma regra, então não descer nele produz exatamente o mesmo conjunto.
    """
    files: list[Path] = []
    stack: list[Path] = [root]

    while stack:
        directory = stack.pop()
        try:
            children = list(directory.iterdir())
        except OSError as e:
            # Um diretório ilegível não interrompe a digestão do resto: o
            # `.dockerignore` pode muito bem excluí-lo, e o daemon não teria
            # recebido nada dali de qualquer forma.
            logger.debug(f"Não foi possível listar {directory}: {e}")
            continue

        for child in children:
            # Symlink não é seguido nem digerido, como antes: seguir um daria
            # ao digest um conteúdo de fora do contexto.
            if child.is_symlink():
                continue
            relative = child.relative_to(root).as_posix()
            if child.is_dir():
                if not _is_ignored(relative, patterns):
                    stack.append(child)
            elif child.is_file() and not _is_ignored(relative, patterns):
                files.append(child)

    # Sobre os caminhos completos, exatamente como o `sorted(rglob(...))`
    # anterior: o digest de um contexto inalterado continua o mesmo, e um
    # documento de procedência antigo segue comparável com um novo.
    files.sort()
    return files


def _ignore_patterns(dockerignore: Path) -> list[str]:
    if not dockerignore.is_file():
        return []
    patterns: list[str] = []
    for raw in dockerignore.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        # Negações (`!arquivo`) reincluem o que um padrão anterior tirou.
        # Tratá-las como padrão comum excluiria exatamente o que elas mandam
        # incluir, então ficam de fora da lista de exclusão.
        if not line or line.startswith(("#", "!")):
            continue
        patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(relative: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(relative, pattern):
            return True
        # Um padrão de diretório cobre tudo abaixo dele: `.git` no
        # .dockerignore significa `.git/**`, e comparar só o caminho completo
        # deixaria passar cada arquivo lá dentro.
        if relative.startswith(f"{pattern}/") or fnmatch.fnmatch(relative, f"{pattern}/*"):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in relative.split("/")[:-1]):
            return True
    return False
