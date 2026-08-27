"""Ler os `FROM` de um Dockerfile e dizer o que fazer com cada um.

O `analyze-dockerfile` sabe ler o seu projeto mas não mede nada -- a sugestão
de base era uma string fixa, `"FROM node:22-alpine or FROM chainguard/node"`,
respondida igual para qualquer Dockerfile, inclusive um de Python. O
`recommend` mede de verdade, mas só funciona se alguém digitar a referência na
mão: ele nunca olha o seu Dockerfile. A metade que lê o projeto não media, e a
metade que media não lia o projeto.

Este módulo é a ponte, e é a parte pura dela: recebe o texto do Dockerfile e
os digests que alguém resolveu por fora, e responde o que cada `FROM` é hoje e
o que deveria ser. Sem rede, sem disco -- o que torna cada regra testável
contra o texto exato que a produziu.

O estado de uma base é um de quatro, e a distinção importa porque cada um pede
uma ação diferente:

* `PINNED_CURRENT` -- fixada num digest, e a tag ainda aponta para ele. Nada a
  fazer.
* `PINNED_STALE` -- fixada num digest, mas a tag já aponta para outro. **Este
  é o caso que apodrece em silêncio**: foi assim que uma base de 2024 ficou
  parada nesta imagem carregando CVEs do `libexpat1` que já tinham correção.
* `UNPINNED` -- só uma tag. O que você testou e o que vai para produção podem
  ser bytes diferentes sem nenhuma mudança da sua parte.
* `UNRESOLVED` -- ninguém conseguiu perguntar ao registry. Ausência de
  resposta, e não confirmação de que está tudo bem: é reportado como tal e
  nunca vira "atualizado".

A reescrita mexe **apenas** no token da imagem, preservando `--platform`,
`AS <estágio>` e todo o resto da linha -- um upgrade de base que reformata o
arquivo transforma uma revisão de uma linha numa revisão de trinta.

Referências montadas com `ARG` (`FROM python:3.12-alpine@${PYTHON_DIGEST}`)
recebem tratamento próprio, porque são a forma correta de escrever isto e
seria absurdo não suportá-las: o valor é resolvido a partir do padrão do
`ARG` para a comparação, e a atualização vai para **a linha do `ARG`**, que é
onde o digest realmente mora. Sobrescrever o token do `FROM` quebraria o
contrato do arquivo em vez de atualizá-lo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

#: `FROM [--platform=...] <referência> [AS <estágio>]`, com os pedaços
#: preservados para que a reescrita não perca nada da linha original.
_FROM_LINE = re.compile(
    r"^(?P<prefix>\s*FROM\s+(?:--\S+\s+)*)(?P<reference>\S+)(?P<suffix>.*)$",
    re.IGNORECASE,
)

#: `ARG NOME=valor`, de onde saem os valores que os `FROM` interpolam.
_ARG_LINE = re.compile(
    r"^(?P<prefix>\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)=)(?P<value>\S*)", re.IGNORECASE
)

#: `${NOME}` ou `$NOME` dentro de uma referência.
_VARIABLE = re.compile(
    r"\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<bare>[A-Za-z_][A-Za-z0-9_]*)"
)


class BaseStatus(StrEnum):
    """O que se sabe sobre uma base declarada."""

    PINNED_CURRENT = "PINNED_CURRENT"
    PINNED_STALE = "PINNED_STALE"
    UNPINNED = "UNPINNED"
    UNRESOLVED = "UNRESOLVED"

    @property
    def needs_action(self) -> bool:
        """Se há algo a corrigir. `UNRESOLVED` não entra: não se corrige o que
        não se conseguiu medir -- reporta-se."""
        return self in (BaseStatus.PINNED_STALE, BaseStatus.UNPINNED)


@dataclass(frozen=True)
class DeclaredBase:
    """Uma base como o Dockerfile a declara, decomposta."""

    #: Número da linha, 1-indexado, para a mensagem apontar onde.
    line: int
    #: O token exato que aparece no arquivo.
    raw: str
    name: str
    tag: str
    #: Digest fixado no arquivo, vazio quando a base é só uma tag.
    digest: str = ""
    #: Nome do estágio (`AS builder`), quando há.
    stage: str = ""
    #: Referência montada a partir de variável (`${VERSION}`). O valor é
    #: resolvido a partir do padrão do `ARG` para a comparação.
    templated: bool = False
    #: Nome do `ARG` de onde o digest veio, quando veio de um. É a linha que a
    #: atualização deve tocar -- o digest mora lá, não no `FROM`.
    digest_arg: str = ""
    #: Linha do `ARG` correspondente, 1-indexada.
    digest_arg_line: int = 0

    @property
    def is_pinned(self) -> bool:
        return bool(self.digest)

    @property
    def reference(self) -> str:
        base = f"{self.name}:{self.tag}" if self.tag else self.name
        return f"{base}@{self.digest}" if self.digest else base


@dataclass(frozen=True)
class BaseFinding:
    """O veredito sobre uma base, e a linha que a substituiria."""

    base: DeclaredBase
    status: BaseStatus
    #: O digest que a tag aponta hoje, quando alguém conseguiu perguntar.
    current_digest: str = ""

    @property
    def proposed_reference(self) -> str:
        """A referência a usar, ou "" quando não há nada a propor."""
        if not self.current_digest:
            return ""
        # Uma referência interpolada só é reescrevível quando o digest vem de
        # um `ARG` que existe no arquivo -- aí a troca vai para lá. Sem isso,
        # não há onde escrever sem quebrar o contrato do Dockerfile.
        if self.base.templated and not self.base.digest_arg_line:
            return ""
        if self.status is BaseStatus.PINNED_CURRENT:
            return ""
        tag = self.base.tag or "latest"
        return f"{self.base.name}:{tag}@{self.current_digest}"

    def explain(self) -> str:
        if self.status is BaseStatus.PINNED_STALE:
            return (
                "pinned to a digest the tag no longer points at: the base was "
                "republished and this image keeps building from the old version"
            )
        if self.status is BaseStatus.UNPINNED:
            return (
                "moving tag, no digest: what you tested and what goes to production "
                "can be different bytes with no change on your part"
            )
        if self.status is BaseStatus.UNRESOLVED:
            return "the registry could not be asked which digest this tag points at"
        return "pinned to the digest the tag points at today"


def parse_bases(content: str) -> list[DeclaredBase]:
    """Toda base declarada no Dockerfile, na ordem em que aparece.

    Estágios internos entram junto: um `FROM golang:1.21 AS builder` velho
    compila com um toolchain velho, e isso é problema de cadeia de
    fornecimento mesmo que o binário vá para uma imagem final endurecida.
    """
    args, arg_lines = _arg_defaults(content)
    bases: list[DeclaredBase] = []
    for number, line in enumerate(content.splitlines(), 1):
        match = _FROM_LINE.match(line)
        if not match:
            continue
        reference = match.group("reference")
        stage = ""
        suffix = match.group("suffix").strip()
        if suffix:
            parts = suffix.split()
            if len(parts) >= 2 and parts[0].upper() == "AS":
                stage = parts[1]

        expanded = _expand(reference, args)
        name, tag, digest = _split_reference(expanded)
        _, _, raw_digest = reference.partition("@")
        digest_arg = _variable_name(raw_digest)
        bases.append(
            DeclaredBase(
                line=number,
                raw=reference,
                name=name,
                tag=tag,
                digest=digest,
                stage=stage,
                templated="$" in reference,
                digest_arg=digest_arg,
                digest_arg_line=arg_lines.get(digest_arg, 0),
            )
        )
    return bases


def _arg_defaults(content: str) -> tuple[dict[str, str], dict[str, int]]:
    """Valores padrão dos `ARG` e a linha de cada um."""
    values: dict[str, str] = {}
    lines: dict[str, int] = {}
    for number, line in enumerate(content.splitlines(), 1):
        match = _ARG_LINE.match(line)
        if match:
            values[match.group("name")] = match.group("value")
            lines[match.group("name")] = number
    return values, lines


def _expand(reference: str, args: dict[str, str]) -> str:
    """Substitui `${VAR}` pelos padrões declarados, deixando o resto como está."""

    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("bare")
        return args.get(name, match.group(0))

    return _VARIABLE.sub(replace, reference)


def _variable_name(value: str) -> str:
    """O nome da variável, se o valor for exatamente uma interpolação."""
    match = _VARIABLE.fullmatch(value.strip())
    if not match:
        return ""
    return match.group("braced") or match.group("bare")


def classify(base: DeclaredBase, current_digest: str) -> BaseFinding:
    """O estado de uma base, dado o digest que a tag aponta hoje.

    `current_digest` vazio significa "ninguém conseguiu perguntar", e o
    resultado é `UNRESOLVED` -- nunca `PINNED_CURRENT` por omissão.
    """
    if not current_digest:
        return BaseFinding(base=base, status=BaseStatus.UNRESOLVED)
    if not base.is_pinned:
        return BaseFinding(base=base, status=BaseStatus.UNPINNED, current_digest=current_digest)
    status = BaseStatus.PINNED_CURRENT if base.digest == current_digest else BaseStatus.PINNED_STALE
    return BaseFinding(base=base, status=status, current_digest=current_digest)


def rewrite(content: str, findings: list[BaseFinding]) -> tuple[str, int]:
    """Aplica as substituições, devolvendo o texto novo e quantas houve.

    Só o token da imagem é trocado: `--platform`, `AS <estágio>`, comentários
    e indentação sobrevivem intactos, porque um upgrade de base que reformata
    o arquivo transforma uma revisão de uma linha numa revisão de trinta.
    """
    from_edits: dict[int, str] = {}
    arg_edits: dict[int, str] = {}
    for finding in findings:
        if not finding.proposed_reference:
            continue
        base = finding.base
        if base.digest_arg_line:
            # O digest mora no `ARG`; é lá que a atualização vale, e assim o
            # `FROM` continua legível e o contrato do arquivo intacto.
            arg_edits[base.digest_arg_line] = finding.current_digest
        else:
            from_edits[base.line] = finding.proposed_reference

    if not from_edits and not arg_edits:
        return content, 0

    applied = 0
    lines = content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        number = index + 1
        stripped = line.rstrip("\r\n")
        ending = line[len(stripped) :]

        if number in from_edits:
            match = _FROM_LINE.match(stripped)
            if match:
                lines[index] = (
                    f"{match.group('prefix')}{from_edits[number]}{match.group('suffix')}{ending}"
                )
                applied += 1
        elif number in arg_edits:
            match = _ARG_LINE.match(stripped)
            if match:
                tail = stripped[match.end() :]
                lines[index] = f"{match.group('prefix')}{arg_edits[number]}{tail}{ending}"
                applied += 1
    return "".join(lines), applied


def _split_reference(reference: str) -> tuple[str, str, str]:
    """`nome`, `tag`, `digest` de uma referência, com os vazios explícitos."""
    remainder, _, digest = reference.partition("@")
    # O host pode carregar porta (`registry:5000/app`), então o `:` da tag é
    # procurado só no último componente do caminho.
    head, slash, last = remainder.rpartition("/")
    name_part, _, tag = last.partition(":")
    name = f"{head}{slash}{name_part}"
    return name, tag, digest
