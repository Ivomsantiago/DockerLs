"""O nome que aparece na tabela, sem o registry que a coluna ao lado já diz.

A tabela de resultados tem treze colunas e nenhuma largura sobrando. Com
`overflow="fold"`, um nome como `gcr.io/distroless/nodejs22-debian12` era
quebrado no meio da palavra e saía em duas ou três linhas ilegíveis --
enquanto a coluna `Source`, encostada nele, já dizia "Distroless".

Encurtar aqui não é cosmético: o leitor precisa reconhecer *que runtime é
aquele* de relance, e é justamente essa metade que se perdia. `nodejs22-debian12`
diz Node 22 sobre Debian 12; `gcr.io/distrole` / `ss/nodejs22-de` não diz nada.

O corte só acontece quando a coluna vizinha carrega a informação removida.
Um registry que a tabela não identifica -- `ghcr.io/org/app` -- é mostrado
inteiro, porque ali o host *é* a identidade e escondê-lo confundiria duas
imagens diferentes com o mesmo nome final.

A referência completa não se perde em lugar nenhum: `--format json`, a linha
`Pin to:` e a evidência continuam com o nome inteiro, que é o que alguém
copia para um Dockerfile.
"""

from __future__ import annotations

#: Prefixos de catálogos que a coluna `Source` já nomeia.
_REDUNDANT_PREFIXES = (
    "cgr.dev/chainguard/",
    "gcr.io/distroless/",
    "dhi.io/",
    "docker.io/library/",
    "index.docker.io/library/",
)


def display_name(name: str) -> str:
    """O nome do runtime, sem o prefixo que a coluna `Source` repete."""
    value = name.strip()
    for prefix in _REDUNDANT_PREFIXES:
        if value.lower().startswith(prefix):
            return value[len(prefix) :] or value
    return value


def display_reference(name: str, tag: str) -> str:
    short = display_name(name)
    return f"{short}:{tag}" if tag else short


def _looks_like_registry(segment: str) -> bool:
    """A leading path segment is a registry host, not a repository owner,
    when it carries a port (`:`), a domain (`.`) or is `localhost`.

    Docker's own reference grammar uses exactly this rule to tell
    `registry.internal:5000/app` (host, no tag) from `node:18` (no host, a
    tag): a bare repository component never contains a colon or a dot.
    """
    return ":" in segment or "." in segment or segment == "localhost"


def split_repository_and_tag(reference: str) -> tuple[str, str]:
    """Split an image reference into (repository, tag).

    Unlike a plain `rsplit(":", 1)`, this never mistakes a `host:port`
    registry prefix for a tag: only a colon in the *last* path segment
    counts. A digest suffix (`@sha256:...`) is stripped first and never
    treated as part of the tag.
    """
    ref = reference.split("@", 1)[0]
    parts = ref.split("/")
    prefix = ""
    if len(parts) > 1 and _looks_like_registry(parts[0]):
        prefix = parts[0] + "/"
        parts = parts[1:]
    tail = "/".join(parts)
    if ":" in tail:
        repo_tail, tag = tail.rsplit(":", 1)
        return prefix + repo_tail, tag
    return ref, ""


def reject_tagged_reference(image: str, command: str) -> str | None:
    """An error message when `image` names a tag instead of a bare
    repository, or None when the argument is fine as given.

    `search`, `recommend` and `export` all take a repository name and
    discover its tags themselves; a caller who passes `node:18` almost
    certainly meant to inspect that one tag, not search for a repository
    literally named `node:18` (which does not exist and used to fail with
    an opaque "No tags found").
    """
    repository, tag = split_repository_and_tag(image)
    if not tag:
        return None
    return (
        f"Error: '{command}' takes the image name, not a specific tag. "
        f"Did you mean 'dockerls {command} {repository}'? "
        f"To analyze one specific tag, use 'dockerls analyze {image}'."
    )
