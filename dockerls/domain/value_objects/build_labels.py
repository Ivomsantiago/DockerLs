"""Quem responde por esta imagem, gravado nela antes de ela existir.

A regra DF007 deste projeto cobra `maintainer` e `security.scanner` de todo
Dockerfile que ele analisa, e o `build` publicava imagens sem nenhum dos dois
-- cobrando dos outros o que não fazia. Pior: `--labels` aceitava qualquer
JSON e não exigia nada, então o campo existia e ficava vazio.

O que estes rótulos resolvem acontece meses depois, às três da manhã: uma
imagem aparece rodando em produção, alguém precisa saber de onde ela veio,
qual commit a gerou e para quem ligar. Sem isso, a resposta é arqueologia a
partir da tag. As chaves usadas são as anotações pré-definidas da
especificação OCI, e não invenções deste projeto, justamente para que
qualquer ferramenta de inventário leia sem adaptação.

Perguntar antes do build é deliberado: depois do build a imagem já existe, e
rotular passa a ser reconstruir.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Rótulos sem os quais uma imagem não deveria chegar a um registry de
#: empresa. São poucos de propósito: uma lista longa vira formulário que
#: ninguém preenche de verdade.
REQUIRED_FIELDS: tuple[tuple[str, str], ...] = (
    ("owner", "Owning team or person for this image"),
    ("security_contact", "Who to tell about a vulnerability in this image"),
    ("source", "URL of the repository that produces this image"),
)


class MissingBuildMetadataError(ValueError):
    """Faltam rótulos obrigatórios, nomeados na mensagem."""


@dataclass(frozen=True)
class BuildIdentity:
    """A procedência de uma imagem, do jeito que a OCI espera lê-la."""

    #: Time ou pessoa responsável. Vira `maintainer` e
    #: `org.opencontainers.image.vendor`.
    owner: str = ""
    #: Canal de contato para vulnerabilidades.
    security_contact: str = ""
    #: Repositório de origem.
    source: str = ""
    title: str = ""
    description: str = ""
    version: str = ""
    #: Commit que gerou a imagem. Opcional porque nem todo build sai de um
    #: repositório limpo, mas é o campo que responde "qual código é esse".
    revision: str = ""
    #: Rótulos livres da equipe, aplicados por cima dos derivados.
    extra: dict[str, str] = field(default_factory=dict)

    def missing(self) -> list[str]:
        """Campos obrigatórios ainda vazios, na ordem em que devem ser pedidos."""
        return [name for name, _ in REQUIRED_FIELDS if not getattr(self, name, "").strip()]

    def require_complete(self) -> None:
        absent = self.missing()
        if absent:
            raise MissingBuildMetadataError(
                "required labels are missing: "
                + ", ".join(absent)
                + ". Give them as build options, or answer the questions "
                "(use --non-interactive to require them as options)."
            )

    def to_labels(self) -> dict[str, str]:
        """As chaves OCI, mais as duas que a regra DF007 cobra.

        Rótulos vazios são omitidos em vez de gravados em branco: uma chave
        presente e vazia é pior do que ausente, porque um inventário a lê
        como respondida.
        """
        labels: dict[str, str] = {}
        if self.owner:
            labels["maintainer"] = self.owner
            labels["org.opencontainers.image.vendor"] = self.owner
        if self.security_contact:
            # Não é chave OCI; é o canal que a pessoa de plantão procura.
            labels["security.contact"] = self.security_contact
        if self.source:
            labels["org.opencontainers.image.source"] = self.source
        if self.title:
            labels["org.opencontainers.image.title"] = self.title
        if self.description:
            labels["org.opencontainers.image.description"] = self.description
        if self.version:
            labels["org.opencontainers.image.version"] = self.version
        if self.revision:
            labels["org.opencontainers.image.revision"] = self.revision
        # Quem mediu esta imagem. A regra DF007 cobra exatamente isto, e o
        # `build` publicava sem.
        labels["security.scanner"] = "dockerls"
        labels.update({k: v for k, v in self.extra.items() if v})
        return labels
