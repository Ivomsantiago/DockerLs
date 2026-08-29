"""Para onde a imagem vai, e o que cada provedor exige antes de aceitar.

O `--push` existente rodava `docker push <tag>` com a tag local, exatamente
como ela foi construída. Numa tag sem host -- `dockerls:1.3.2`, que é a forma
que todo mundo digita -- isso vira uma tentativa de publicar em
`docker.io/library/dockerls`, que falha com "denied" para qualquer pessoa que
não seja mantenedora de uma imagem oficial. E o assistente interativo oferecia
escolher entre "dockerhub", "ghcr" e "harbor" sem usar a resposta para nada:
nenhuma delas mudava o destino do push.

Este módulo é a peça que faltava. Ele não fala com registry nenhum -- é
domínio puro, testável sem rede -- e responde três perguntas que precisam de
resposta *antes* do build começar:

* **para onde**, montando a referência completa a partir de host, namespace,
  repositório e tag;
* **isso é válido para este provedor**, porque as regras diferem de verdade: o
  Artifact Registry do Google exige `projeto/repositório` no caminho, o ACR do
  Azure exige um host `<registro>.azurecr.io`, e o Docker Hub exige um
  namespace que não seja `library`;
* **como autenticar**, nomeando o comando de login de cada provedor, já que é
  a primeira coisa que falta quando um push é recusado.

Perguntar antes do build, e não depois, é o ponto: descobrir que o destino
está errado depois de escanear e construir desperdiça o trabalho todo, e é
justamente quando a pessoa está mais propensa a publicar em qualquer lugar só
para não repetir a espera.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class RegistryProvider(StrEnum):
    """Quem hospeda o destino. Determina validação e forma de login."""

    DOCKER_HUB = "Docker Hub"
    AZURE_ACR = "Azure Container Registry"
    GOOGLE_ARTIFACT_REGISTRY = "Google Artifact Registry"
    GOOGLE_CONTAINER_REGISTRY = "Google Container Registry"
    DHI = "Docker Hardened Images"
    GITHUB_GHCR = "GitHub Container Registry"
    OTHER = "Registry privado"


#: Hosts que significam Docker Hub.
_DOCKER_HUB_HOSTS = frozenset({"", "docker.io", "index.docker.io", "registry-1.docker.io"})

#: `<registro>.azurecr.io`, incluindo as nuvens soberanas (`.azurecr.cn`,
#: `.azurecr.us`), que são o mesmo produto em outra geografia.
_ACR_HOST = re.compile(r"^[a-z0-9]+\.azurecr\.(io|cn|us)$")

#: `<região>-docker.pkg.dev` do Artifact Registry.
_GAR_HOST = re.compile(r"^[a-z0-9-]+-docker\.pkg\.dev$")

#: O GCR clássico, incluindo os espelhos regionais (`eu.gcr.io`).
_GCR_HOST = re.compile(r"^(?:[a-z0-9]+\.)?gcr\.io$")

#: Componente de caminho aceito por qualquer registry OCI.
_PATH_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")

#: Tag OCI.
_TAG = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$")


def detect_provider(host: str) -> RegistryProvider:
    """Quem hospeda `host`. Um host desconhecido é registry privado, não erro."""
    value = host.strip().lower()
    if value in _DOCKER_HUB_HOSTS:
        return RegistryProvider.DOCKER_HUB
    if _ACR_HOST.match(value):
        return RegistryProvider.AZURE_ACR
    if _GAR_HOST.match(value):
        return RegistryProvider.GOOGLE_ARTIFACT_REGISTRY
    if _GCR_HOST.match(value):
        return RegistryProvider.GOOGLE_CONTAINER_REGISTRY
    if value == "dhi.io":
        return RegistryProvider.DHI
    if value == "ghcr.io":
        return RegistryProvider.GITHUB_GHCR
    return RegistryProvider.OTHER


#: Como autenticar em cada provedor. Nomeado porque é o que falta em quase
#: todo push recusado, e porque a mensagem genérica do Docker ("denied")
#: não diz qual comando resolve.
LOGIN_HINTS: dict[RegistryProvider, str] = {
    RegistryProvider.DOCKER_HUB: (
        "docker login  (or `dockerls login`, which stores it in the keyring)"
    ),
    RegistryProvider.AZURE_ACR: "az acr login --name <registry>",
    RegistryProvider.GOOGLE_ARTIFACT_REGISTRY: (
        "gcloud auth configure-docker <region>-docker.pkg.dev"
    ),
    RegistryProvider.GOOGLE_CONTAINER_REGISTRY: "gcloud auth configure-docker gcr.io",
    RegistryProvider.DHI: "docker login dhi.io  (requires a Docker Hardened Images subscription)",
    RegistryProvider.GITHUB_GHCR: (
        "echo $GITHUB_TOKEN | docker login ghcr.io -u <username> --password-stdin"
    ),
    RegistryProvider.OTHER: "docker login <host>",
}


class InvalidRegistryTargetError(ValueError):
    """O destino não é publicável como está, com o motivo em texto."""


@dataclass(frozen=True)
class RegistryTarget:
    """Um destino de publicação completo, validado por provedor.

    `namespace` é o caminho entre o host e o repositório, e é onde os
    provedores divergem: no Docker Hub é o usuário ou organização; no ACR
    costuma ser vazio ou um agrupamento livre; no Artifact Registry é
    obrigatoriamente `<projeto>/<repositório>`.
    """

    host: str
    repository: str
    tag: str
    namespace: str = ""

    @property
    def provider(self) -> RegistryProvider:
        return detect_provider(self.host)

    @property
    def path(self) -> str:
        parts = [p for p in (self.namespace.strip("/"), self.repository.strip("/")) if p]
        return "/".join(parts)

    @property
    def reference(self) -> str:
        """A referência que vai para `docker tag` e `docker push`."""
        host = self.host.strip().strip("/")
        base = f"{host}/{self.path}" if host else self.path
        return f"{base}:{self.tag}"

    @property
    def login_hint(self) -> str:
        return LOGIN_HINTS[self.provider]

    def validate(self) -> None:
        """Levanta `InvalidRegistryTargetError` com o motivo, ou não faz nada.

        Validar aqui, antes do build, é o objetivo do módulo: um destino
        malformado descoberto depois do scan custa o build inteiro.
        """
        if not self.repository.strip():
            raise InvalidRegistryTargetError("the destination repository cannot be empty")
        if not _TAG.match(self.tag or ""):
            raise InvalidRegistryTargetError(f"invalid tag: {self.tag!r}")
        for component in self.path.split("/"):
            if not _PATH_COMPONENT.match(component):
                raise InvalidRegistryTargetError(
                    f"invalid path component: {component!r} "
                    "(lowercase, digits, and the . _ - separators)"
                )
        self._validate_provider()

    def _validate_provider(self) -> None:
        provider = self.provider
        if provider is RegistryProvider.DOCKER_HUB:
            # Sem namespace, `docker push` mira `library/<repo>`, que é
            # reservado às imagens oficiais: o push é recusado com "denied" e
            # a mensagem não explica por quê.
            if not self.namespace.strip("/"):
                raise InvalidRegistryTargetError(
                    "Docker Hub requires the user or organization as the namespace "
                    "(e.g. myorg/dockerls); without it the push targets library/, "
                    "which is reserved for official images"
                )
            if self.namespace.strip("/").lower() == "library":
                raise InvalidRegistryTargetError(
                    "`library` is the namespace of Docker Hub official images and "
                    "does not accept third-party publishing"
                )
        elif provider is RegistryProvider.GOOGLE_ARTIFACT_REGISTRY:
            # gcr.io aceitava `projeto/imagem`; o Artifact Registry exige o
            # repositório no caminho, e omiti-lo falha só na hora do push.
            if len(self.path.split("/")) < 3:
                raise InvalidRegistryTargetError(
                    "Artifact Registry requires <project>/<repository>/<image> in the "
                    "path (e.g. my-project/containers/dockerls)"
                )
        elif provider is RegistryProvider.DHI:
            raise InvalidRegistryTargetError(
                "dhi.io is a Docker image catalogue, not a publish destination: it "
                "distributes hardened images and does not accept pushes"
            )

    @classmethod
    def parse(cls, destination: str, tag: str) -> RegistryTarget:
        """Monta um destino a partir de `host/namespace/repo` e uma tag.

        O host é reconhecido pela mesma regra do Docker -- primeiro componente
        com ponto, dois-pontos, ou igual a `localhost` --, e o que sobra é
        dividido em namespace e repositório.
        """
        value = destination.strip().strip("/")
        if not value:
            raise InvalidRegistryTargetError("empty destination")
        # Uma tag embutida no destino é ambiguidade, não conveniência: qual
        # das duas vale, a de `--tag` ou a colada aqui?
        head = value.split("/", 1)[0]
        if ":" in value.rsplit("/", 1)[-1]:
            raise InvalidRegistryTargetError(
                "give the destination without a tag; the tag comes from --tag so "
                "there are never two"
            )

        if "." in head or ":" in head or head.lower() == "localhost":
            host, _, rest = value.partition("/")
        else:
            host, rest = "", value
        if not rest:
            raise InvalidRegistryTargetError(
                f"the destination {destination!r} does not name a repository"
            )

        namespace, _, repository = rest.rpartition("/")
        return cls(host=host, repository=repository, tag=tag, namespace=namespace)
