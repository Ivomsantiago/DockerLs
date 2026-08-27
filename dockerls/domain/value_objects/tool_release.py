"""Qual artefato de release baixar, para qual plataforma.

Puro de propósito: a escolha do asset é uma regra sobre nomes, e uma regra
sobre nomes se testa exaustivamente sem rede, sem disco e sem instalar nada.
O download, a verificação e a extração vivem em `infrastructure/toolchain`,
que é onde o I/O pertence.

Os nomes não são adivinhados, e foram confirmados por duas fontes
independentes: a configuração de release de cada projeto (`goreleaser.yml` no
Trivy, `.goreleaser.yaml` no Grype), que produz os arquivos, e o `install.sh`
oficial de cada um, que os consome.

    Trivy   contrib/install.sh:390
            NAME=${PROJECT_NAME}_${VERSION}_${OS}-${ARCH}
            CHECKSUM=${PROJECT_NAME}_${VERSION}_checksums.txt
            adjust_os:   linux -> Linux, darwin -> macOS, windows inalterado
            adjust_arch: amd64 -> 64bit, arm64 -> ARM64

    Grype   install.sh:432 (search_for_asset)
            asset_glob="${name}_.*_${os}_${arch}.${format}"
            checksums:   "${name}_${version}_checksums.txt"
            os/arch vêm de `uname` em minúsculas, sem tradução

Os dois usam `zip` no Windows e `tar.gz` no resto.

Uma plataforma sem artefato conhecido devolve None, e o comando recusa com
uma mensagem em vez de tentar uma URL genérica que daria 404 depois do
consentimento do usuário.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class OS(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class Arch(StrEnum):
    AMD64 = "amd64"
    ARM64 = "arm64"


def detect_os(system: str) -> OS | None:
    """Traduz `platform.system()` para o enum, ou None se não suportado.

    Recusar explicitamente é o ponto: um SO desconhecido tem que falhar com
    mensagem, não escorregar para o caminho do Linux e baixar um binário
    que não roda ali.
    """
    match system.strip().lower():
        case "linux":
            return OS.LINUX
        case "windows":
            return OS.WINDOWS
        case "darwin":
            return OS.MACOS
        case _:
            return None


def detect_arch(machine: str) -> Arch | None:
    """Traduz `platform.machine()`, cujos rótulos variam por SO.

    `x86_64` no Linux e `AMD64` no Windows são a mesma arquitetura, e
    `aarch64`/`arm64` também.
    """
    match machine.strip().lower():
        case "x86_64" | "amd64" | "x64":
            return Arch.AMD64
        case "aarch64" | "arm64":
            return Arch.ARM64
        case _:
            return None


@dataclass(frozen=True)
class ReleaseAsset:
    """O que baixar e onde conferir, para uma versão e plataforma."""

    #: URL do arquivo compactado com o binário.
    archive_url: str
    #: URL do arquivo de checksums que cobre esse arquivo.
    checksums_url: str
    #: Nome do arquivo dentro do `checksums.txt`, que é por onde a linha
    #: correta é localizada.
    archive_name: str
    #: Nome do binário depois de extraído, com a extensão do SO.
    binary_name: str
    #: A página de release, para o usuário conferir de onde isto vem antes
    #: de consentir.
    release_url: str
    #: Assinatura cosign do `checksums.txt`, quando o projeto publica uma.
    #: Vazio quando não publica -- e vazio nunca significa "não assinado":
    #: significa que este catálogo não sabe de nenhuma, que é ausência de
    #: informação e não veredito.
    checksums_signature_url: str = ""
    #: Certificado keyless que acompanha a assinatura.
    checksums_certificate_url: str = ""
    #: Regex da identidade que precisa ter assinado, e emissor OIDC
    #: esperado. Vazios quando não há assinatura a conferir.
    signer_identity_pattern: str = ""
    signer_oidc_issuer: str = ""


@dataclass(frozen=True)
class ToolSpec:
    """Um scanner e como o projeto dele publica os releases."""

    name: str
    owner: str
    repo: str
    #: Rótulos de SO no nome do arquivo, por plataforma.
    os_labels: dict[OS, str]
    #: Rótulos de arquitetura no nome do arquivo.
    arch_labels: dict[Arch, str]
    #: Separador **entre SO e arquitetura**: o Trivy usa `-`
    #: (`Linux-64bit`), o Grype `_` (`linux_amd64`). O separador entre
    #: projeto, versão e plataforma é `_` nos dois -- é o que o goreleaser
    #: emite -- e não é configurável aqui.
    separator: str
    #: Plataformas para as quais o projeto publica artefato.
    supported: frozenset[tuple[OS, Arch]]
    #: Se o projeto publica `checksums.txt.sig` e `checksums.txt.pem` ao
    #: lado do `checksums.txt`, que é o par que o `cosign verify-blob`
    #: consome.
    #:
    #: A cadeia inteira depende disto e de mais nada: a assinatura prova
    #: que o `checksums.txt` é o que o projeto publicou, e o SHA-256 do
    #: arquivo compactado contra a linha correspondente prova que o
    #: arquivo é o que aquele `checksums.txt` descreve.
    #:
    #: `False` significa **não confirmado por este catálogo**, e não "não
    #: assinado": ninguém aqui foi ao release ver. A instalação segue com
    #: o checksum, e `signature_verified` fica `None` -- ausência de
    #: verificação, dita como ausência.
    signs_checksums: bool = False

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    def supports(self, os_: OS, arch: Arch) -> bool:
        return (os_, arch) in self.supported

    def asset_for(self, version: str, os_: OS, arch: Arch) -> ReleaseAsset | None:
        """O artefato desta versão para esta plataforma, ou None.

        `version` vem sem o `v` inicial: as tags são `v0.58.1` e os arquivos
        dentro do release são `trivy_0.58.1_...`.
        """
        if not self.supports(os_, arch):
            return None
        clean = version.lstrip("v")
        if not clean:
            return None

        extension = "zip" if os_ is OS.WINDOWS else "tar.gz"
        platform_label = f"{self.os_labels[os_]}{self.separator}{self.arch_labels[arch]}"
        archive = f"{self.repo}_{clean}_{platform_label}.{extension}"
        # O goreleaser sempre nomeia o checksum com `_`, mesmo quando o
        # template do arquivo usa outro separador.
        checksums = f"{self.repo}_{clean}_checksums.txt"
        base = f"{self.repo_url}/releases/download/v{clean}"
        return ReleaseAsset(
            archive_url=f"{base}/{archive}",
            checksums_url=f"{base}/{checksums}",
            archive_name=archive,
            binary_name=f"{self.name}.exe" if os_ is OS.WINDOWS else self.name,
            release_url=f"{self.repo_url}/releases/tag/v{clean}",
            checksums_signature_url=(f"{base}/{checksums}.sig" if self.signs_checksums else ""),
            checksums_certificate_url=(f"{base}/{checksums}.pem" if self.signs_checksums else ""),
            # A identidade tem de ser deste projeto: uma assinatura válida
            # de *outra* workflow do GitHub prova que alguém assinou, e não
            # que quem publica esta ferramenta assinou. O emissor é o do
            # OIDC do GitHub Actions, que é como os dois projetos assinam.
            signer_identity_pattern=(
                rf"^https://github\.com/{self.owner}/{self.repo}/" if self.signs_checksums else ""
            ),
            signer_oidc_issuer=(
                "https://token.actions.githubusercontent.com" if self.signs_checksums else ""
            ),
        )


_EVERY_PLATFORM = frozenset(
    {
        (OS.LINUX, Arch.AMD64),
        (OS.LINUX, Arch.ARM64),
        (OS.WINDOWS, Arch.AMD64),
        (OS.MACOS, Arch.AMD64),
        (OS.MACOS, Arch.ARM64),
    }
)

#: Rótulos conforme `goreleaser.yml` do Trivy: CamelCase para o SO,
#: `64bit`/`ARM64` para a arquitetura, separados por `-`. Windows não está
#: na lista de casos especiais do template, então cai no `.Os` cru, em
#: minúsculas.
TRIVY = ToolSpec(
    name="trivy",
    owner="aquasecurity",
    repo="trivy",
    os_labels={OS.LINUX: "Linux", OS.WINDOWS: "windows", OS.MACOS: "macOS"},
    arch_labels={Arch.AMD64: "64bit", Arch.ARM64: "ARM64"},
    separator="-",
    supported=_EVERY_PLATFORM,
    # Não confirmado: o release do Trivy não foi inspecionado a partir
    # deste ambiente, e afirmar que ele assina (ou que não assina) seria
    # inventar. Fica `False`, a instalação segue pelo checksum, e
    # `signature_verified` volta `None` -- ausência de verificação, dita
    # como ausência.
    signs_checksums=False,
)

#: O `.goreleaser.yaml` do Grype não declara `name_template`, então vale o
#: default do goreleaser: tudo minúsculo, separado por `_`.
GRYPE = ToolSpec(
    name="grype",
    owner="anchore",
    repo="grype",
    os_labels={OS.LINUX: "linux", OS.WINDOWS: "windows", OS.MACOS: "darwin"},
    arch_labels={Arch.AMD64: "amd64", Arch.ARM64: "arm64"},
    separator="_",
    supported=_EVERY_PLATFORM,
    # Confirmado no `install.sh` do próprio Grype, que baixa
    # `checksums.txt.sig` e `checksums.txt.pem` ao lado do `checksums.txt`
    # e chama `cosign verify-blob` com os três.
    signs_checksums=True,
)

#: Os scanners que `doctor --install` sabe instalar, na ordem em que são
#: oferecidos. Trivy primeiro porque é o scanner primário do projeto.
INSTALLABLE: tuple[ToolSpec, ...] = (TRIVY, GRYPE)
