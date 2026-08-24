"""Baixar, verificar e instalar um scanner, sem executar nada de terceiro.

Isto é uma ferramenta de segurança instalando outra, então o padrão usual --
`curl ... | sh` -- está fora de questão: não há como verificar a integridade
de um script antes de executá-lo, e nem o Trivy nem o Grype publicam checksum
do próprio `install.sh` (o que eles publicam é o checksum dos binários).

O caminho aqui faz o que aquele script faria, verificando:

1. resolve a versão publicada mais recente pela API de releases do projeto;
2. baixa o arquivo compactado **e** o `checksums.txt` do mesmo release;
3. confere o SHA-256 do arquivo contra a linha correspondente;
4. quando o cosign está disponível, confere também a assinatura;
5. extrai **apenas** o binário, para um diretório do usuário.

Nada baixado é executado. A extração é feita pelo `tarfile`/`zipfile` do
Python, sem shell, e cada membro do arquivo é validado antes de ser escrito:
um `.tar.gz` pode conter caminhos como `../../.ssh/authorized_keys`, e é
assim que uma extração ingênua vira escrita arbitrária no sistema de
arquivos.

Tudo acontece num diretório temporário que é removido ao fim, com sucesso ou
sem: um download interrompido não pode deixar meio binário ocupando espaço,
nem meio binário no PATH.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from loguru import logger

if TYPE_CHECKING:
    from dockerls.domain.value_objects.tool_release import ReleaseAsset, ToolSpec
    from dockerls.infrastructure.network.host_guard import HostGuard

#: Teto do arquivo compactado. Um scanner tem dezenas de MB; o limite existe
#: para que uma resposta inesperada não decida quanto este processo escreve
#: em disco.
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024

#: O `checksums.txt` tem alguns KB. Qualquer coisa maior não é ele.
MAX_CHECKSUMS_BYTES = 1024 * 1024

#: Permissão do binário instalado: executável pelo dono, legível pelos
#: demais. Nada de bit de escrita para grupo/outros -- um binário que
#: qualquer processo pode reescrever é um binário que qualquer processo
#: pode trocar.
BINARY_MODE = 0o755


class InstallError(RuntimeError):
    """Uma falha que impede a instalação, com mensagem para o usuário."""


@dataclass(frozen=True)
class InstallPlan:
    """O que será baixado, de onde, e o que isso exige do usuário.

    Existe para ser **impresso antes de qualquer download**: o consentimento
    só é informado se a pessoa vê a URL exata antes de dar o sim.
    """

    tool: str
    version: str
    asset: ReleaseAsset
    destination: Path
    #: True quando o destino exige privilégio que o usuário não tem. Aparece
    #: na confirmação, nunca surge no meio da execução.
    needs_privilege: bool

    @property
    def sources(self) -> tuple[str, ...]:
        return (self.asset.archive_url, self.asset.checksums_url)


@dataclass(frozen=True)
class InstallOutcome:
    tool: str
    installed: bool
    detail: str
    path: Path | None = None
    #: Se a assinatura foi conferida além do checksum. `None` quando o
    #: cosign não estava disponível -- ausência de verificação, que é
    #: diferente de assinatura inválida (essa aborta).
    signature_verified: bool | None = None


class ToolInstaller:
    """Instala um scanner a partir do release oficial do projeto."""

    def __init__(
        self,
        timeout: int = 120,
        guard: HostGuard | None = None,
        client_factory: object | None = None,
    ):
        self._timeout = timeout
        self._guard = guard
        # Injetável para que o teste nunca toque a rede.
        self._client_factory = client_factory

    def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._timeout, follow_redirects=True)

    async def latest_version(self, spec: ToolSpec) -> str:
        """A última versão publicada, pela API de releases do projeto."""
        url = f"https://api.github.com/repos/{spec.owner}/{spec.repo}/releases/latest"
        self._check_policy(url)
        try:
            async with self._client() as client:
                resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
                resp.raise_for_status()
                tag = str(resp.json().get("tag_name", "")).lstrip("v")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
            raise InstallError(f"could not resolve the latest {spec.name} version: {e}") from e
        if not tag:
            raise InstallError(f"the {spec.name} release feed returned no version")
        return tag

    def _check_policy(self, url: str) -> None:
        if self._guard is not None and not self._guard.allows(url):
            raise InstallError(f"the network policy refuses {url}")

    async def install(self, plan: InstallPlan, *, cosign: object | None = None) -> InstallOutcome:
        """Executa um plano já consentido.

        Todo o trabalho acontece num diretório temporário; o binário só
        chega ao destino depois de o checksum bater.
        """
        with tempfile.TemporaryDirectory(prefix="dockerls-install-") as tmp:
            workdir = Path(tmp)
            archive = workdir / plan.asset.archive_name
            try:
                # Dentro do `try` junto com o resto: este método devolve um
                # resultado, nunca levanta. Uma ferramenta recusada pela
                # política não pode abortar a tentativa de instalar a outra.
                for url in plan.sources:
                    self._check_policy(url)
                await self._download(plan.asset.archive_url, archive, MAX_ARCHIVE_BYTES)
                checksums = await self._fetch_text(plan.asset.checksums_url, MAX_CHECKSUMS_BYTES)
                expected = self._expected_digest(checksums, plan.asset.archive_name)
                actual = _sha256(archive)
                if actual != expected:
                    # Nada é extraído, nada é escrito no destino, e o
                    # temporário some com o `with`.
                    raise InstallError(
                        f"checksum mismatch for {plan.asset.archive_name}: "
                        f"expected {expected}, got {actual}"
                    )

                signature_verified = await _verify_signature(cosign, archive, plan)
                binary = self._extract(archive, workdir, plan.asset.binary_name)
                destination = self._place(binary, plan.destination, plan.asset.binary_name)
            except InstallError as e:
                return InstallOutcome(plan.tool, installed=False, detail=str(e))
            except (OSError, httpx.HTTPError) as e:
                return InstallOutcome(plan.tool, installed=False, detail=str(e))

        return InstallOutcome(
            plan.tool,
            installed=True,
            detail=f"verified sha256 and installed to {destination}",
            path=destination,
            signature_verified=signature_verified,
        )

    async def _download(self, url: str, target: Path, limit: int) -> None:
        async with self._client() as client, client.stream("GET", url) as resp:
            resp.raise_for_status()
            total = 0
            with target.open("wb") as fh:
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise InstallError(f"{url} exceeded {limit} bytes; refusing it")
                    fh.write(chunk)

    async def _fetch_text(self, url: str, limit: int) -> str:
        async with self._client() as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content = resp.content[: limit + 1]
            if len(content) > limit:
                raise InstallError(f"{url} exceeded {limit} bytes; refusing it")
            return content.decode("utf-8", errors="replace")

    @staticmethod
    def _expected_digest(checksums: str, archive_name: str) -> str:
        """A linha do `checksums.txt` que cobre este arquivo.

        Formato do goreleaser: `<sha256>  <filename>`. O arquivo é casado
        pelo nome exato -- um `endswith` casaria
        `trivy_0.58.1_Linux-64bit.tar.gz` com uma linha de
        `outro_Linux-64bit.tar.gz`.
        """
        for line in checksums.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            digest, name = parts
            if name.lstrip("*") == archive_name:
                if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest.lower()):
                    raise InstallError(f"malformed sha256 for {archive_name} in the checksum file")
                return digest.lower()
        raise InstallError(f"{archive_name} is not listed in the published checksum file")

    @staticmethod
    def _extract(archive: Path, workdir: Path, binary_name: str) -> Path:
        """Extrai só o binário, recusando qualquer caminho que escape.

        Um membro chamado `../../.ssh/authorized_keys` é como uma extração
        ingênua vira escrita arbitrária (CVE-2007-4559). Aqui só um membro
        é considerado -- o que tem exatamente o nome do binário, sem
        diretório -- e nada mais é escrito.
        """
        out = workdir / "extracted"
        out.mkdir(exist_ok=True)

        if archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                member = _safe_member(zf.namelist(), binary_name, archive.name)
                with zf.open(member) as src, (out / binary_name).open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive, "r:gz") as tf:
                member = _safe_member(tf.getnames(), binary_name, archive.name)
                info = tf.getmember(member)
                if not info.isfile():
                    raise InstallError(f"{member} in {archive.name} is not a regular file")
                extracted = tf.extractfile(info)
                if extracted is None:
                    raise InstallError(f"could not read {member} from {archive.name}")
                with extracted as src, (out / binary_name).open("wb") as dst:
                    shutil.copyfileobj(src, dst)

        return out / binary_name

    @staticmethod
    def _place(binary: Path, destination: Path, name: str) -> Path:
        """Move o binário verificado para o destino, atomicamente.

        `os.replace` dentro do mesmo sistema de arquivos é atômico, então
        nunca existe um instante em que o destino contém meio binário. Se
        cruzar sistemas de arquivos, cai para copiar e renomear -- ainda
        sem expor um arquivo parcial com o nome final.
        """
        destination.mkdir(parents=True, exist_ok=True)
        final = destination / name
        binary.chmod(BINARY_MODE)
        staging = destination / f".{name}.dockerls-partial"
        try:
            shutil.copy2(binary, staging)
            staging.chmod(BINARY_MODE)
            os.replace(staging, final)
        except OSError:
            staging.unlink(missing_ok=True)
            raise
        return final


def _safe_member(names: list[str], binary_name: str, archive_name: str) -> str:
    """O membro que é exatamente o binário, na raiz do arquivo.

    Comparar pelo nome completo, e não por sufixo, é o que impede que
    `evil/../../trivy` ou `nested/trivy` sejam aceitos: o release publica o
    binário na raiz, então qualquer outra forma não é o que se espera dele.
    """
    if binary_name in names:
        return binary_name
    raise InstallError(f"{archive_name} does not contain {binary_name} at its root")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


async def _verify_signature(cosign: object | None, archive: Path, plan: InstallPlan) -> bool | None:
    """Confere a assinatura quando há cosign, sem exigir que haja.

    Devolve None quando o cosign não está disponível: isso é ausência de
    verificação, e o checksum já garantiu que os bytes são os publicados.
    Uma assinatura **inválida**, por outro lado, aborta -- é uma afirmação,
    não uma ausência.
    """
    if cosign is None:
        return None
    verify = getattr(cosign, "verify_blob", None)
    if not callable(verify):
        return None
    try:
        ok = await verify(str(archive), plan.asset.archive_url)
    except Exception as e:  # pragma: no cover - a verificação é best-effort
        logger.debug(f"cosign verification unavailable for {plan.tool}: {e}")
        return None
    if ok is False:
        raise InstallError(
            f"cosign reported an invalid signature for {plan.asset.archive_name}; "
            "refusing to install it"
        )
    return bool(ok)
