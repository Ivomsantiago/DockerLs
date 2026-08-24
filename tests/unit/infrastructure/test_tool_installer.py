"""Instalar um scanner sem executar nada de terceiro.

Nenhum teste aqui toca a rede ou instala coisa alguma: o transporte HTTP é
fixo e o destino é um `tmp_path`. O que está sob teste é o que separa este
caminho de um `curl | sh`: o checksum publicado é conferido **antes** de
qualquer extração, e um arquivo que tenta escrever fora do destino é
recusado em vez de extraído.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zipfile
from typing import TYPE_CHECKING

import httpx
import pytest

from dockerls.domain.value_objects.tool_release import OS, TRIVY, Arch
from dockerls.infrastructure.toolchain.installer import (
    InstallError,
    InstallPlan,
    ToolInstaller,
)

if TYPE_CHECKING:
    from pathlib import Path

BINARY = b"#!/bin/sh\necho trivy\n"


def _tarball(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def _checksums(name: str, payload: bytes, *, corrupt: bool = False) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    if corrupt:
        digest = "0" * 64
    return f"{digest}  {name}\n{'1' * 64}  some_other_file.tar.gz\n"


def _plan(tmp_path: Path, os_: OS = OS.LINUX) -> InstallPlan:
    asset = TRIVY.asset_for("0.58.1", os_, Arch.AMD64)
    assert asset is not None
    return InstallPlan(
        tool="trivy",
        version="0.58.1",
        asset=asset,
        destination=tmp_path / "bin",
        needs_privilege=False,
    )


def _installer(routes: dict[str, tuple[int, bytes]]) -> ToolInstaller:
    """Um instalador cujo transporte devolve corpos fixos por sufixo de URL."""

    def handler(request: httpx.Request) -> httpx.Response:
        for suffix, (status, body) in routes.items():
            if str(request.url).endswith(suffix):
                return httpx.Response(status, content=body)
        return httpx.Response(404, content=b"not found")

    transport = httpx.MockTransport(handler)
    return ToolInstaller(
        client_factory=lambda: httpx.AsyncClient(transport=transport, follow_redirects=True)
    )


class TestChecksumGatesTheInstall:
    async def test_a_matching_checksum_installs_the_binary(self, tmp_path):
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan)

        assert outcome.installed is True
        assert outcome.path is not None
        assert outcome.path.read_bytes() == BINARY
        assert os.access(outcome.path, os.X_OK)

    async def test_a_mismatched_checksum_blocks_the_install(self, tmp_path):
        """O teste central: bytes que não conferem nunca chegam ao disco."""
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (
                    200,
                    _checksums(plan.asset.archive_name, archive, corrupt=True).encode(),
                ),
            }
        )

        outcome = await installer.install(plan)

        assert outcome.installed is False
        assert "checksum mismatch" in outcome.detail
        # E nada foi escrito: nem o binário, nem um parcial.
        assert not (plan.destination / "trivy").exists()
        assert list(plan.destination.glob("*")) == [] or not plan.destination.exists()

    async def test_an_archive_missing_from_the_checksum_file_is_refused(self, tmp_path):
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, b"%s  unrelated.tar.gz\n" % (b"a" * 64)),
            }
        )

        outcome = await installer.install(plan)

        assert outcome.installed is False
        assert "not listed in the published checksum file" in outcome.detail

    async def test_a_malformed_digest_is_refused(self, tmp_path):
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, f"nothexadecimal  {plan.asset.archive_name}\n".encode()),
            }
        )

        outcome = await installer.install(plan)
        assert outcome.installed is False

    async def test_a_prefix_name_does_not_match_the_wrong_line(self, tmp_path):
        """Casar por sufixo confundiria `trivy_..._Linux-64bit.tar.gz` com
        uma linha de `outro_Linux-64bit.tar.gz`."""
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        wrong = hashlib.sha256(b"other bytes").hexdigest()
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, f"{wrong}  evil_{plan.asset.archive_name}\n".encode()),
            }
        )

        outcome = await installer.install(plan)
        assert outcome.installed is False
        assert "not listed" in outcome.detail


class TestArchiveIsUntrustedInput:
    async def test_a_path_traversal_member_is_refused(self, tmp_path):
        """CVE-2007-4559: um `.tar.gz` pode carregar `../../..` e virar
        escrita arbitrária. Só o binário na raiz é aceito."""
        escape = "../../../../" + str(tmp_path / "pwned").lstrip("/")
        archive = _tarball({escape: b"owned", "trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan)

        # O membro legítimo existe, então instala -- e o hostil é ignorado
        # por construção, porque só o nome exato é extraído.
        assert outcome.installed is True
        assert not (tmp_path / "pwned").exists()

    async def test_an_archive_without_the_binary_is_refused(self, tmp_path):
        archive = _tarball({"README.md": b"nothing useful"})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan)
        assert outcome.installed is False
        assert "does not contain trivy" in outcome.detail

    async def test_a_nested_binary_is_not_accepted(self, tmp_path):
        """O release publica o binário na raiz. Qualquer outra forma não é
        o que se espera dele."""
        archive = _tarball({"nested/trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan)
        assert outcome.installed is False

    async def test_a_windows_zip_is_extracted(self, tmp_path):
        plan = _plan(tmp_path, OS.WINDOWS)
        archive = _zip({"trivy.exe": BINARY})
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan)

        assert outcome.installed is True
        assert outcome.path is not None
        assert outcome.path.name == "trivy.exe"


class TestNetworkFailuresAreContained:
    async def test_a_missing_archive_reports_a_failure(self, tmp_path):
        plan = _plan(tmp_path)
        installer = _installer({"checksums.txt": (200, b"")})

        outcome = await installer.install(plan)
        assert outcome.installed is False

    async def test_a_missing_checksum_file_blocks_the_install(self, tmp_path):
        """Sem checksum não há verificação, e sem verificação não há
        instalação -- mesmo que o arquivo tenha baixado inteiro."""
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer({plan.asset.archive_name: (200, archive)})

        outcome = await installer.install(plan)
        assert outcome.installed is False
        assert not (plan.destination / "trivy").exists()

    async def test_the_network_policy_can_refuse_the_download(self, tmp_path):
        class _Guard:
            def allows(self, url: str) -> bool:
                return False

        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )
        installer._guard = _Guard()  # type: ignore[assignment]

        outcome = await installer.install(plan)
        assert outcome.installed is False
        assert "network policy" in outcome.detail


class TestSignatureVerification:
    async def test_an_invalid_signature_aborts_the_install(self, tmp_path):
        """Assinatura inválida é uma afirmação, não uma ausência: aborta."""

        class _Cosign:
            async def verify_blob(self, path: str, url: str) -> bool:
                return False

        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan, cosign=_Cosign())

        assert outcome.installed is False
        assert "invalid signature" in outcome.detail
        assert not (plan.destination / "trivy").exists()

    async def test_a_valid_signature_is_reported(self, tmp_path):
        class _Cosign:
            async def verify_blob(self, path: str, url: str) -> bool:
                return True

        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan, cosign=_Cosign())

        assert outcome.installed is True
        assert outcome.signature_verified is True

    async def test_without_cosign_the_checksum_still_installs(self, tmp_path):
        """A assinatura é reforço; o checksum publicado é o requisito."""
        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )

        outcome = await installer.install(plan, cosign=None)

        assert outcome.installed is True
        # None, não False: ninguém disse que a assinatura é ruim.
        assert outcome.signature_verified is None


class TestLatestVersion:
    async def test_the_tag_loses_its_leading_v(self, tmp_path):
        installer = _installer({"releases/latest": (200, b'{"tag_name": "v0.58.1"}')})
        assert await installer.latest_version(TRIVY) == "0.58.1"

    async def test_an_unreachable_feed_raises_an_install_error(self, tmp_path):
        installer = _installer({"releases/latest": (503, b"")})
        with pytest.raises(InstallError, match="could not resolve"):
            await installer.latest_version(TRIVY)

    async def test_a_feed_with_no_version_raises(self, tmp_path):
        installer = _installer({"releases/latest": (200, b"{}")})
        with pytest.raises(InstallError, match="no version"):
            await installer.latest_version(TRIVY)
