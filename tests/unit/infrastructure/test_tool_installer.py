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
import pathlib
import tarfile
import zipfile
from typing import TYPE_CHECKING

import httpx
import pytest

from dockerls.domain.value_objects.tool_release import GRYPE, OS, TRIVY, Arch
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


def _signed_plan(tmp_path: Path) -> InstallPlan:
    """Um plano do Grype -- o projeto que publica `checksums.txt.sig`."""
    asset = GRYPE.asset_for("0.87.0", OS.LINUX, Arch.AMD64)
    assert asset is not None
    return InstallPlan(
        tool="grype",
        version="0.87.0",
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

    async def test_the_real_guard_does_not_refuse_the_release_urls(self, tmp_path):
        """Regressão: o guard julga `host[:porta]`, e recebia a URL inteira.

        `hostname_of("https://github.com/...")` corta no dois-pontos do
        esquema e devolve `https`, que não resolve para endereço nenhum, e
        `doctor --install` recusava a si mesmo em toda máquina com política
        de rede ligada -- que é o padrão. A allowlist evita DNS no teste.
        """
        from dockerls.domain.value_objects.network_policy import NetworkPolicy
        from dockerls.infrastructure.network.host_guard import HostGuard

        archive = _tarball({"trivy": BINARY})
        plan = _plan(tmp_path)
        installer = _installer(
            {
                plan.asset.archive_name: (200, archive),
                "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            }
        )
        installer._guard = HostGuard(  # type: ignore[assignment]
            NetworkPolicy(allowed_hosts=frozenset({"github.com"}))
        )

        outcome = await installer.install(plan)
        assert outcome.installed is True


class TestSignatureVerification:
    """A assinatura cobre o `checksums.txt`, e o checksum cobre o arquivo.

    A cadeia tem exatamente dois elos e nenhum a mais: não existe assinatura
    por artefato para conferir diretamente. O que estes testes travam é a
    diferença que decide se uma instalação aborta -- assinatura **inválida**
    é uma afirmação; cosign ausente, projeto sem assinatura conhecida e
    cosign inconclusivo são ausências, e nenhuma delas impede a instalação
    nem é reportada como verificação.
    """

    @staticmethod
    def _routes(plan: InstallPlan, archive: bytes) -> dict[str, tuple[int, bytes]]:
        return {
            plan.asset.archive_name: (200, archive),
            "checksums.txt": (200, _checksums(plan.asset.archive_name, archive).encode()),
            "checksums.txt.sig": (200, b"-----BEGIN SIGNATURE-----"),
            "checksums.txt.pem": (200, b"-----BEGIN CERTIFICATE-----"),
        }

    async def test_an_invalid_signature_aborts_the_install(self, tmp_path):
        """Assinatura inválida é uma afirmação, não uma ausência: aborta."""

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                return False

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        installer = _installer(self._routes(plan, archive))

        outcome = await installer.install(plan, cosign=_Cosign())

        assert outcome.installed is False
        assert "invalid signature" in outcome.detail
        assert not (plan.destination / "grype").exists()

    async def test_a_valid_signature_is_reported(self, tmp_path):
        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                return True

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        installer = _installer(self._routes(plan, archive))

        outcome = await installer.install(plan, cosign=_Cosign())

        assert outcome.installed is True
        assert outcome.signature_verified is True
        assert "cosign signature" in outcome.detail

    async def test_the_signature_covers_the_checksums_file(self, tmp_path):
        """O blob assinado é o `checksums.txt`, e não o arquivo compactado:
        é assim que o Grype publica, e é o único elo que existe."""
        seen: dict[str, str] = {}

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                seen["blob"] = pathlib.Path(blob).read_text(encoding="utf-8")
                seen.update({k: str(v) for k, v in kwargs.items()})
                return True

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        await _installer(self._routes(plan, archive)).install(plan, cosign=_Cosign())

        assert plan.asset.archive_name in seen["blob"]
        assert seen["signature"].endswith(".sig")
        assert seen["certificate"].endswith(".pem")

    async def test_the_identity_is_constrained_to_the_project(self, tmp_path):
        """Sem restringir identidade, o cosign responde "alguém assinou" --
        uma pergunta diferente da que importa."""
        seen: dict[str, str] = {}

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                seen.update({k: str(v) for k, v in kwargs.items()})
                return True

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        await _installer(self._routes(plan, archive)).install(plan, cosign=_Cosign())

        assert "anchore/grype" in seen["certificate_identity_regexp"]
        assert seen["certificate_oidc_issuer"] == "https://token.actions.githubusercontent.com"

    async def test_the_signature_is_checked_before_the_digest(self, tmp_path):
        """Conferir o digest primeiro compararia o arquivo com uma lista que
        ainda não se sabe de quem é -- e uma lista adulterada aprova um
        arquivo adulterado."""
        order: list[str] = []

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                order.append("signature")
                return False

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        routes = self._routes(plan, archive)
        # Checksum propositalmente errado: se o digest fosse conferido
        # primeiro, a mensagem seria "checksum mismatch" em vez da recusa
        # por assinatura.
        routes["checksums.txt"] = (
            200,
            _checksums(plan.asset.archive_name, archive, corrupt=True).encode(),
        )

        outcome = await _installer(routes).install(plan, cosign=_Cosign())

        assert order == ["signature"]
        assert "invalid signature" in outcome.detail

    async def test_no_cosign_is_an_absence_and_not_a_refusal(self, tmp_path):
        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)

        outcome = await _installer(self._routes(plan, archive)).install(plan, cosign=None)

        assert outcome.installed is True
        assert outcome.signature_verified is None
        # O tmp_path do pytest carrega o nome do teste, e "cosign" aparece
        # nele; a asserção olha só o prefixo da frase, que é onde a
        # verificação seria anunciada.
        assert outcome.detail.startswith("verified sha256")

    async def test_an_inconclusive_cosign_is_an_absence_and_not_an_approval(self, tmp_path):
        """`None` do verificador é "não consegui concluir" -- rede fora,
        Rekor indisponível. Nunca vira `True`."""

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                return None

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)

        outcome = await _installer(self._routes(plan, archive)).install(plan, cosign=_Cosign())

        assert outcome.installed is True
        assert outcome.signature_verified is None

    async def test_a_project_without_known_signatures_installs_on_the_checksum_alone(
        self, tmp_path
    ):
        """`signs_checksums=False` significa "não confirmado por este
        catálogo", e não "não assinado". A instalação segue, e
        `signature_verified` fica `None`."""

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                raise AssertionError("não há assinatura declarada para pedir ao cosign")

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
        assert outcome.signature_verified is None

    async def test_missing_signature_material_does_not_block_the_install(self, tmp_path):
        """O par `.sig`/`.pem` não veio (404, rede). É ausência de
        verificação, e o checksum publicado continua valendo."""

        class _Cosign:
            async def verify_blob(self, blob, **kwargs):
                raise AssertionError("não havia material de assinatura para verificar")

        archive = _tarball({"grype": BINARY})
        plan = _signed_plan(tmp_path)
        routes = self._routes(plan, archive)
        routes["checksums.txt.sig"] = (404, b"not found")

        outcome = await _installer(routes).install(plan, cosign=_Cosign())

        assert outcome.installed is True
        assert outcome.signature_verified is None

    def test_the_signature_urls_are_part_of_what_the_user_consents_to(self, tmp_path):
        """Uma URL que a confirmação não mostrou é uma URL que ninguém
        consentiu -- e que a política de rede não julgou."""
        plan = _signed_plan(tmp_path)
        assert plan.asset.checksums_signature_url in plan.sources
        assert plan.asset.checksums_certificate_url in plan.sources


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
