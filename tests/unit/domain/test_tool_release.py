"""Qual artefato baixar, para qual plataforma.

Os nomes esperados aqui não são invenção: saem da configuração de release de
cada projeto -- `goreleaser.yml` no Trivy, `.goreleaser.yaml` no Grype --, que
é o que de fato produz os arquivos publicados. Uma regra sobre nomes se testa
exaustivamente sem rede, e é por isso que ela mora no domínio.
"""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.tool_release import (
    GRYPE,
    INSTALLABLE,
    OS,
    TRIVY,
    Arch,
    detect_arch,
    detect_os,
)


class TestOSDetection:
    @pytest.mark.parametrize(
        ("system", "expected"),
        [
            ("Linux", OS.LINUX),
            ("linux", OS.LINUX),
            ("Windows", OS.WINDOWS),
            ("Darwin", OS.MACOS),
            ("  Linux  ", OS.LINUX),
        ],
    )
    def test_platform_system_is_translated(self, system, expected):
        assert detect_os(system) is expected

    @pytest.mark.parametrize("system", ["FreeBSD", "SunOS", "", "Java"])
    def test_an_unsupported_system_is_refused_not_guessed(self, system):
        """Recusar explicitamente é o ponto: escorregar para o caminho do
        Linux baixaria um binário que não roda ali."""
        assert detect_os(system) is None


class TestArchDetection:
    @pytest.mark.parametrize(
        ("machine", "expected"),
        [
            # Mesma arquitetura, rótulos diferentes por SO.
            ("x86_64", Arch.AMD64),
            ("AMD64", Arch.AMD64),
            ("aarch64", Arch.ARM64),
            ("arm64", Arch.ARM64),
        ],
    )
    def test_platform_machine_is_translated(self, machine, expected):
        assert detect_arch(machine) is expected

    @pytest.mark.parametrize("machine", ["i386", "armv7l", "ppc64le", ""])
    def test_an_unsupported_arch_is_refused(self, machine):
        assert detect_arch(machine) is None


class TestTrivyAssetNames:
    """`goreleaser.yml` do Trivy: SO em CamelCase, arquitetura como
    `64bit`/`ARM64`, separados por `-`. Windows não é caso especial no
    template, então sai como `.Os` cru, minúsculo."""

    @pytest.mark.parametrize(
        ("os_", "arch", "expected"),
        [
            (OS.LINUX, Arch.AMD64, "trivy_0.58.1_Linux-64bit.tar.gz"),
            (OS.LINUX, Arch.ARM64, "trivy_0.58.1_Linux-ARM64.tar.gz"),
            (OS.WINDOWS, Arch.AMD64, "trivy_0.58.1_windows-64bit.zip"),
            (OS.MACOS, Arch.AMD64, "trivy_0.58.1_macOS-64bit.tar.gz"),
            (OS.MACOS, Arch.ARM64, "trivy_0.58.1_macOS-ARM64.tar.gz"),
        ],
    )
    def test_archive_names(self, os_, arch, expected):
        asset = TRIVY.asset_for("0.58.1", os_, arch)
        assert asset is not None
        assert asset.archive_name == expected
        assert asset.archive_url.endswith(f"/releases/download/v0.58.1/{expected}")

    def test_the_checksum_file_uses_underscores_whatever_the_archive_does(self):
        asset = TRIVY.asset_for("0.58.1", OS.LINUX, Arch.AMD64)
        assert asset is not None
        assert asset.checksums_url.endswith("/trivy_0.58.1_checksums.txt")


class TestGrypeAssetNames:
    """O Grype não declara `name_template`, então vale o default do
    goreleaser: tudo minúsculo, separado por `_`."""

    @pytest.mark.parametrize(
        ("os_", "arch", "expected"),
        [
            (OS.LINUX, Arch.AMD64, "grype_0.87.0_linux_amd64.tar.gz"),
            (OS.LINUX, Arch.ARM64, "grype_0.87.0_linux_arm64.tar.gz"),
            (OS.WINDOWS, Arch.AMD64, "grype_0.87.0_windows_amd64.zip"),
            (OS.MACOS, Arch.ARM64, "grype_0.87.0_darwin_arm64.tar.gz"),
        ],
    )
    def test_archive_names(self, os_, arch, expected):
        asset = GRYPE.asset_for("0.87.0", os_, arch)
        assert asset is not None
        assert asset.archive_name == expected

    def test_the_checksum_file(self):
        asset = GRYPE.asset_for("0.87.0", OS.LINUX, Arch.AMD64)
        assert asset is not None
        assert asset.checksums_url.endswith("/grype_0.87.0_checksums.txt")


class TestAssetShape:
    @pytest.mark.parametrize("spec", INSTALLABLE)
    def test_windows_gets_a_zip_and_an_exe(self, spec):
        asset = spec.asset_for("1.0.0", OS.WINDOWS, Arch.AMD64)
        assert asset is not None
        assert asset.archive_name.endswith(".zip")
        assert asset.binary_name == f"{spec.name}.exe"

    @pytest.mark.parametrize("spec", INSTALLABLE)
    def test_linux_gets_a_tarball_and_a_bare_binary(self, spec):
        asset = spec.asset_for("1.0.0", OS.LINUX, Arch.AMD64)
        assert asset is not None
        assert asset.archive_name.endswith(".tar.gz")
        assert asset.binary_name == spec.name

    @pytest.mark.parametrize("spec", INSTALLABLE)
    def test_a_leading_v_on_the_version_is_tolerated(self, spec):
        """As tags são `v0.58.1`, os arquivos dentro do release não."""
        with_v = spec.asset_for("v0.58.1", OS.LINUX, Arch.AMD64)
        without = spec.asset_for("0.58.1", OS.LINUX, Arch.AMD64)
        assert with_v == without

    @pytest.mark.parametrize("spec", INSTALLABLE)
    def test_an_empty_version_yields_nothing(self, spec):
        assert spec.asset_for("", OS.LINUX, Arch.AMD64) is None
        assert spec.asset_for("v", OS.LINUX, Arch.AMD64) is None

    @pytest.mark.parametrize("spec", INSTALLABLE)
    def test_every_url_points_at_the_project_repository(self, spec):
        """Nunca um mirror de terceiro: os binários vêm do release do
        próprio projeto, e é isso que o usuário confirma antes de baixar."""
        asset = spec.asset_for("1.0.0", OS.LINUX, Arch.AMD64)
        assert asset is not None
        for url in (asset.archive_url, asset.checksums_url, asset.release_url):
            assert url.startswith(f"https://github.com/{spec.owner}/{spec.repo}/")

    def test_an_unsupported_platform_yields_nothing(self):
        from dataclasses import replace

        narrow = replace(TRIVY, supported=frozenset({(OS.LINUX, Arch.AMD64)}))
        assert narrow.asset_for("1.0.0", OS.WINDOWS, Arch.AMD64) is None
        assert narrow.supports(OS.LINUX, Arch.AMD64) is True
