"""`doctor --install`: consentimento primeiro, e nada instalado nos testes.

Rede e subprocess são mockados sem exceção -- nenhum teste aqui baixa ou
instala coisa alguma. O que está sob teste é o contrato do comando: o
diagnóstico continua read-only por padrão, a instalação exige consentimento
explícito, e uma ferramenta que falha não impede a outra de ser tentada.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.cli.commands import doctor as doctor_cmd
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.infrastructure.toolchain.installer import InstallError, InstallOutcome

runner = CliRunner()


@pytest.fixture
def nothing_installed(monkeypatch):
    """Nem Trivy nem Grype no PATH, e nenhum cosign."""
    monkeypatch.setattr(doctor_cmd.shutil, "which", lambda name: None)


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(doctor_cmd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(doctor_cmd.platform, "machine", lambda: "x86_64")


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(doctor_cmd.platform, "system", lambda: "Windows")
    monkeypatch.setattr(doctor_cmd.platform, "machine", lambda: "AMD64")


def _installer(*, version: str = "0.58.1", outcomes: dict[str, InstallOutcome] | None = None):
    """Um ToolInstaller falso: nada de rede, nada de disco."""
    installer = AsyncMock()
    installer.latest_version = AsyncMock(return_value=version)

    async def install(plan, *, cosign=None):
        if outcomes and plan.tool in outcomes:
            return outcomes[plan.tool]
        return InstallOutcome(
            plan.tool,
            installed=True,
            detail="verified sha256",
            path=plan.destination / plan.tool,
        )

    installer.install = install
    return installer


def _run(args: list[str], installer=None, tty: bool = False):
    installer = installer or _installer()
    with (
        patch.object(doctor_cmd, "ToolInstaller", return_value=installer),
        patch.object(doctor_cmd.sys.stdin, "isatty", return_value=tty),
        # O diagnóstico final não deve inventar disponibilidade.
        patch.object(doctor_cmd, "_doctor", AsyncMock(return_value=EXIT_OK)),
    ):
        return runner.invoke(app, ["doctor", *args])


class TestDiagnosisStaysReadOnly:
    def test_doctor_without_flags_never_builds_an_installer(self, nothing_installed, linux):
        """O comportamento default não pode mudar: `doctor` diagnostica."""
        with patch.object(doctor_cmd, "ToolInstaller") as installer:
            runner.invoke(app, ["doctor"])
        installer.assert_not_called()

    def test_the_help_names_every_source_it_downloads_from(self):
        """Transparência total: nada de instalação mágica escondida."""
        result = runner.invoke(app, ["doctor", "--help"])
        collapsed = " ".join(result.output.split())

        assert "github.com/aquasecurity/trivy/releases" in collapsed
        assert "github.com/anchore/grype/releases" in collapsed
        assert "SHA-256" in collapsed


class TestConsent:
    def test_a_non_interactive_terminal_refuses_without_yes(self, nothing_installed, linux):
        """O caso do pipeline: sem TTY e sem --yes, a resposta é não."""
        result = _run(["--install"], tty=False)

        assert result.exit_code == EXIT_ERROR
        assert "Nothing was installed" in result.output
        assert "--yes" in result.output

    def test_declining_the_prompt_installs_nothing(self, nothing_installed, linux):
        with patch.object(doctor_cmd.typer, "confirm", return_value=False):
            result = _run(["--install"], tty=True)

        assert result.exit_code == EXIT_ERROR
        assert "Nothing was installed" in result.output

    def test_the_urls_are_printed_before_any_download(self, nothing_installed, linux):
        """Consentimento só é informado se a pessoa vê a URL antes."""
        result = _run(["--install"], tty=False)
        collapsed = " ".join(result.output.split())

        assert "trivy_0.58.1_Linux-64bit.tar.gz" in collapsed
        assert "trivy_0.58.1_checksums.txt" in collapsed
        assert "grype_0.58.1_linux_amd64.tar.gz" in collapsed
        # E a promessa que o caminho cumpre.
        assert "No install script is fetched or run" in collapsed

    def test_yes_skips_the_prompt(self, nothing_installed, linux):
        with patch.object(doctor_cmd.typer, "confirm") as confirm:
            _run(["--install", "--yes"], tty=False)
        confirm.assert_not_called()

    def test_privilege_is_announced_in_the_confirmation(self, nothing_installed, linux):
        """Nunca pedir sudo de surpresa no meio da execução."""
        with patch.object(doctor_cmd, "_writable_without_privilege", return_value=False):
            result = _run(["--install"], tty=False)

        assert "elevated privileges" in " ".join(result.output.split())


class TestPlatformDetection:
    def test_linux_picks_the_linux_assets(self, nothing_installed, linux):
        result = _run(["--install", "--yes"])
        collapsed = " ".join(result.output.split())

        assert "Linux-64bit.tar.gz" in collapsed
        assert "linux_amd64.tar.gz" in collapsed

    def test_windows_picks_the_windows_assets(self, nothing_installed, windows):
        result = _run(["--install", "--yes"])
        collapsed = " ".join(result.output.split())

        assert "windows-64bit.zip" in collapsed
        assert "windows_amd64.zip" in collapsed

    def test_an_unsupported_platform_fails_with_a_message(self, nothing_installed, monkeypatch):
        """Falhar claro em vez de tentar algo genérico e quebrar."""
        monkeypatch.setattr(doctor_cmd.platform, "system", lambda: "SunOS")
        monkeypatch.setattr(doctor_cmd.platform, "machine", lambda: "sparc")

        result = _run(["--install", "--yes"])

        assert result.exit_code == EXIT_ERROR
        assert "Unsupported platform" in result.output

    def test_the_windows_default_directory_needs_no_privilege(self, monkeypatch):
        monkeypatch.setattr(doctor_cmd.platform, "system", lambda: "Windows")
        monkeypatch.setenv("LOCALAPPDATA", r"C:\\Users\\someone\\AppData\\Local")

        assert "AppData" in str(doctor_cmd.default_install_dir())

    def test_the_posix_default_directory_is_under_home(self, monkeypatch):
        monkeypatch.setattr(doctor_cmd.platform, "system", lambda: "Linux")
        assert doctor_cmd.default_install_dir() == Path.home() / ".local" / "bin"


class TestOneFailureDoesNotStopTheOther:
    def test_a_failed_install_does_not_prevent_the_next(self, nothing_installed, linux):
        installer = _installer(
            outcomes={"trivy": InstallOutcome("trivy", installed=False, detail="checksum mismatch")}
        )
        result = _run(["--install", "--yes"], installer=installer)
        collapsed = " ".join(result.output.split())

        assert "FAILED checksum mismatch" in collapsed
        # E o grype seguiu sendo instalado.
        assert "OK verified sha256" in collapsed

    def test_a_version_lookup_failure_falls_back_to_the_built_in_default(
        self, nothing_installed, linux
    ):
        """`releases/latest` failing (a 403 from a restrictive proxy, say) no
        longer drops the tool: it installs the hardcoded default version
        instead, and says so, rather than leaving CI onboarding stuck."""
        installer = _installer()
        calls: list[str] = []

        async def latest(spec):
            calls.append(spec.name)
            if spec.name == "trivy":
                raise InstallError("release feed unreachable")
            return "0.87.0"

        installer.latest_version = latest
        result = _run(["--install", "--yes"], installer=installer)
        collapsed = " ".join(result.output.split())

        assert calls == ["trivy", "grype"]
        assert "release feed unreachable" in collapsed
        assert "Falling back to the built-in default version" in collapsed
        assert "grype_0.87.0_linux_amd64.tar.gz" in collapsed
        assert "trivy_0.58.1_Linux-64bit.tar.gz" in collapsed

    def test_every_tool_failing_the_latest_lookup_still_installs_via_fallback(
        self, nothing_installed, linux
    ):
        installer = _installer()

        async def latest(spec):
            raise InstallError("nope")

        installer.latest_version = latest
        result = _run(["--install", "--yes"], installer=installer)

        assert result.exit_code == EXIT_OK
        assert "Falling back to the built-in default version" in " ".join(result.output.split())

    def test_an_explicit_version_skips_the_latest_lookup_entirely(self, nothing_installed, linux):
        installer = _installer()

        async def latest(spec):  # pragma: no cover - must never be called
            raise AssertionError("releases/latest must not be queried when a version is pinned")

        installer.latest_version = latest
        result = _run(
            ["--install", "--yes", "--trivy-version", "0.60.0", "--grype-version", "0.90.0"],
            installer=installer,
        )
        collapsed = " ".join(result.output.split())

        assert result.exit_code == EXIT_OK
        assert "trivy_0.60.0_Linux-64bit.tar.gz" in collapsed
        assert "grype_0.90.0_linux_amd64.tar.gz" in collapsed


class TestFinalDiagnosisReflectsReality:
    def test_the_diagnosis_runs_again_after_installing(self, nothing_installed, linux):
        """Dizer "instalado" sem reconferir seria reportar a intenção em vez
        do resultado."""
        installer = _installer()
        with (
            patch.object(doctor_cmd, "ToolInstaller", return_value=installer),
            patch.object(doctor_cmd.sys.stdin, "isatty", return_value=False),
            patch.object(doctor_cmd, "_doctor", AsyncMock(return_value=EXIT_ERROR)) as diagnosis,
        ):
            result = runner.invoke(app, ["doctor", "--install", "--yes"])

        diagnosis.assert_awaited_once()
        # O código de saída é o do diagnóstico real, não o da instalação.
        assert result.exit_code == EXIT_ERROR

    def test_nothing_to_install_says_so_and_exits_ok(self, linux, monkeypatch):
        monkeypatch.setattr(doctor_cmd.shutil, "which", lambda name: f"/usr/bin/{name}")
        result = _run(["--install", "--yes"])

        assert result.exit_code == EXIT_OK
        assert "Nothing to install" in result.output

    def test_a_destination_outside_path_is_flagged(self, nothing_installed, linux, monkeypatch):
        """Instalar fora do PATH deixa a ferramenta invisível, e o
        diagnóstico abaixo diria "Not found" sem explicar por quê."""
        monkeypatch.setenv("PATH", "/usr/bin")
        result = _run(["--install", "--yes", "--install-dir", "/opt/dockerls/bin"])

        assert "is not on your PATH" in " ".join(result.output.split())
