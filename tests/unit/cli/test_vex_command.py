"""Guard: o comando `vex` na fronteira -- autoria, prazo e silêncio.

Três coisas que um documento VEX gerado errado faz de pior: afirmar sem
dizer quem afirma, ressuscitar uma isenção que expirou, e sair vazio sem
avisar que saiu vazio.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

IGNORES = """ignores:
  - cve: CVE-2024-1111
    justification: risk accepted by the platform team
    expires: 2099-01-01
  - cve: CVE-2024-2222
    justification: the vulnerable function is not compiled in
    vex_justification: vulnerable_code_not_present
  - cve: CVE-2023-0001
    justification: lapsed long ago
    expires: 2024-01-01
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / ".dockerls-ignore.yaml").write_text(IGNORES, encoding="utf-8")
    return tmp_path / ".dockerls-ignore.yaml"


class TestAuthorship:
    def test_a_document_with_no_author_is_refused(self, tmp_path):
        """Uma afirmação VEX é alguém afirmando alguma coisa. Sem autor ela
        não responsabiliza ninguém, e o consumidor não tem como decidir se
        confia."""
        result = runner.invoke(app, ["vex", "app:1", "--ignore-file", str(_project(tmp_path))])

        assert result.exit_code == EXIT_ERROR
        assert "--author is required" in result.output

    def test_whitespace_is_not_an_author(self, tmp_path):
        result = runner.invoke(
            app, ["vex", "app:1", "--author", "   ", "--ignore-file", str(_project(tmp_path))]
        )
        assert result.exit_code == EXIT_ERROR


class TestTranslation:
    def _run(self, tmp_path, *args):
        result = runner.invoke(
            app,
            [
                "vex",
                "ghcr.io/org/app:1.2.3",
                "--author",
                "Security <sec@example.com>",
                "--ignore-file",
                str(_project(tmp_path)),
                *args,
            ],
        )
        assert result.exit_code == 0, result.output
        return json.loads(result.stdout)

    def test_risk_acceptance_stays_affected(self, tmp_path):
        payload = self._run(tmp_path)
        accepted = next(
            s for s in payload["statements"] if s["vulnerability"]["name"] == "CVE-2024-1111"
        )

        assert accepted["status"] == "affected"
        assert "justification" not in accepted
        assert "risk accepted by the platform team" in accepted["action_statement"]

    def test_a_declared_justification_becomes_not_affected(self, tmp_path):
        payload = self._run(tmp_path)
        declared = next(
            s for s in payload["statements"] if s["vulnerability"]["name"] == "CVE-2024-2222"
        )

        assert declared["status"] == "not_affected"
        assert declared["justification"] == "vulnerable_code_not_present"

    def test_an_expired_exemption_is_not_resurrected(self, tmp_path):
        """O prazo é o ponto do prazo. Um documento que reafirma uma isenção
        vencida diz ao mundo inteiro que ela continua valendo."""
        payload = self._run(tmp_path)
        names = {s["vulnerability"]["name"] for s in payload["statements"]}

        assert "CVE-2023-0001" not in names

    def test_the_product_carries_the_image(self, tmp_path):
        payload = self._run(tmp_path)
        product = payload["statements"][0]["products"][0]["@id"]

        assert product.startswith("pkg:oci/app")
        assert "ghcr.io/org/app" in product

    def test_a_digest_reference_is_kept_as_a_digest(self, tmp_path):
        """Um digest aponta para bytes específicos, que é exatamente o que
        uma afirmação VEX deveria cobrir."""
        digest = "sha256:" + "a" * 64
        result = runner.invoke(
            app,
            [
                "vex",
                f"ghcr.io/org/app@{digest}",
                "--author",
                "Security",
                "--ignore-file",
                str(_project(tmp_path)),
            ],
        )
        payload = json.loads(result.stdout)

        assert digest in payload["statements"][0]["products"][0]["@id"]


class TestFileHandling:
    def test_it_writes_to_a_file_when_asked(self, tmp_path):
        destination = tmp_path / "vex.json"
        result = runner.invoke(
            app,
            [
                "vex",
                "app:1",
                "--author",
                "Security",
                "--ignore-file",
                str(_project(tmp_path)),
                "--output",
                str(destination),
            ],
        )

        assert result.exit_code == 0
        assert json.loads(destination.read_text(encoding="utf-8"))["statements"]

    def test_an_unwritable_output_path_is_an_error_not_a_traceback(self, tmp_path):
        """`Path(output).write_text(...)` used to run with no exception
        handling at all: a destination that can't be written (here, a
        directory where the command expects to create a file) raised an
        uncaught `OSError` straight out of the command."""
        destination = tmp_path / "not-a-file"
        destination.mkdir()
        result = runner.invoke(
            app,
            [
                "vex",
                "app:1",
                "--author",
                "Security",
                "--ignore-file",
                str(_project(tmp_path)),
                "--output",
                str(destination),
            ],
        )

        assert result.exit_code == EXIT_ERROR
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Error" in result.output

    def test_an_ignore_file_that_does_not_exist_is_an_error(self, tmp_path):
        """Cair no silêncio de "nenhuma regra" produziria um documento vazio
        que parece uma resposta."""
        result = runner.invoke(
            app,
            ["vex", "app:1", "--author", "Security", "--ignore-file", str(tmp_path / "absent")],
        )

        assert result.exit_code == EXIT_ERROR
        # Rich wraps long lines at the terminal width, and tmp_path's length
        # varies by test run/worker -- "does not exist" can itself be split
        # across the wrap. Collapse whitespace before asserting so this
        # isn't sensitive to where the wrap lands.
        assert "does not exist" in " ".join(result.output.split())

    def test_an_empty_document_says_it_is_empty(self, tmp_path):
        empty = tmp_path / ".dockerls-ignore.yaml"
        empty.write_text("ignores: []\n", encoding="utf-8")
        result = runner.invoke(
            app, ["vex", "app:1", "--author", "Security", "--ignore-file", str(empty)]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["statements"] == []
        assert "No active exemptions" in result.output
