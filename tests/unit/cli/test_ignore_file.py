from __future__ import annotations

from datetime import date, timedelta

from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules


class TestLoadIgnoreRules:
    def test_missing_file_returns_empty(self, tmp_path):
        rules = load_ignore_rules(tmp_path / "nope.yaml")
        assert rules == []

    def test_loads_valid_rules(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text("ignores:\n  - cve: CVE-2024-0001\n    justification: not reachable\n")
        rules = load_ignore_rules(f)
        assert len(rules) == 1
        assert rules[0].cve == "CVE-2024-0001"

    def test_expired_rule_is_dropped(self, tmp_path):
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(
            f"ignores:\n  - cve: CVE-2024-0002\n    justification: temp\n    expires: {yesterday}\n"
        )
        rules = load_ignore_rules(f)
        assert rules == []

    def test_future_expiry_kept(self, tmp_path):
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(f"ignores:\n  - cve: CVE-2024-0003\n    expires: {tomorrow}\n")
        rules = load_ignore_rules(f)
        assert len(rules) == 1

    def test_malformed_yaml_returns_empty(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text("ignores: [this is not: valid: yaml")
        assert load_ignore_rules(f) == []

    def test_active_ignored_cve_ids_normalizes_case(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text("ignores:\n  - cve: cve-2024-0004\n")
        rules = load_ignore_rules(f)
        assert active_ignored_cve_ids(rules) == {"CVE-2024-0004"}


class TestABlankExemptionCannotSilenceEveryUnnamedFinding:
    """As isencoes sao aplicadas com `vuln.cve_id.upper() not in ignored`, e
    um scanner deixa `cve_id` **vazio** quando o aviso nao tem identificador
    publicado -- o Trivy faz isso, como o exportador SARIF documenta.

    Uma linha `- cve: ""` no arquivo punha a string vazia no conjunto e
    apagava do relatorio todo achado sem identificador, e com ele do score,
    do tier e do veredito de producao. Vulnerabilidades reais somem e a
    imagem sobe de nota, sem nada na saida dizendo que foram removidas.
    """

    def test_a_blank_cve_is_rejected_rather_than_loaded(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text('ignores:\n  - cve: ""\n    justification: oops\n')

        assert load_ignore_rules(f) == []

    def test_a_whitespace_cve_is_rejected_too(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text('ignores:\n  - cve: "   "\n    justification: oops\n')

        assert load_ignore_rules(f) == []

    def test_a_blank_rule_never_reaches_the_applied_set(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text('ignores:\n  - cve: ""\n  - cve: CVE-2024-0009\n')

        assert active_ignored_cve_ids(load_ignore_rules(f)) == {"CVE-2024-0009"}

    def test_non_cve_advisory_identifiers_are_still_accepted(self, tmp_path):
        """A guarda recusa o que nao identifica nada, e nao tudo que nao
        comeca com `CVE-`: GHSA, DSA, RUSTSEC e ALAS sao legitimos."""
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(
            "ignores:\n"
            "  - cve: GHSA-xxxx-yyyy-zzzz\n"
            "  - cve: DSA-5555-1\n"
            "  - cve: RUSTSEC-2024-0001\n"
            "  - cve: ALAS2-2024-2500\n"
        )

        assert len(load_ignore_rules(f)) == 4
