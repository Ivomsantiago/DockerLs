"""Ler os FROM, comparar com o registry, e reescrever sem estragar a linha.

O caso que este módulo existe para pegar é o que não avisa ninguém: uma base
fixada num digest que a tag não aponta mais. Foi assim que uma base de meados
de 2024 continuou sendo construída neste projeto por meses, carregando duas
CVEs CRITICAL do `libexpat1` que já tinham correção publicada. O Dockerfile
estava "corretamente" fixado o tempo todo.
"""

from __future__ import annotations

from dockerls.domain.value_objects.base_upgrade import (
    BaseStatus,
    classify,
    parse_bases,
    rewrite,
)

_ANTIGO = "sha256:" + "a" * 64
_ATUAL = "sha256:" + "b" * 64


class TestParsing:
    def test_stage_names_and_line_numbers_are_kept(self):
        bases = parse_bases("FROM node:22 AS builder\nRUN x\nFROM alpine:3.20\n")
        assert [(b.line, b.name, b.tag, b.stage) for b in bases] == [
            (1, "node", "22", "builder"),
            (3, "alpine", "3.20", ""),
        ]

    def test_platform_flags_do_not_confuse_the_reference(self):
        bases = parse_bases("FROM --platform=linux/amd64 node:22 AS b\n")
        assert bases[0].name == "node"
        assert bases[0].stage == "b"

    def test_a_port_in_the_host_is_not_read_as_a_tag(self):
        bases = parse_bases("FROM registry.interna:5000/time/app:1.2\n")
        assert bases[0].name == "registry.interna:5000/time/app"
        assert bases[0].tag == "1.2"

    def test_arg_digests_are_resolved_for_comparison(self):
        content = f"ARG D={_ANTIGO}\nFROM python:3.12@${{D}}\n"
        base = parse_bases(content)[0]
        assert base.digest == _ANTIGO
        assert base.digest_arg == "D"
        assert base.digest_arg_line == 1
        assert base.templated is True

    def test_a_digest_only_reference_has_no_tag(self):
        bases = parse_bases(f"FROM python@{_ANTIGO}\n")
        assert bases[0].name == "python"
        assert bases[0].tag == ""
        assert bases[0].digest == _ANTIGO


class TestClassification:
    def _base(self, content: str):
        return parse_bases(content)[0]

    def test_a_matching_digest_is_current(self):
        finding = classify(self._base(f"FROM node:22@{_ATUAL}\n"), _ATUAL)
        assert finding.status is BaseStatus.PINNED_CURRENT
        assert finding.proposed_reference == ""
        assert finding.status.needs_action is False

    def test_a_digest_the_tag_left_behind_is_stale(self):
        finding = classify(self._base(f"FROM node:22@{_ANTIGO}\n"), _ATUAL)
        assert finding.status is BaseStatus.PINNED_STALE
        assert finding.proposed_reference == f"node:22@{_ATUAL}"
        assert "republished" in finding.explain()

    def test_a_bare_tag_is_unpinned(self):
        finding = classify(self._base("FROM node:22\n"), _ATUAL)
        assert finding.status is BaseStatus.UNPINNED
        assert finding.proposed_reference == f"node:22@{_ATUAL}"

    def test_a_silent_registry_is_unresolved_never_current(self):
        # Ausência de resposta não vira confirmação: é o mesmo princípio que
        # rege o scan que não completou.
        finding = classify(self._base(f"FROM node:22@{_ANTIGO}\n"), "")
        assert finding.status is BaseStatus.UNRESOLVED
        assert finding.status.needs_action is False
        assert finding.proposed_reference == ""

    def test_an_untagged_reference_proposes_latest(self):
        finding = classify(self._base("FROM node\n"), _ATUAL)
        assert finding.proposed_reference == f"node:latest@{_ATUAL}"


class TestRewrite:
    def test_the_rest_of_the_line_survives(self):
        content = "FROM --platform=$BUILDPLATFORM node:22 AS builder  # comentário\n"
        findings = [classify(b, _ATUAL) for b in parse_bases(content)]
        updated, applied = rewrite(content, findings)
        assert applied == 1
        assert updated == (
            f"FROM --platform=$BUILDPLATFORM node:22@{_ATUAL} AS builder  # comentário\n"
        )

    def test_an_arg_digest_is_updated_at_the_arg_line(self):
        # O digest mora no ARG; escrever no FROM quebraria o contrato do
        # arquivo em vez de atualizá-lo.
        content = f"ARG D={_ANTIGO}\nFROM python:3.12@${{D}} AS a\nFROM python:3.12@${{D}}\n"
        findings = [classify(b, _ATUAL) for b in parse_bases(content)]
        updated, applied = rewrite(content, findings)
        assert applied == 1
        assert updated.splitlines()[0] == f"ARG D={_ATUAL}"
        assert "${D}" in updated

    def test_a_templated_reference_without_an_arg_is_left_alone(self):
        content = "FROM python:3.12@${VINDO_DE_FORA}\n"
        findings = [classify(b, _ATUAL) for b in parse_bases(content)]
        updated, applied = rewrite(content, findings)
        assert applied == 0
        assert updated == content

    def test_nothing_to_do_returns_the_original_text(self):
        content = f"FROM node:22@{_ATUAL}\n"
        findings = [classify(b, _ATUAL) for b in parse_bases(content)]
        updated, applied = rewrite(content, findings)
        assert applied == 0
        assert updated == content

    def test_line_endings_are_preserved(self):
        content = "FROM node:22 AS b\r\nRUN x\r\n"
        findings = [classify(b, _ATUAL) for b in parse_bases(content)]
        updated, _ = rewrite(content, findings)
        assert updated.endswith("RUN x\r\n")
        assert "\r\n" in updated.splitlines(keepends=True)[0]
