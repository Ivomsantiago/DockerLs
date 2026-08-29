"""Carregar `.dockerls-policy.yaml` -- e recusar o que não se entende.

A diferença de comportamento entre este arquivo e o `.dockerls-ignore.yaml` é
a direção da falha. Uma regra de ignore que não carrega deixa de esconder uma
CVE: mais alarme, e alarme a mais é seguro. Uma regra de política que não
carrega deixa de exigir alguma coisa, e o build passa parecendo ter sido
conferido.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dockerls.infrastructure.config.policy_file import (
    DEFAULT_POLICY_FILENAME,
    PolicyFileError,
    find_policy_file,
    load_policy,
)

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, content: str) -> Path:
    destination = tmp_path / DEFAULT_POLICY_FILENAME
    destination.write_text(content, encoding="utf-8")
    return destination


class TestLoading:
    def test_politica_completa_carrega(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """
fail_on: high
require_scan: true
require_pinned_bases: true
require_nonroot: true
require_provenance: true
required_labels:
  - org.opencontainers.image.source
allowed_base_registries:
  - docker.io
  - cgr.dev
max_vulnerabilities:
  critical: 0
  high: 5
""",
        )

        policy = load_policy(path)

        assert policy.fail_on == "high"
        assert policy.require_scan
        assert policy.required_labels == ("org.opencontainers.image.source",)
        assert policy.allowed_base_registries == ("docker.io", "cgr.dev")
        assert policy.max_vulnerabilities == {"critical": 0, "high": 5}

    def test_arquivo_ausente_nao_e_encontrado(self, tmp_path: Path) -> None:
        assert find_policy_file(tmp_path) is None

    def test_arquivo_presente_e_encontrado(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "require_scan: true\n")
        assert find_policy_file(tmp_path) == path


class TestRefusals:
    def test_chave_desconhecida_e_erro_e_nao_politica_vazia(self, tmp_path: Path) -> None:
        """`require_non_root` em vez de `require_nonroot` viraria um portão
        aberto com cara de fechado."""
        path = _write(tmp_path, "require_non_root: true\n")

        with pytest.raises(PolicyFileError, match="desconhecida"):
            load_policy(path)

    def test_arquivo_vazio_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "\n")
        with pytest.raises(PolicyFileError, match="vazio"):
            load_policy(path)

    def test_arquivo_sem_nenhuma_regra_e_erro(self, tmp_path: Path) -> None:
        """Um arquivo presente que não exige nada é indistinguível de um
        portão desligado."""
        path = _write(tmp_path, "require_scan: false\n")
        with pytest.raises(PolicyFileError, match="no rule was declared"):
            load_policy(path)

    def test_documento_que_nao_e_mapa_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "- require_scan\n")
        with pytest.raises(PolicyFileError, match="must be a map of rules"):
            load_policy(path)

    def test_yaml_quebrado_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "require_scan: [true\n")
        with pytest.raises(PolicyFileError):
            load_policy(path)

    def test_flag_com_tipo_errado_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "require_scan: sim\n")
        with pytest.raises(PolicyFileError, match="must be true or false"):
            load_policy(path)

    def test_severidade_inexistente_em_fail_on_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "fail_on: catastrofica\n")
        with pytest.raises(PolicyFileError, match="fail_on"):
            load_policy(path)

    def test_severidade_inexistente_em_teto_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "max_vulnerabilities:\n  urgente: 3\n")
        with pytest.raises(PolicyFileError, match="unknown severity"):
            load_policy(path)

    def test_teto_booleano_nao_vira_um(self, tmp_path: Path) -> None:
        """`bool` é subclasse de `int`: `high: true` passaria como teto de 1,
        que não é o que ninguém quis dizer."""
        path = _write(tmp_path, "max_vulnerabilities:\n  high: true\n")
        with pytest.raises(PolicyFileError, match="must be an integer"):
            load_policy(path)

    def test_teto_negativo_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "max_vulnerabilities:\n  high: -1\n")
        with pytest.raises(PolicyFileError, match="must be an integer"):
            load_policy(path)

    def test_lista_com_item_nao_texto_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "required_labels:\n  - 7\n")
        with pytest.raises(PolicyFileError, match="must be a list of strings"):
            load_policy(path)

    def test_lista_so_com_espacos_e_erro(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'required_labels:\n  - "   "\n')
        with pytest.raises(PolicyFileError, match="no usable value"):
            load_policy(path)

    def test_documento_com_tag_python_e_recusado(self, tmp_path: Path) -> None:
        """Um arquivo de política pode vir de um repositório que não é seu."""
        path = _write(tmp_path, "require_scan: !!python/object/apply:os.system ['id']\n")
        with pytest.raises(PolicyFileError):
            load_policy(path)


class TestGateThreshold:
    def test_unknown_e_recusado_como_fail_on(self, tmp_path: Path) -> None:
        """É severidade válida numa contagem e não é limiar válido: o portão
        não sabe avaliá-lo."""
        path = _write(tmp_path, "fail_on: unknown\n")

        with pytest.raises(PolicyFileError, match="fail_on"):
            load_policy(path)

    def test_unknown_continua_valendo_como_teto(self, tmp_path: Path) -> None:
        """Um scanner que reporta um achado sem severidade ainda reportou um
        achado."""
        path = _write(tmp_path, "max_vulnerabilities:\n  unknown: 0\n")

        assert load_policy(path).max_vulnerabilities == {"unknown": 0}
