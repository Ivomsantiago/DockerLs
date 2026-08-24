"""O retrato agregado da frota, e o que ele se recusa a afirmar."""

from __future__ import annotations

from dockerls.domain.value_objects.build_policy import BuildPolicy, PolicyRule, PolicyViolation
from dockerls.domain.value_objects.fleet import FleetEntry, FleetReport
from dockerls.domain.value_objects.tristate import Tristate


def _entry(path: str, **kwargs: object) -> FleetEntry:
    return FleetEntry(path=path, **kwargs)  # type: ignore[arg-type]


def _violation(n: int = 1) -> tuple[PolicyViolation, ...]:
    return tuple(
        PolicyViolation(rule=PolicyRule.REQUIRE_NONROOT, message=f"m{i}") for i in range(n)
    )


class TestCounts:
    def test_root_e_indeterminado_sao_contados_separados(self) -> None:
        """Juntá-los transformaria ausência de medida em acusação, e a fila de
        trabalho de cada um é diferente."""
        report = FleetReport(
            root=".",
            entries=(
                _entry("a", nonroot=Tristate.FALSE),
                _entry("b", nonroot=Tristate.UNKNOWN),
                _entry("c", nonroot=Tristate.TRUE),
            ),
        )

        assert report.running_as_root == 1
        assert report.undetermined_user == 1

    def test_ilegivel_nao_conta_como_conforme(self) -> None:
        report = FleetReport(root=".", entries=(_entry("a", error="permissão negada"),))

        assert report.total == 1
        assert report.fully_pinned == 0
        assert len(report.unreadable) == 1

    def test_base_parcialmente_fixada_nao_conta_como_fixada(self) -> None:
        report = FleetReport(root=".", entries=(_entry("a", pinned_bases=1, total_bases=2),))
        assert report.fully_pinned == 0

    def test_sem_nenhuma_base_nao_conta_como_fixada(self) -> None:
        """Zero de zero não é "tudo fixado": é nada lido."""
        assert FleetReport(root=".", entries=(_entry("a"),)).fully_pinned == 0


class TestQueue:
    def test_mais_violacoes_primeiro(self) -> None:
        report = FleetReport(
            root=".",
            entries=(
                _entry("a", violations=_violation(1)),
                _entry("b", violations=_violation(3)),
            ),
        )

        assert [e.path for e in report.worst_first()] == ["b", "a"]

    def test_empate_e_resolvido_pelo_caminho_para_a_ordem_ser_estavel(self) -> None:
        """Sem isso a mesma frota sairia em ordem diferente a cada varredura,
        e nenhum relatório seria comparável com o anterior."""
        report = FleetReport(
            root=".",
            entries=(
                _entry("z", violations=_violation(2)),
                _entry("a", violations=_violation(2)),
                _entry("m", violations=_violation(2)),
            ),
        )

        assert [e.path for e in report.worst_first()] == ["a", "m", "z"]


class TestHonesty:
    def test_o_relatorio_diz_o_que_nao_mediu(self) -> None:
        caveat = FleetReport(root=".").caveat()
        assert "builds no image and calls no scanner" in caveat

    def test_resumo_de_frota_vazia_nao_finge_sucesso(self) -> None:
        assert FleetReport(root=".").summary() == "no Dockerfile found"

    def test_truncamento_entra_no_documento(self) -> None:
        payload = FleetReport(root=".", truncated=True).to_dict()
        assert payload["truncated"] is True

    def test_ausencia_de_politica_fica_registrada(self) -> None:
        payload = FleetReport(root=".").to_dict()
        assert payload["policy_applied"] is False

    def test_diretorio_nao_percorrido_aparece(self) -> None:
        payload = FleetReport(root=".", unreadable_paths=("privado",)).to_dict()
        assert payload["unreadable_paths"] == ["privado"]


class TestStaticSubset:
    def test_regras_que_dependem_de_scan_ficam_de_fora(self) -> None:
        """Aplicá-las numa varredura produziria uma violação idêntica por
        arquivo, e uma lista toda vermelha não distingue nada."""
        completa = BuildPolicy(
            fail_on="high",
            max_vulnerabilities={"critical": 0},
            require_scan=True,
            require_provenance=True,
            require_pinned_bases=True,
            require_nonroot=True,
            required_labels=("owner",),
            allowed_base_registries=("docker.io",),
        )

        estatica = completa.static_subset()

        assert not estatica.fail_on
        assert not estatica.max_vulnerabilities
        assert not estatica.require_scan
        assert not estatica.require_provenance

    def test_regras_estaticas_sobrevivem(self) -> None:
        estatica = BuildPolicy(
            require_pinned_bases=True,
            require_nonroot=True,
            required_labels=("owner",),
            allowed_base_registries=("docker.io",),
        ).static_subset()

        assert estatica.require_pinned_bases
        assert estatica.require_nonroot
        assert estatica.required_labels == ("owner",)
        assert estatica.allowed_base_registries == ("docker.io",)
