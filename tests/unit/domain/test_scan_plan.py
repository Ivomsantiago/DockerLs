"""Guard: cortar scans não pode virar esconder tags.

`plan_scans` decide o que este run mede. É a única função do projeto que
remove candidatas *sem medi-las*, então o que ela precisa provar não é que
escolhe bem -- é que nada some sem ser nomeado, e que nenhuma tag adiada é
tratada como uma tag pior.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.scan_plan import (
    DEFAULT_SCAN_BUDGET,
    DeferralReason,
    plan_scans,
)


def image(tag: str, *, official: bool = True, days_old: int = 0) -> DockerImage:
    return DockerImage(
        name="node",
        tag=tag,
        is_official=official,
        last_updated=datetime.now(tz=UTC) - timedelta(days=days_old),
    )


class TestNothingVanishes:
    def test_every_discovered_tag_is_either_measured_or_named(self):
        """A invariante que sustenta o corte inteiro."""
        tags = [image(f"22.{i}-alpine") for i in range(60)]
        plan = plan_scans(tags, budget=10)

        accounted = {i.full_reference for i in plan.selected}
        accounted |= {d.reference for d in plan.deferred}
        assert accounted == {t.full_reference for t in tags}
        assert len(plan.selected) + plan.deferred_count == len(tags)
        assert plan.discovered == len(tags)

    def test_every_deferral_carries_a_reason_and_a_sentence(self):
        tags = [image(f"22.{i}-alpine") for i in range(40)]
        plan = plan_scans(tags, budget=5)

        assert plan.deferred
        for item in plan.deferred:
            assert item.reason in DeferralReason
            assert item.detail.strip()

    def test_no_deferral_says_the_image_is_worse(self):
        """Uma tag adiada nunca foi medida, então nada pode ser afirmado
        sobre ela. O texto tem de falar de seleção, não de segurança."""
        tags = [image(f"22.{i}-alpine") for i in range(40)]
        plan = plan_scans(tags, budget=5)

        forbidden = ("vulnerab", "insecure", "unsafe", "worse", "risk", "cve")
        for item in plan.deferred:
            assert not any(word in item.detail.lower() for word in forbidden), item.detail


class TestSupersededWithinALine:
    def test_an_older_patch_of_the_same_line_is_deferred(self):
        tags = [image("22.13-alpine"), image("22.14-alpine")]
        plan = plan_scans(tags, budget=1)

        assert [i.tag for i in plan.selected] == ["22.14-alpine"]
        assert plan.deferred[0].reason is DeferralReason.SUPERSEDED
        assert "22.14-alpine" in plan.deferred[0].detail

    def test_different_majors_are_different_answers_and_both_survive(self):
        """`node:20-alpine` continua sendo resposta legítima ao lado de
        `node:22-alpine`, e frequentemente é a certa (LTS)."""
        tags = [image("20-alpine"), image("22-alpine")]
        plan = plan_scans(tags, budget=2)

        assert {i.tag for i in plan.selected} == {"20-alpine", "22-alpine"}
        assert plan.deferred == []

    def test_different_variants_are_different_answers(self):
        tags = [image("22.14-alpine"), image("22.14-bookworm-slim"), image("22.13-alpine")]
        plan = plan_scans(tags, budget=2)

        assert {i.tag for i in plan.selected} == {"22.14-alpine", "22.14-bookworm-slim"}

    def test_a_moving_alias_is_not_collapsed_into_a_pinned_patch(self):
        """`22-alpine` acompanha a linha e `22.14-alpine` fixa o patch. São
        perguntas diferentes, e escolher entre elas é do usuário."""
        tags = [image("22-alpine"), image("22.14-alpine")]
        plan = plan_scans(tags, budget=2)

        assert {i.tag for i in plan.selected} == {"22-alpine", "22.14-alpine"}
        assert plan.deferred == []

    def test_a_tag_without_a_version_is_never_deferred_as_superseded(self):
        """Não há como ordenar o que não tem número, então `latest` e
        `lts-alpine` nunca perdem para uma versão."""
        tags = [image("latest"), image("lts-alpine"), image("22.14-alpine")]
        plan = plan_scans(tags, budget=3)

        assert {i.tag for i in plan.selected} == {"latest", "lts-alpine", "22.14-alpine"}

    def test_a_pinned_patch_beats_an_older_pinned_patch_across_precisions(self):
        tags = [image("22.14.0-alpine"), image("22.13.5-alpine"), image("22.14-alpine")]
        plan = plan_scans(tags, budget=2)

        tags_kept = {i.tag for i in plan.selected}
        assert "22.14.0-alpine" in tags_kept  # o mais novo de 3 componentes
        assert "22.14-alpine" in tags_kept  # precisão diferente, pergunta diferente
        assert "22.13.5-alpine" not in tags_kept


class TestTheBudget:
    def test_a_budget_of_zero_measures_everything(self):
        """O comportamento anterior continua disponível, e por
        configuração: quem precisa da varredura completa não perdeu nada."""
        tags = [image(f"22.{i}-alpine") for i in range(50)]
        plan = plan_scans(tags, budget=0)

        assert len(plan.selected) == 50
        assert plan.deferred == []

    def test_a_negative_budget_is_treated_as_no_budget(self):
        tags = [image(f"22.{i}-alpine") for i in range(5)]
        assert len(plan_scans(tags, budget=-1).selected) == 5

    def test_within_budget_nothing_is_pruned_at_all(self):
        """O orçamento é a única coisa que remove tag. Havendo folga, medir
        mais é estritamente mais informação -- inclusive um patch antigo,
        que ninguém pediu para esconder."""
        tags = [image("22.13-alpine"), image("22.14-alpine")]
        plan = plan_scans(tags, budget=25)

        assert len(plan.selected) == 2
        assert plan.deferred == []

    def test_fewer_tags_than_budget_costs_nothing(self):
        tags = [image("22-alpine"), image("20-alpine")]
        plan = plan_scans(tags, budget=DEFAULT_SCAN_BUDGET)

        assert len(plan.selected) == 2
        assert plan.deferred == []

    def test_the_budget_is_a_ceiling_the_plan_never_exceeds(self):
        # Cinquenta linhas distintas: a regra de sucessão não corta nenhuma,
        # então o orçamento é a única coisa entre 50 tags e 8 scans.
        tags = [image(f"{major}-alpine") for major in range(50)]
        plan = plan_scans(tags, budget=8)

        assert len(plan.selected) == 8
        assert all(d.reason is DeferralReason.OVER_BUDGET for d in plan.deferred)

    def test_official_images_are_spent_on_first(self):
        tags = [image(f"{i}-community", official=False) for i in range(20)]
        tags += [image("99-official", official=True)]
        plan = plan_scans(tags, budget=1)

        assert [i.tag for i in plan.selected] == ["99-official"]

    def test_the_most_recently_published_wins_among_equals(self):
        tags = [
            image("1-alpine", days_old=400),
            image("2-alpine", days_old=1),
            image("3-alpine", days_old=200),
        ]
        plan = plan_scans(tags, budget=1)

        assert [i.tag for i in plan.selected] == ["2-alpine"]

    def test_the_same_input_always_produces_the_same_plan(self):
        """Dois runs sobre os mesmos dados têm de medir as mesmas tags, ou
        o resultado passa a depender da ordem de um dicionário."""
        tags = [image(f"{i}-alpine", days_old=0) for i in range(30)]
        first = [i.full_reference for i in plan_scans(tags, budget=7).selected]
        for _ in range(10):
            assert [i.full_reference for i in plan_scans(tags, budget=7).selected] == first


class TestOrder:
    def test_the_selection_keeps_discovery_order(self):
        """O ranqueamento por segurança acontece depois, sobre medições.
        Reordenar aqui embaralharia a entrada de uma decisão que nada tem
        a ver com esta."""
        tags = [image("9-alpine"), image("1-alpine"), image("5-alpine")]
        plan = plan_scans(tags, budget=3)

        assert [i.tag for i in plan.selected] == ["9-alpine", "1-alpine", "5-alpine"]


class TestEdges:
    def test_no_tags_is_an_empty_plan_and_not_a_crash(self):
        plan = plan_scans([], budget=25)
        assert plan.selected == []
        assert plan.deferred == []
        assert plan.discovered == 0

    def test_a_v_prefix_is_understood(self):
        tags = [image("v1.2-alpine"), image("v1.3-alpine")]
        plan = plan_scans(tags, budget=1)
        assert [i.tag for i in plan.selected] == ["v1.3-alpine"]

    def test_a_bare_version_with_no_variant_still_forms_a_line(self):
        tags = [image("22.13"), image("22.14")]
        plan = plan_scans(tags, budget=1)
        assert [i.tag for i in plan.selected] == ["22.14"]

    def test_numeric_ordering_is_numeric_and_not_lexicographic(self):
        """`22.9` depois de `22.10` é o erro clássico de comparar strings."""
        tags = [image("22.9-alpine"), image("22.10-alpine")]
        plan = plan_scans(tags, budget=1)
        assert [i.tag for i in plan.selected] == ["22.10-alpine"]
