"""O diff entre duas receitas de base: descreve as trocas, não elege vencedora."""

from __future__ import annotations

from dockerls.domain.value_objects.base_recipe import BaseRecipe, OsFamily, Runtime
from dockerls.domain.value_objects.recipe_diff import PackageDelta, compare


class TestPackages:
    def test_pacote_so_da_direita_aparece_como_adicionado_com_o_custo(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, packages=("ca-certificates",))
        right = BaseRecipe(family=OsFamily.ALPINE, packages=("ca-certificates", "curl"))

        diff = compare(left, right)

        assert [d.key for d in diff.added] == ["curl"]
        assert not diff.removed
        assert diff.added[0].cost  # o preço é dito, não só o nome

    def test_pacote_so_da_esquerda_aparece_como_removido(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, packages=("tzdata",))
        right = BaseRecipe(family=OsFamily.ALPINE)

        diff = compare(left, right)

        assert [d.key for d in diff.removed] == ["tzdata"]

    def test_receitas_iguais_nao_tem_mudanca(self) -> None:
        recipe = BaseRecipe(family=OsFamily.ALPINE, packages=("tzdata",))
        assert not compare(recipe, recipe).has_changes

    def test_pacote_fora_do_catalogo_e_descrito_como_desconhecido(self) -> None:
        """O diff não é lugar de levantar: descrever o desconhecido é mais útil."""
        delta = PackageDelta.of("pacote-inventado")
        assert delta.purpose == "não catalogado"
        assert delta.cost == "desconhecido"


class TestNotes:
    def test_troca_de_libc_e_destacada(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, runtime=Runtime.NODE)
        right = BaseRecipe(family=OsFamily.DEBIAN, runtime=Runtime.NODE)

        diff = compare(left, right)

        assert diff.libc_changed
        assert any("musl" in n and "glibc" in n for n in diff.notes())

    def test_troca_de_familia_com_a_mesma_libc_nao_alarma_sobre_libc(self) -> None:
        left = BaseRecipe(family=OsFamily.DEBIAN)
        right = BaseRecipe(family=OsFamily.UBUNTU)

        diff = compare(left, right)

        assert diff.family_changed
        assert not diff.libc_changed
        assert any("mesma libc" in n for n in diff.notes())

    def test_distroless_avisa_que_nada_pode_ser_instalado_depois(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, runtime=Runtime.NODE)
        right = BaseRecipe(family=OsFamily.DISTROLESS, runtime=Runtime.NODE)

        notas = compare(left, right).notes()

        assert any("gerenciador de pacotes nem shell" in n for n in notas)

    def test_distroless_nao_gera_nota_sobre_remover_gerenciador_embutido(self) -> None:
        """Não há gerenciador embutido numa distroless: dizer que um lado
        remove e o outro não descreveria uma diferença que não existe."""
        left = BaseRecipe(family=OsFamily.ALPINE, runtime=Runtime.NODE, strip_bundled_manager=True)
        right = BaseRecipe(family=OsFamily.DISTROLESS, runtime=Runtime.NODE)

        notas = compare(left, right).notes()

        assert not any("gerenciador embutido" in n for n in notas)

    def test_remocao_do_gerenciador_embutido_e_dita_quando_ambas_instalam(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, runtime=Runtime.NODE, strip_bundled_manager=True)
        right = BaseRecipe(family=OsFamily.DEBIAN, runtime=Runtime.NODE)

        diff = compare(left, right)

        assert diff.manager_strip_changed
        assert any("gerenciador embutido" in n for n in diff.notes())

    def test_tag_movel_de_um_dos_lados_e_apontada(self) -> None:
        left = BaseRecipe(family=OsFamily.ALPINE, digest="sha256:aaa")
        right = BaseRecipe(family=OsFamily.ALPINE)

        diff = compare(left, right)

        assert diff.pinning_changed
        assert any("tag móvel" in n for n in diff.notes())


class TestVerdict:
    def test_o_diff_manda_escanear_em_vez_de_eleger_vencedora(self) -> None:
        """Contar pacotes não mede CVE, e esta ferramenta não apresenta como
        medido o que não foi medido."""
        diff = compare(BaseRecipe(family=OsFamily.ALPINE), BaseRecipe(family=OsFamily.DEBIAN))

        assert "não de vulnerabilidade" in diff.verdict()
        assert "escanear" in diff.verdict()

    def test_documento_traz_os_dois_lados_e_as_notas(self) -> None:
        diff = compare(
            BaseRecipe(family=OsFamily.ALPINE, runtime=Runtime.NODE, packages=("tzdata",)),
            BaseRecipe(family=OsFamily.DEBIAN, runtime=Runtime.NODE),
        )
        payload = diff.to_dict()

        assert payload["libc_changed"] is True
        assert payload["left"]["libc"] == "musl"  # type: ignore[index]
        assert payload["right"]["libc"] == "glibc"  # type: ignore[index]
        assert payload["removed"]
        assert payload["notes"]

    def test_combinacao_sem_imagem_publicada_ainda_e_descrita(self) -> None:
        """O diff descreve; quem recusa a receita impossível é `validate()`."""
        payload = compare(
            BaseRecipe(family=OsFamily.ALPINE),
            BaseRecipe(family=OsFamily.DISTROLESS, runtime=Runtime.JAVA),
        ).to_dict()

        assert payload["right"]["reference"]  # type: ignore[index]
