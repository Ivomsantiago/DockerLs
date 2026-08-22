"""A política como dado: cada regra conferida contra o que foi medido.

O que estes testes fixam acima de tudo é a direção da falha. Toda regra que
depende de uma medição que não aconteceu vira violação, nunca silêncio: uma
imagem não medida não é uma imagem em conformidade.
"""

from __future__ import annotations

from dockerls.domain.value_objects.build_policy import (
    BaseFact,
    BuildPolicy,
    PolicyFacts,
    PolicyRule,
    evaluate,
)
from dockerls.domain.value_objects.tristate import Tristate


def _rules(policy: BuildPolicy, facts: PolicyFacts) -> list[PolicyRule]:
    return [v.rule for v in evaluate(policy, facts)]


class TestScanRequirement:
    def test_scan_ausente_viola_em_vez_de_passar(self) -> None:
        policy = BuildPolicy(require_scan=True)
        assert _rules(policy, PolicyFacts(scan_ran=False)) == [PolicyRule.REQUIRE_SCAN]

    def test_scan_presente_cumpre(self) -> None:
        assert not evaluate(BuildPolicy(require_scan=True), PolicyFacts(scan_ran=True))


class TestCeilings:
    def test_acima_do_teto_viola_com_o_numero(self) -> None:
        policy = BuildPolicy(max_vulnerabilities={"high": 2})
        facts = PolicyFacts(scan_ran=True, severity_counts={"high": 5})

        violations = evaluate(policy, facts)

        assert violations[0].rule is PolicyRule.MAX_VULNERABILITIES
        assert "5" in violations[0].message and "2" in violations[0].message

    def test_dentro_do_teto_cumpre(self) -> None:
        policy = BuildPolicy(max_vulnerabilities={"high": 5})
        facts = PolicyFacts(scan_ran=True, severity_counts={"high": 5})

        assert not evaluate(policy, facts)

    def test_teto_sem_scan_viola_porque_nao_ha_contagem(self) -> None:
        """ "Contagem ausente" não é "contagem dentro do teto": aprovar aqui
        esvaziaria toda regra de teto numa máquina sem scanner."""
        policy = BuildPolicy(max_vulnerabilities={"critical": 0})

        assert _rules(policy, PolicyFacts(scan_ran=False)) == [PolicyRule.MAX_VULNERABILITIES]

    def test_severidade_nao_declarada_nao_e_conferida(self) -> None:
        policy = BuildPolicy(max_vulnerabilities={"critical": 0})
        facts = PolicyFacts(scan_ran=True, severity_counts={"critical": 0, "low": 900})

        assert not evaluate(policy, facts)


class TestBases:
    def test_base_sem_digest_viola(self) -> None:
        policy = BuildPolicy(require_pinned_bases=True)
        facts = PolicyFacts(bases=(BaseFact(reference="node:22", registry="", pinned=False),))

        violations = evaluate(policy, facts)

        assert violations[0].rule is PolicyRule.REQUIRE_PINNED_BASES
        assert "node:22" in violations[0].message

    def test_nenhuma_base_lida_viola_em_vez_de_aprovar_por_omissao(self) -> None:
        policy = BuildPolicy(require_pinned_bases=True)
        assert _rules(policy, PolicyFacts()) == [PolicyRule.REQUIRE_PINNED_BASES]

    def test_todas_fixadas_cumprem(self) -> None:
        policy = BuildPolicy(require_pinned_bases=True)
        facts = PolicyFacts(
            bases=(BaseFact(reference="node:22@sha256:aa", registry="", pinned=True),)
        )
        assert not evaluate(policy, facts)

    def test_registry_fora_da_lista_viola(self) -> None:
        policy = BuildPolicy(allowed_base_registries=("cgr.dev",))
        facts = PolicyFacts(
            bases=(BaseFact(reference="quay.io/app:1", registry="quay.io", pinned=True),)
        )

        violations = evaluate(policy, facts)

        assert violations[0].rule is PolicyRule.ALLOWED_BASE_REGISTRIES

    def test_base_sem_host_conta_como_docker_hub(self) -> None:
        """Tratá-la como "sem registry" faria a regra ignorar o caso mais comum."""
        policy = BuildPolicy(allowed_base_registries=("cgr.dev",))
        facts = PolicyFacts(bases=(BaseFact(reference="node:22", registry="", pinned=True),))

        assert _rules(policy, facts) == [PolicyRule.ALLOWED_BASE_REGISTRIES]

    def test_registry_permitido_cumpre_sem_diferenciar_maiusculas(self) -> None:
        policy = BuildPolicy(allowed_base_registries=("CGR.dev",))
        facts = PolicyFacts(
            bases=(BaseFact(reference="cgr.dev/x:1", registry="cgr.dev", pinned=True),)
        )
        assert not evaluate(policy, facts)


class TestNonroot:
    def test_root_viola(self) -> None:
        policy = BuildPolicy(require_nonroot=True)
        violations = evaluate(policy, PolicyFacts(nonroot=Tristate.FALSE))

        assert violations[0].rule is PolicyRule.REQUIRE_NONROOT
        assert "roda como root" in violations[0].message

    def test_desconhecido_viola_e_diz_que_e_ausencia_de_medida(self) -> None:
        policy = BuildPolicy(require_nonroot=True)
        violations = evaluate(policy, PolicyFacts(nonroot=Tristate.UNKNOWN))

        assert violations[0].rule is PolicyRule.REQUIRE_NONROOT
        assert "não foi possível determinar" in violations[0].message

    def test_nao_root_cumpre(self) -> None:
        assert not evaluate(BuildPolicy(require_nonroot=True), PolicyFacts(nonroot=Tristate.TRUE))


class TestLabels:
    def test_rotulo_ausente_viola(self) -> None:
        policy = BuildPolicy(required_labels=("org.opencontainers.image.source",))
        assert _rules(policy, PolicyFacts()) == [PolicyRule.REQUIRED_LABELS]

    def test_rotulo_vazio_conta_como_ausente(self) -> None:
        policy = BuildPolicy(required_labels=("owner",))
        assert _rules(policy, PolicyFacts(labels={"owner": "   "})) == [PolicyRule.REQUIRED_LABELS]

    def test_rotulo_presente_cumpre(self) -> None:
        policy = BuildPolicy(required_labels=("owner",))
        assert not evaluate(policy, PolicyFacts(labels={"owner": "Plataforma"}))


class TestProvenance:
    def test_procedencia_verificada_cumpre(self) -> None:
        policy = BuildPolicy(require_provenance=True)
        assert not evaluate(policy, PolicyFacts(provenance_status="VERIFIED"))

    def test_entrada_alterada_viola(self) -> None:
        policy = BuildPolicy(require_provenance=True)
        violations = evaluate(policy, PolicyFacts(provenance_status="INPUT_CHANGED"))

        assert violations[0].rule is PolicyRule.REQUIRE_PROVENANCE
        assert "INPUT_CHANGED" in violations[0].message

    def test_sem_registro_viola(self) -> None:
        policy = BuildPolicy(require_provenance=True)
        assert _rules(policy, PolicyFacts()) == [PolicyRule.REQUIRE_PROVENANCE]


class TestEffectiveFailOn:
    def test_vence_o_mais_estrito_venha_de_onde_vier(self) -> None:
        """Um arquivo no repositório não pode desligar um portão que o
        pipeline pediu, e uma flag não pode afrouxar a política.

        "Mais estrito" é o limiar mais baixo na escala, não a palavra mais
        assustadora: `--fail-on low` reprova em LOW *e em tudo acima*, enquanto
        `--fail-on critical` só olha para CRITICAL.
        """
        assert BuildPolicy(fail_on="high").effective_fail_on("critical") == "high"
        assert BuildPolicy(fail_on="critical").effective_fail_on("high") == "high"
        assert BuildPolicy(fail_on="critical").effective_fail_on("low") == "low"

    def test_unknown_nunca_vira_limiar(self) -> None:
        """O portão não sabe avaliá-lo; aceitá-lo produziria um build que morre
        com erro técnico no meio do caminho."""
        assert BuildPolicy(fail_on="critical").effective_fail_on("unknown") == "critical"

    def test_politica_sozinha_define_o_limiar(self) -> None:
        assert BuildPolicy(fail_on="high").effective_fail_on("") == "high"

    def test_sem_politica_a_linha_de_comando_vale(self) -> None:
        assert BuildPolicy().effective_fail_on("medium") == "medium"

    def test_nenhum_dos_dois_nao_inventa_portao(self) -> None:
        assert BuildPolicy().effective_fail_on("") == ""


class TestEmptiness:
    def test_politica_sem_regras_e_reconhecida_como_vazia(self) -> None:
        assert BuildPolicy().is_empty

    def test_qualquer_regra_declarada_deixa_de_ser_vazia(self) -> None:
        assert not BuildPolicy(require_scan=True).is_empty
        assert not BuildPolicy(max_vulnerabilities={"low": 0}).is_empty

    def test_politica_vazia_nao_viola_nada_e_tambem_nao_garante_nada(self) -> None:
        assert not evaluate(BuildPolicy(), PolicyFacts())


class TestProductionProfile:
    """O perfil nomeado existe porque a alternativa é uma lista de sete flags
    que cada pipeline digita de novo, esquecendo uma diferente por vez."""

    def test_o_perfil_exige_o_conjunto_completo(self) -> None:
        perfil = BuildPolicy.production()

        assert perfil.fail_on == "critical"
        assert perfil.require_scan
        assert perfil.require_pinned_bases
        assert perfil.require_nonroot
        assert perfil.require_provenance
        assert "security.contact" in perfil.required_labels

    def test_o_portao_fica_em_critical_e_nao_em_high(self) -> None:
        """Um perfil que ninguém consegue cumprir é um perfil que as pessoas
        desligam inteiro, e `high` reprova quase toda base Debian."""
        assert BuildPolicy.production().fail_on == "critical"

    def test_sem_arquivo_o_perfil_vale_sozinho(self) -> None:
        assert BuildPolicy.production().merged_with(None) == BuildPolicy.production()


class TestMerge:
    def test_o_arquivo_do_repositorio_pode_apertar(self) -> None:
        """`high` reprova em HIGH e em CRITICAL; o perfil de produção só olha
        para CRITICAL. O arquivo aperta, e isso vale."""
        perfil = BuildPolicy.production().merged_with(BuildPolicy(fail_on="high"))
        assert perfil.fail_on == "high"

    def test_o_arquivo_pode_apertar_ate_o_limite(self) -> None:
        perfil = BuildPolicy.production().merged_with(BuildPolicy(fail_on="low"))
        assert perfil.fail_on == "low"

    def test_o_arquivo_nao_pode_afrouxar(self) -> None:
        """Senão bastaria commitar um YAML para publicar o que não passaria."""
        perfil = BuildPolicy(fail_on="low").merged_with(BuildPolicy(fail_on="critical"))
        assert perfil.fail_on == "low"

    def test_exigencias_de_qualquer_lado_valem_nos_dois(self) -> None:
        perfil = BuildPolicy(require_nonroot=True).merged_with(BuildPolicy(require_scan=True))

        assert perfil.require_nonroot
        assert perfil.require_scan

    def test_rotulos_se_somam_sem_repetir(self) -> None:
        perfil = BuildPolicy(required_labels=("a", "b")).merged_with(
            BuildPolicy(required_labels=("b", "c"))
        )

        assert perfil.required_labels == ("a", "b", "c")

    def test_o_teto_mais_baixo_vence(self) -> None:
        perfil = BuildPolicy(max_vulnerabilities={"high": 2}).merged_with(
            BuildPolicy(max_vulnerabilities={"high": 9, "low": 5})
        )

        assert perfil.max_vulnerabilities == {"high": 2, "low": 5}

    def test_registries_se_somam_em_vez_de_intersectar(self) -> None:
        """Duas listas disjuntas produziriam um conjunto vazio, que significa
        "não restringe" -- exatamente o oposto do que as duas pediram."""
        perfil = BuildPolicy(allowed_base_registries=("cgr.dev",)).merged_with(
            BuildPolicy(allowed_base_registries=("docker.io",))
        )

        assert set(perfil.allowed_base_registries) == {"cgr.dev", "docker.io"}
