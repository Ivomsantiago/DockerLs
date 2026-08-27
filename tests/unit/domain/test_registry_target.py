"""Destino de publicação: validado antes do build, não na hora do push.

O `--push` publicava a tag local como está. Numa tag sem host --
`dockerls:1.5.0`, que é a forma que todo mundo digita -- isso vira uma
tentativa de publicar em `docker.io/library/dockerls`, recusada com um
"denied" que não explica nada. E o assistente interativo oferecia escolher
entre "dockerhub", "ghcr" e "harbor" sem usar a resposta para coisa alguma.

Estes testes fixam as regras que diferem de verdade entre provedores, porque
é onde um destino malformado passa despercebido até o push -- depois de
validar, construir e escanear.
"""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.registry_target import (
    InvalidRegistryTargetError,
    RegistryProvider,
    RegistryTarget,
    detect_provider,
)


class TestProviderDetection:
    @pytest.mark.parametrize(
        ("host", "provider"),
        [
            ("", RegistryProvider.DOCKER_HUB),
            ("docker.io", RegistryProvider.DOCKER_HUB),
            ("meuregistro.azurecr.io", RegistryProvider.AZURE_ACR),
            # Nuvens soberanas: mesmo produto, outra geografia.
            ("meuregistro.azurecr.cn", RegistryProvider.AZURE_ACR),
            ("meuregistro.azurecr.us", RegistryProvider.AZURE_ACR),
            ("us-central1-docker.pkg.dev", RegistryProvider.GOOGLE_ARTIFACT_REGISTRY),
            ("southamerica-east1-docker.pkg.dev", RegistryProvider.GOOGLE_ARTIFACT_REGISTRY),
            ("gcr.io", RegistryProvider.GOOGLE_CONTAINER_REGISTRY),
            ("eu.gcr.io", RegistryProvider.GOOGLE_CONTAINER_REGISTRY),
            ("dhi.io", RegistryProvider.DHI),
            ("ghcr.io", RegistryProvider.GITHUB_GHCR),
            ("registry.interna:5000", RegistryProvider.OTHER),
        ],
    )
    def test_hosts_are_attributed_to_their_provider(self, host, provider):
        assert detect_provider(host) is provider

    def test_an_unknown_host_is_a_private_registry_not_an_error(self):
        # Recusar o que não se reconhece fecharia a porta de todo registry
        # interno, que é infraestrutura absolutamente normal.
        assert detect_provider("nexus.empresa.local") is RegistryProvider.OTHER


class TestReferenceComposition:
    def test_full_destination_round_trips(self):
        target = RegistryTarget.parse("meuacr.azurecr.io/apps/minha-app", "1.5.0")
        assert target.host == "meuacr.azurecr.io"
        assert target.namespace == "apps"
        assert target.repository == "minha-app"
        assert target.reference == "meuacr.azurecr.io/apps/minha-app:1.5.0"

    def test_docker_hub_destination_has_no_host(self):
        target = RegistryTarget.parse("minhaorg/minha-app", "2.0")
        assert target.host == ""
        assert target.reference == "minhaorg/minha-app:2.0"

    def test_a_port_in_the_host_is_not_read_as_a_tag(self):
        target = RegistryTarget.parse("registry.interna:5000/time/app", "1.0")
        assert target.reference == "registry.interna:5000/time/app:1.0"

    def test_a_tag_inside_the_destination_is_refused(self):
        # Duas tags é ambiguidade, não conveniência: qual das duas vale?
        with pytest.raises(InvalidRegistryTargetError, match="without a tag"):
            RegistryTarget.parse("minhaorg/app:1.0", "2.0")


class TestProviderRules:
    def test_docker_hub_without_a_namespace_is_refused(self):
        target = RegistryTarget.parse("minha-app", "1.0")
        with pytest.raises(InvalidRegistryTargetError, match="user or organization"):
            target.validate()

    def test_the_library_namespace_is_refused(self):
        target = RegistryTarget.parse("library/minha-app", "1.0")
        with pytest.raises(InvalidRegistryTargetError, match="official images"):
            target.validate()

    def test_artifact_registry_requires_project_and_repository(self):
        target = RegistryTarget.parse("us-central1-docker.pkg.dev/proj/app", "1.0")
        with pytest.raises(InvalidRegistryTargetError, match="<project>"):
            target.validate()

    def test_artifact_registry_with_the_full_path_is_accepted(self):
        RegistryTarget.parse("us-central1-docker.pkg.dev/proj/containers/app", "1.0").validate()

    def test_gcr_accepts_project_and_image(self):
        RegistryTarget.parse("gcr.io/meu-projeto/app", "1.0").validate()

    def test_acr_accepts_a_flat_repository(self):
        RegistryTarget.parse("meuacr.azurecr.io/app", "1.0").validate()

    def test_dhi_is_a_catalogue_not_a_destination(self):
        target = RegistryTarget.parse("dhi.io/minha-app", "1.0")
        with pytest.raises(InvalidRegistryTargetError, match="does not accept pushes"):
            target.validate()

    @pytest.mark.parametrize("tag", ["", "-começa-com-hífen", "tag com espaço", "a" * 200])
    def test_invalid_tags_are_refused(self, tag):
        with pytest.raises(InvalidRegistryTargetError):
            RegistryTarget.parse("minhaorg/app", tag).validate()

    def test_uppercase_paths_are_refused(self):
        with pytest.raises(InvalidRegistryTargetError, match="lowercase"):
            RegistryTarget.parse("MinhaOrg/App", "1.0").validate()


class TestLoginHints:
    @pytest.mark.parametrize(
        ("destination", "fragment"),
        [
            ("meuacr.azurecr.io/app", "az acr login"),
            ("us-central1-docker.pkg.dev/p/r/app", "gcloud auth configure-docker"),
            ("minhaorg/app", "docker login"),
            ("ghcr.io/org/app", "ghcr.io"),
        ],
    )
    def test_each_provider_names_its_login_command(self, destination, fragment):
        # "denied" é a mensagem que o Docker dá, e ela não diz qual comando
        # resolve. Esta é a metade que falta em quase todo push recusado.
        assert fragment in RegistryTarget.parse(destination, "1.0").login_hint
