"""`build_source_registry()` wiring a private/organization registry.

The point under test is the extension itself: a source configured through
settings shows up with no `--source private` branch added to any command,
and stays entirely absent when nobody configured it.
"""

from __future__ import annotations

import pytest

from dockerls.cli import dependencies
from dockerls.cli.dependencies import build_source_registry


@pytest.fixture(autouse=True)
def _clear_settings_singleton():
    dependencies._settings.cache_clear()
    yield
    dependencies._settings.cache_clear()


class TestPrivateSourceIsOptIn:
    def test_absent_when_no_host_is_configured(self, monkeypatch):
        monkeypatch.delenv("DOCKERLS_PRIVATE_REGISTRY_HOST", raising=False)

        registry = build_source_registry()

        assert "private" not in registry.names

    def test_present_once_a_host_is_configured(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_HOST", "registry.example.com")

        registry = build_source_registry()

        assert "private" in registry.names
        spec = registry.get("private")
        assert spec is not None
        assert spec.label == "Private Registry"
        assert "registry.example.com" in spec.description
        assert spec.default_enabled is False

    def test_requires_auth_reflects_whether_credentials_are_configured(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_HOST", "registry.example.com")
        monkeypatch.delenv("DOCKERLS_PRIVATE_REGISTRY_USERNAME", raising=False)

        assert build_source_registry().get("private").requires_auth is False

        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_USERNAME", "AWS")
        dependencies._settings.cache_clear()

        assert build_source_registry().get("private").requires_auth is True

    @pytest.mark.asyncio
    async def test_the_builder_produces_a_repository_pointed_at_the_configured_host(
        self, monkeypatch
    ):
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_HOST", "registry.example.com")
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_NAMESPACE", "myorg")
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_USERNAME", "AWS")
        monkeypatch.setenv("DOCKERLS_PRIVATE_REGISTRY_PASSWORD", "ecr-token")

        registry = build_source_registry()
        repo = await registry.get("private").build()

        assert repo.host == "registry.example.com"
        assert repo.namespace == "myorg"
        assert repo._client._username == "AWS"
        assert repo._client._password == "ecr-token"

        await repo.close()


class TestOtherSourcesAreUnaffected:
    def test_the_default_sources_are_still_registered_without_private_config(self, monkeypatch):
        monkeypatch.delenv("DOCKERLS_PRIVATE_REGISTRY_HOST", raising=False)

        names = build_source_registry().names

        assert {"dockerhub", "chainguard", "distroless", "dhi"} <= set(names)
