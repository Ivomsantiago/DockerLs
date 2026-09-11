import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.image_identity import ImageIdentity


def test_docker_hub_identity_is_normalized_and_tag_free():
    image = DockerImage(name="nginx", tag="latest", digest="sha256:" + "a" * 64)

    identity = ImageIdentity.from_image(image)

    assert identity.registry == "docker.io"
    assert identity.repository == "library/nginx"
    assert identity.platform == "linux/amd64"
    assert "latest" not in identity.cache_material


def test_explicit_registry_and_platform_are_preserved():
    image = DockerImage(
        name="registry.example/team/app",
        tag="v1",
        digest="sha256:" + "b" * 64,
        os="linux",
        architecture="arm64",
    )

    identity = ImageIdentity.from_image(image)

    assert identity.cache_material.endswith("#linux/arm64")
    assert identity.registry == "registry.example"
    assert identity.repository == "team/app"


@pytest.mark.parametrize("digest", ["", "sha256:1234", "md5:" + "a" * 32])
def test_identity_rejects_absent_or_noncanonical_digest(digest):
    image = DockerImage(name="nginx", tag="latest", digest=digest)

    with pytest.raises(ValueError, match="canonical sha256"):
        ImageIdentity.from_image(image)


@pytest.mark.parametrize("digest", ["", "sha256:1234", "md5:" + "a" * 32])
def test_cache_safe_factory_returns_none_for_untrusted_digest(digest):
    image = DockerImage(name="nginx", tag="latest", digest=digest)

    assert ImageIdentity.try_from_image(image) is None
