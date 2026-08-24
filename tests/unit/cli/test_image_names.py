"""`split_repository_and_tag` / `reject_tagged_reference`.

The bug: `search`, `recommend` and `export` treated `node:18` as a literal
repository name to look up, instead of recognising it as a repository plus
a tag the user almost certainly meant for `analyze`. A naive
`rsplit(":", 1)` also breaks on a private registry with a port
(`registry.internal:5000/app`), mistaking the port for a tag.
"""

from __future__ import annotations

from dockerls.cli.image_names import reject_tagged_reference, split_repository_and_tag


class TestSplitRepositoryAndTag:
    def test_bare_name_has_no_tag(self):
        assert split_repository_and_tag("node") == ("node", "")

    def test_name_with_tag_is_split(self):
        assert split_repository_and_tag("node:18") == ("node", "18")

    def test_org_repo_with_tag_is_split(self):
        assert split_repository_and_tag("bitnami/node:18") == ("bitnami/node", "18")

    def test_private_registry_with_port_is_not_a_tag(self):
        assert split_repository_and_tag("registry.internal:5000/app") == (
            "registry.internal:5000/app",
            "",
        )

    def test_private_registry_with_port_and_tag(self):
        assert split_repository_and_tag("registry.internal:5000/app:18") == (
            "registry.internal:5000/app",
            "18",
        )

    def test_localhost_registry_is_not_a_tag(self):
        assert split_repository_and_tag("localhost:5000/app") == ("localhost:5000/app", "")

    def test_dotted_registry_without_port_is_not_a_tag(self):
        assert split_repository_and_tag("myregistry.local/app") == ("myregistry.local/app", "")

    def test_digest_suffix_is_stripped_and_not_mistaken_for_a_tag(self):
        assert split_repository_and_tag(
            "node@sha256:" + "a" * 64
        ) == ("node", "")

    def test_tag_and_digest_together(self):
        assert split_repository_and_tag(
            "node:18@sha256:" + "a" * 64
        ) == ("node", "18")


class TestRejectTaggedReference:
    def test_bare_name_is_accepted(self):
        assert reject_tagged_reference("node", "search") is None

    def test_private_registry_with_port_is_accepted(self):
        assert reject_tagged_reference("registry.internal:5000/app", "search") is None

    def test_tagged_reference_is_rejected_with_an_actionable_message(self):
        message = reject_tagged_reference("node:18", "search")
        assert message is not None
        assert "search" in message
        assert "dockerls search node" in message
        assert "dockerls analyze node:18" in message
