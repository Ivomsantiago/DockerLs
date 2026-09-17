"""Deterministic, provider-neutral CI environment detection and presentation.

Connectors may format issues and discover documented CI metadata. They never
alter findings, policy, confidence, or verdicts: CI integration is a boundary
around the security engine, not another decision maker.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from dockerls.infrastructure.redaction import redact

if TYPE_CHECKING:
    from collections.abc import Mapping


class CIProvider(StrEnum):
    AZURE_DEVOPS = "azure-devops"
    GITHUB = "github-actions"
    GITLAB = "gitlab-ci"
    JENKINS = "jenkins"
    BITBUCKET = "bitbucket-pipelines"
    CIRCLECI = "circleci"
    GENERIC = "generic-ci"
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class CIContext:
    provider: CIProvider
    repository: str = ""
    branch: str = ""
    commit: str = ""
    build_id: str = ""
    project: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider.value,
            "repository": self.repository,
            "branch": self.branch,
            "commit": self.commit,
            "build_id": self.build_id,
            "project": self.project,
        }


class PipelineConnector:
    """Presentation-only adapter for one detected pipeline environment."""

    def __init__(self, context: CIContext):
        self.context = context

    def emit_issue(self, level: str, message: str) -> str:
        """Return a provider logging command, or stable generic text."""
        severity = "error" if level.lower() == "error" else "warning"
        safe = _one_line(redact(message))
        if self.context.provider is CIProvider.AZURE_DEVOPS:
            return f"##vso[task.logissue type={severity};]{_azure_escape(safe)}"
        if self.context.provider is CIProvider.GITHUB:
            return f"::{severity}::{_github_escape(safe)}"
        return f"DOCKERLS_{severity.upper()}: {safe}"


def detect_connector(environ: Mapping[str, str]) -> PipelineConnector:
    """Detect a provider only from its documented, affirmative variables."""
    env = MappingProxyType(dict(environ))
    if _true(env.get("TF_BUILD")):
        context = CIContext(
            CIProvider.AZURE_DEVOPS,
            repository=env.get("BUILD_REPOSITORY_NAME", ""),
            branch=env.get("BUILD_SOURCEBRANCH", ""),
            commit=env.get("BUILD_SOURCEVERSION", ""),
            build_id=env.get("BUILD_BUILDID", ""),
            project=env.get("SYSTEM_TEAMPROJECT", ""),
        )
    elif _true(env.get("GITHUB_ACTIONS")):
        context = CIContext(
            CIProvider.GITHUB,
            repository=env.get("GITHUB_REPOSITORY", ""),
            branch=env.get("GITHUB_REF_NAME", ""),
            commit=env.get("GITHUB_SHA", ""),
            build_id=env.get("GITHUB_RUN_ID", ""),
        )
    elif _true(env.get("GITLAB_CI")):
        context = CIContext(
            CIProvider.GITLAB,
            repository=env.get("CI_PROJECT_PATH", ""),
            branch=env.get("CI_COMMIT_REF_NAME", ""),
            commit=env.get("CI_COMMIT_SHA", ""),
            build_id=env.get("CI_PIPELINE_ID", ""),
        )
    elif env.get("JENKINS_URL"):
        context = CIContext(
            CIProvider.JENKINS,
            repository=env.get("JOB_NAME", ""),
            branch=env.get("BRANCH_NAME", ""),
            commit=env.get("GIT_COMMIT", ""),
            build_id=env.get("BUILD_ID", ""),
        )
    elif _true(env.get("BITBUCKET_BUILD_NUMBER")):
        context = CIContext(
            CIProvider.BITBUCKET,
            repository=env.get("BITBUCKET_REPO_FULL_NAME", ""),
            branch=env.get("BITBUCKET_BRANCH", ""),
            commit=env.get("BITBUCKET_COMMIT", ""),
            build_id=env.get("BITBUCKET_BUILD_NUMBER", ""),
        )
    elif _true(env.get("CIRCLECI")):
        context = CIContext(
            CIProvider.CIRCLECI,
            repository=env.get("CIRCLE_PROJECT_REPONAME", ""),
            branch=env.get("CIRCLE_BRANCH", ""),
            commit=env.get("CIRCLE_SHA1", ""),
            build_id=env.get("CIRCLE_WORKFLOW_ID", ""),
        )
    elif _true(env.get("CI")):
        context = CIContext(CIProvider.GENERIC)
    else:
        context = CIContext(CIProvider.LOCAL)
    return PipelineConnector(context)


def _true(value: str | None) -> bool:
    return bool(value and value.strip().lower() not in {"0", "false", "no", "off"})


def _one_line(value: str) -> str:
    return " ".join(value.splitlines())


def _azure_escape(value: str) -> str:
    return value.replace("%", "%25").replace(";", "%3B").replace("]", "%5D")


def _github_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
