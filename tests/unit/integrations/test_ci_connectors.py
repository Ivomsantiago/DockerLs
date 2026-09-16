import pytest

from dockerls.integrations.ci.connectors import CIProvider, detect_connector


@pytest.mark.parametrize(
    ("env", "provider"),
    [
        ({"TF_BUILD": "True"}, CIProvider.AZURE_DEVOPS),
        ({"GITHUB_ACTIONS": "true"}, CIProvider.GITHUB),
        ({"GITLAB_CI": "true"}, CIProvider.GITLAB),
        ({"JENKINS_URL": "https://jenkins.example"}, CIProvider.JENKINS),
        ({"BITBUCKET_BUILD_NUMBER": "42"}, CIProvider.BITBUCKET),
        ({"CIRCLECI": "true"}, CIProvider.CIRCLECI),
        ({"CI": "true"}, CIProvider.GENERIC),
        ({}, CIProvider.LOCAL),
    ],
)
def test_detection_requires_documented_positive_evidence(env, provider):
    assert detect_connector(env).context.provider is provider


def test_azure_context_uses_documented_variables_only():
    connector = detect_connector(
        {
            "TF_BUILD": "True",
            "BUILD_BUILDID": "1842",
            "BUILD_SOURCEVERSION": "abc123",
            "BUILD_SOURCEBRANCH": "refs/heads/main",
            "BUILD_REPOSITORY_NAME": "team/api",
            "SYSTEM_TEAMPROJECT": "payments",
        }
    )

    assert connector.context.to_dict() == {
        "provider": "azure-devops",
        "repository": "team/api",
        "branch": "refs/heads/main",
        "commit": "abc123",
        "build_id": "1842",
        "project": "payments",
    }


def test_connector_never_leaks_secrets_or_allows_command_injection():
    secret = "dckr_pat_AbCdEf123456789xyz"
    connector = detect_connector({"TF_BUILD": "true"})

    output = connector.emit_issue("error", f"token={secret}\n]malicious;field=value")

    assert secret not in output
    assert "\n" not in output
    assert "%5D" in output
    assert "%3B" in output


def test_github_issue_has_stable_machine_syntax():
    connector = detect_connector({"GITHUB_ACTIONS": "true"})
    assert connector.emit_issue("warning", "policy rejected image") == (
        "::warning::policy rejected image"
    )
