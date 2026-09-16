# CI/CD integration

`dockerls analyze --ci` is the provider-neutral security-gate contract. It
writes one JSON document to stdout, does not start a spinner, and preserves the
public exit-code contract:

```bash
dockerls analyze "$IMAGE" --ci --fail-on critical > dockerls-result.json
```

The integration boundary detects Azure DevOps, GitHub Actions, GitLab CI,
Jenkins, Bitbucket Pipelines, CircleCI, generic CI, or local execution only
from documented affirmative environment variables. Connectors format context
and issues; they never change findings, policy, confidence, or verdict.

Reusable examples:

- [Azure DevOps](../examples/azure-devops/dockerls.yml)
- [GitHub Actions](../examples/github-actions/dockerls.yml)
- [GitLab CI](../examples/gitlab/dockerls.yml)
- [Jenkins](../examples/jenkins/Jenkinsfile)
- [Generic shell](../examples/generic-ci/dockerls.sh)

Machine-readable JSON and SARIF are written directly to stdout rather than
through Rich, avoiding wrapping, markup, colors, and terminal escape sequences.
Provider logging commands redact credentials and escape provider control
syntax before emission.

The stdout contract remains valid on negative outcomes. A policy rejection
writes its human diagnostic to stderr while stdout remains one report document.
A scanner/database failure emits the same JSON result shape with an empty
`recommendations` list and a populated `unverified` entry, then exits nonzero.
Absence of evidence is therefore machine-readable, but never reported as safe.
