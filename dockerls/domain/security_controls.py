"""Published security controls, and which of this tool's rules implement them.

`analyze-dockerfile` has always answered with a code: `DF002 failed`. That
code means nothing outside this repository. A reader who wants to know
whether the rule is a real requirement or one maintainer's preference has
nowhere to look, and an auditor who needs to map findings onto a compliance
framework has to do it by hand, from the message text.

This module closes that gap by naming, for each rule, the published control
it implements. The value is not decoration: a finding that cites *CIS Docker
Benchmark 4.1* can be argued about, escalated, waived with a reason, and
mapped to an audit programme. A finding that cites `DF002` can only be
obeyed or ignored.

**Every identifier and title here was verified against its primary source**
rather than recalled, on 2026-08-18:

* **CIS Docker Benchmark, section 4** -- checked against Docker's own
  implementation of the benchmark, `docker/docker-bench-security`
  (`tests/4_container_images.sh`), which carries the control numbers and
  titles verbatim.
* **OWASP Docker Security Cheat Sheet** -- checked against the published
  cheat sheet at cheatsheetseries.owasp.org, whose rules are numbered
  `RULE #0` through `RULE #13`.
* **NIST SP 800-190** -- checked against the table of contents of the
  official NIST publication.

That verification is the point, and it changed the content: three of the
four citations drafted from memory were wrong. `NIST SP 800-190 4.4.2` is
*Unbounded network access from containers*, not "least privilege", and
`OWASP RULE #8` is *Set filesystem and volumes to read-only*, not "minimal
base images". A tool that refuses to state a vulnerability count it did not
measure cannot cite a control it did not check either.

Where no published control covers a rule, that is stated rather than
stretched: `controls_for` returns an empty tuple, and the renderers say the
rule is this project's own guidance. Inventing a plausible-looking control
number would be worse than having none, because it is the kind of error that
survives review.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ControlSource(StrEnum):
    """Where a control is published. Cited by name so a reader can find it."""

    CIS_DOCKER = "CIS Docker Benchmark"
    NIST_800_190 = "NIST SP 800-190"
    OWASP_DOCKER = "OWASP Docker Security Cheat Sheet"
    DOCKER_DOCS = "Docker documentation"
    OCI_SPEC = "OCI Image Format Specification"


@dataclass(frozen=True)
class Control:
    """One published control, quoted rather than paraphrased.

    `title` is the source's own wording. Paraphrasing would make the
    citation unsearchable, which defeats the purpose of having one.
    """

    source: ControlSource
    #: The source's identifier: "4.1", "RULE #2", "4.1.2". Empty for
    #: documentation that is cited by page rather than by number.
    identifier: str
    title: str

    def __str__(self) -> str:
        head = f"{self.source.value} {self.identifier}".strip()
        return f"{head} -- {self.title}"


# --- The catalogue, verified against primary sources ---------------------

CIS_4_1 = Control(
    ControlSource.CIS_DOCKER, "4.1", "Ensure that a user for the container has been created"
)
CIS_4_2 = Control(
    ControlSource.CIS_DOCKER, "4.2", "Ensure that containers use only trusted base images"
)
CIS_4_3 = Control(
    ControlSource.CIS_DOCKER,
    "4.3",
    "Ensure that unnecessary packages are not installed in the container",
)
CIS_4_4 = Control(
    ControlSource.CIS_DOCKER,
    "4.4",
    "Ensure images are scanned and rebuilt to include security patches",
)
CIS_4_6 = Control(
    ControlSource.CIS_DOCKER,
    "4.6",
    "Ensure that HEALTHCHECK instructions have been added to container images",
)
CIS_4_7 = Control(
    ControlSource.CIS_DOCKER,
    "4.7",
    "Ensure update instructions are not used alone in the Dockerfile",
)
CIS_4_8 = Control(
    ControlSource.CIS_DOCKER, "4.8", "Ensure setuid and setgid permissions are removed"
)
CIS_4_9 = Control(
    ControlSource.CIS_DOCKER, "4.9", "Ensure that COPY is used instead of ADD in Dockerfiles"
)
CIS_4_10 = Control(ControlSource.CIS_DOCKER, "4.10", "Ensure secrets are not stored in Dockerfiles")
CIS_4_12 = Control(ControlSource.CIS_DOCKER, "4.12", "Ensure all signed artifacts are validated")

OWASP_2 = Control(ControlSource.OWASP_DOCKER, "RULE #2", "Set a user")
OWASP_4 = Control(
    ControlSource.OWASP_DOCKER, "RULE #4", "Prevent in-container privilege escalation"
)
OWASP_9 = Control(
    ControlSource.OWASP_DOCKER,
    "RULE #9",
    "Integrate container scanning tools into your CI/CD pipeline",
)
OWASP_12 = Control(
    ControlSource.OWASP_DOCKER, "RULE #12", "Utilize Docker Secrets for Sensitive Data Management"
)
OWASP_13 = Control(ControlSource.OWASP_DOCKER, "RULE #13", "Enhance Supply Chain Security")

NIST_4_1_1 = Control(ControlSource.NIST_800_190, "4.1.1", "Image vulnerabilities")
NIST_4_1_2 = Control(ControlSource.NIST_800_190, "4.1.2", "Image configuration defects")
NIST_4_1_4 = Control(ControlSource.NIST_800_190, "4.1.4", "Embedded clear text secrets")
NIST_4_1_5 = Control(ControlSource.NIST_800_190, "4.1.5", "Use of untrusted images")

DOCKER_MULTISTAGE = Control(ControlSource.DOCKER_DOCS, "", "Multi-stage builds")
DOCKER_ENTRYPOINT = Control(ControlSource.DOCKER_DOCS, "", "Dockerfile reference: ENTRYPOINT")
DOCKER_BUILD_CONTEXT = Control(ControlSource.DOCKER_DOCS, "", "Build context and .dockerignore")
OCI_ANNOTATIONS = Control(ControlSource.OCI_SPEC, "", "Pre-defined annotation keys")


@dataclass(frozen=True)
class RuleMapping:
    """A DockerLs rule, the controls it implements, and why it matters.

    `rationale` is this project's own words: the controls say *what*, and a
    reader deciding whether to act needs *why*, in terms of what an attacker
    gains. Keeping them in separate fields is what stops a paraphrase from
    being mistaken for a quotation.
    """

    rule_id: str
    summary: str
    rationale: str
    controls: tuple[Control, ...] = ()

    @property
    def is_documented(self) -> bool:
        """False when this is DockerLs's own guidance, not a published control."""
        return bool(self.controls)


RULE_MAPPINGS: tuple[RuleMapping, ...] = (
    RuleMapping(
        rule_id="DF001",
        summary="Pin the base image",
        rationale=(
            "A floating tag means the image you tested and the image that ships can "
            "differ with no change on your side, so nothing you verified about the "
            "base still holds at deploy time."
        ),
        controls=(CIS_4_2, NIST_4_1_5, OWASP_13),
    ),
    RuleMapping(
        rule_id="DF002",
        summary="Run as a non-root user",
        rationale=(
            "A process running as uid 0 starts from the most privileged position "
            "available inside the container, so any code-execution bug begins with "
            "control of the filesystem and of anything mounted into it."
        ),
        controls=(CIS_4_1, OWASP_2, NIST_4_1_2),
    ),
    RuleMapping(
        rule_id="DF003",
        summary="Use a multi-stage build",
        rationale=(
            "Compilers, headers and package managers are needed to build and never "
            "needed to run. A builder stage is how they stay out of the shipped "
            "image without giving up a reproducible build."
        ),
        controls=(CIS_4_3, DOCKER_MULTISTAGE),
    ),
    RuleMapping(
        rule_id="DF004",
        summary="Keep secrets out of ENV and ARG",
        rationale=(
            "A value in ENV is in the image metadata, readable by anyone who can "
            "pull it, and it survives in the layer history even if a later layer "
            "removes it."
        ),
        controls=(CIS_4_10, NIST_4_1_4, OWASP_12),
    ),
    RuleMapping(
        rule_id="DF005",
        summary="Clean the package manager cache in the same layer",
        rationale=(
            "A cache removed in a later layer is still present in the one that "
            "created it, so the image carries the bytes and the attack surface "
            "while appearing not to."
        ),
        controls=(CIS_4_3, CIS_4_7),
    ),
    RuleMapping(
        rule_id="DF006",
        summary="Declare a HEALTHCHECK",
        rationale=(
            "An orchestrator that cannot distinguish a wedged container from a "
            "healthy one keeps sending it traffic. This is availability rather "
            "than confidentiality, which is why it weighs less than the rest."
        ),
        controls=(CIS_4_6,),
    ),
    RuleMapping(
        rule_id="DF007",
        summary="Label the image with provenance metadata",
        rationale=(
            "Standard annotations are what let a responder answer 'where did this "
            "image come from and which commit built it' during an incident, "
            "without guessing from the tag."
        ),
        controls=(OCI_ANNOTATIONS,),
    ),
    RuleMapping(
        rule_id="DF008",
        summary="Start from a minimal base",
        rationale=(
            "Every package in the base is code nobody in your organisation audited "
            "and a future CVE somebody will have to triage; the smallest base that "
            "runs your application is the smallest such backlog."
        ),
        controls=(CIS_4_3, NIST_4_1_2),
    ),
    RuleMapping(
        rule_id="DF009",
        summary="Do not install sudo",
        rationale=(
            "sudo exists to cross a privilege boundary, and it is setuid to do it. "
            "In a container that should already be running unprivileged, it is a "
            "ready-made escalation path."
        ),
        controls=(CIS_4_8, OWASP_4),
    ),
    RuleMapping(
        rule_id="DF010",
        summary="Use exec form for ENTRYPOINT and CMD",
        rationale=(
            "Shell form starts a shell as pid 1, which swallows SIGTERM: the "
            "container stops being able to shut down cleanly, and orchestrators "
            "fall back to killing it."
        ),
        controls=(DOCKER_ENTRYPOINT,),
    ),
    RuleMapping(
        rule_id="DF011",
        summary="Avoid shipping an interactive shell",
        rationale=(
            "A shell turns a limited primitive -- a file write, a template "
            "injection -- into arbitrary command execution, and it is the first "
            "thing most published container exploit chains reach for."
        ),
        controls=(CIS_4_3, NIST_4_1_2),
    ),
    RuleMapping(
        rule_id="DF012",
        summary="Keep a .dockerignore",
        rationale=(
            "Without one the build context carries .git, .env and local "
            "credentials to the daemon, and anything a COPY happens to match ends "
            "up in the image."
        ),
        controls=(CIS_4_10, DOCKER_BUILD_CONTEXT),
    ),
    RuleMapping(
        rule_id="DF013",
        summary="Use COPY instead of ADD",
        rationale=(
            "ADD does two things COPY does not, and neither is written on the line: "
            "it fetches URLs with nothing verifying what came back, and it "
            "auto-extracts local archives, so a tarball carrying '../../etc' writes "
            "outside the destination. A reader sees what looks like a copy."
        ),
        controls=(CIS_4_9, NIST_4_1_5),
    ),
    RuleMapping(
        rule_id="DF014",
        summary="Do not pipe a downloaded script into a shell",
        rationale=(
            "`curl | sh` leaves the script nowhere: nothing signs it, nothing checks a "
            "digest, and no layer records what ran. Whoever controls that host, the "
            "path to it, or the DNS in between chooses what executes as root during "
            "your build, and the Dockerfile keeps reading the same."
        ),
        controls=(NIST_4_1_5, OWASP_13),
    ),
    RuleMapping(
        rule_id="DF015",
        summary="Do not leave setuid or setgid binaries in the image",
        rationale=(
            "A setuid binary runs as its owner, and the owner is root. In a container "
            "that correctly runs as an unprivileged user, it is the ready-made path "
            "back to uid 0 -- the one piece missing to turn a limited command "
            "execution into a complete one."
        ),
        controls=(CIS_4_8, OWASP_4, NIST_4_1_2),
    ),
)

_BY_RULE: dict[str, RuleMapping] = {mapping.rule_id: mapping for mapping in RULE_MAPPINGS}


def mapping_for(rule_id: str | None) -> RuleMapping | None:
    """The mapping for `rule_id`, or None when the rule is not catalogued.

    None is a legitimate answer, not a gap to paper over: a rule this
    catalogue does not cover must render without a citation rather than
    with a guessed one.
    """
    if not rule_id:
        return None
    return _BY_RULE.get(rule_id.strip().upper())


def controls_for(rule_id: str | None) -> tuple[Control, ...]:
    mapping = mapping_for(rule_id)
    return mapping.controls if mapping else ()


def references_for(rule_id: str | None) -> list[str]:
    """Citations as display strings, for serialisation and rendering."""
    return [str(control) for control in controls_for(rule_id)]
