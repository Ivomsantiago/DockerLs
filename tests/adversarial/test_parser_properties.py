"""Property tests (Hypothesis) for the two parsers a hostile string reaches.

The hand-written adversarial tests next to this file pin the shapes someone
thought of. These search for the ones nobody did, in the two places where a
wrong answer has repeatedly become a wrong *security verdict*:

* `image_reference` -- repository/tag/digest splitting. The DF013 round
  fixed a registry port hiding an unpinned base; F13 fixed two code paths
  disagreeing about tag-vs-digest. Both are invariants, so they are checked
  here as invariants rather than as a list of examples.
* `dockerfile_validator` -- its regexes, one of which CodeQL found to be a
  ReDoS. A regex is exactly the kind of code where "it returns the right
  answer" and "it returns at all" are separate questions.

Two of these found live defects, both fixed in the same commit and pinned
by the named regression tests at the bottom.
"""

from __future__ import annotations

import os
import time

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dockerls.domain.value_objects.image_reference import (
    is_registry_host,
    registry_host_of,
    split_repository_and_tag,
)
from dockerls.infrastructure import dockerfile_validator as dv
from dockerls.infrastructure.dockerfile_validator import DockerfileParser

# A generous per-example wall clock. These are pure-CPU string functions on
# inputs of at most a few hundred characters: a healthy one finishes in
# microseconds, and a backtracking one does not finish at all. The gap is
# wide enough that the bound is not flaky on a loaded CI runner.
#
# 500 examples per property keeps the whole file at a few seconds, which is
# what belongs in every run. A soak is the same properties with a bigger
# budget: `DOCKERLS_HYPOTHESIS_EXAMPLES=10000 pytest tests/adversarial/`.
_PROPERTY = settings(
    max_examples=int(os.environ.get("DOCKERLS_HYPOTHESIS_EXAMPLES", "500")),
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

#: Every character the parsers branch on: separators, shell metacharacters,
#: quote marks, the digest and tag punctuation, and a NUL for good measure.
_HOSTILE = "abcdxyzAZ09.:/@-_$ \t\\\"'|&;()#=+*?[]{}\n\x00"

_hostile_text = st.text(alphabet=_HOSTILE, max_size=60)


@st.composite
def _reference(draw: st.DrawFn) -> str:
    """References built from the pieces the splitter has to tell apart."""
    host = draw(
        st.sampled_from(
            [
                "",
                "docker.io/",
                "index.docker.io/",
                "localhost/",
                "localhost:5000/",
                "registry.internal:5000/",
                "ghcr.io/",
                "10.0.0.1:443/",
                # A second, host-shaped path segment: the shape that used to
                # produce a "tag" containing a slash.
                "a.io/b.io:5000/",
            ]
        )
    )
    path = draw(st.sampled_from(["app", "team/app", "a/b/c", "scratch", "node", "x_y-z.w"]))
    tag = draw(
        st.sampled_from(["", ":latest", ":1.0", ":latest-stable", ":LATEST", ":5000/x", ":"])
    )
    digest = draw(
        st.sampled_from(["", "@sha256:" + "a" * 64, "@sha256:short", "@sha256:", "@notadigest"])
    )
    return host + path + tag + digest


# ---------------------------------------------------------------------------
# image_reference: totality and the contract the docstring states
# ---------------------------------------------------------------------------


@given(st.one_of(_hostile_text, _reference()))
@_PROPERTY
def test_splitting_is_total(reference):
    """No input is an unhandled exception -- and none of it hangs."""
    started = time.perf_counter()
    repository, tag = split_repository_and_tag(reference)
    assert isinstance(repository, str)
    assert isinstance(tag, str)
    assert time.perf_counter() - started < 1.0


@given(st.one_of(_hostile_text, _reference()))
@_PROPERTY
def test_registry_host_is_total_and_is_a_prefix(reference):
    host = registry_host_of(reference)
    assert isinstance(host, str)
    if host:
        # The host is reported "as written" so an allowlist can match it; a
        # host that is not literally at the front of the reference would be
        # a different string than the one the pull will use.
        assert reference.strip().startswith(host)
        assert is_registry_host(host)
        assert host.lower() not in {"docker.io", "index.docker.io", "registry-1.docker.io"}


@given(st.one_of(_hostile_text, _reference()))
@_PROPERTY
def test_a_tag_never_contains_a_path_separator(reference):
    """Regression (found by this file): `a.io/b.io:5000/app` split as
    tag=`5000/app`.

    No Docker tag can contain `/` or `:`. A "tag" that does is a colon from
    somewhere else -- a registry port -- read as a tag separator, and
    `_is_moving_reference` then sees a non-empty, non-`latest` tag and
    reports the base as pinned. That is DF013's bug one path segment deeper.
    """
    _, tag = split_repository_and_tag(reference)
    assert "/" not in tag
    assert ":" not in tag


@given(st.one_of(_hostile_text, _reference()))
@_PROPERTY
def test_the_split_loses_nothing_but_the_separator(reference):
    """The two halves reconstruct the digest-free reference.

    The split may drop the `:` it split on and nothing else -- it never
    invents a character, and never silently discards part of the name. A
    dangling `app:` is the one place a colon disappears: an empty tag is no
    tag, and reading it as "no tag" is the conservative answer (DF001 then
    calls the base moving, which is what Docker would do with it).
    """
    body = reference.split("@", 1)[0]
    repository, tag = split_repository_and_tag(reference)
    assert body in (f"{repository}:{tag}", repository, f"{repository}:")


# ---------------------------------------------------------------------------
# The invariant F13 was about: one answer to "is this pinned?"
# ---------------------------------------------------------------------------


@given(_reference())
@_PROPERTY
def test_digest_pinning_and_tag_reading_never_disagree(reference):
    """The two readings of "does this reference move?" must agree.

    `_is_moving_reference` (DF001) short-circuits on a digest;
    `_check_base_image` decides `pinned_by_digest` with a substring test;
    `split_repository_and_tag` decides whether there is a tag at all. Two
    readings of the same question in the same binary is how one of them goes
    wrong without anyone noticing -- which is what F13 was.
    """
    moving = DockerfileParser._is_moving_reference(reference)
    _, tag = split_repository_and_tag(reference)

    if "@sha256:" in reference:
        # A digest fixes the bytes; nothing downstream may call it moving.
        assert moving is False
    elif "$" in reference:
        # An unexpanded ARG is not read, so it is not judged either way.
        assert moving is False
    elif not tag:
        # No tag and no digest is `:latest` by Docker's own default. Missing
        # this is the false negative that matters: it publishes a PASS.
        assert moving is True
    elif tag.lower() == "latest":
        assert moving is True


@given(_reference())
@_PROPERTY
def test_nothing_is_misread_as_digest_pinned(reference):
    """A reference with no digest is never treated as digest-pinned."""
    if "@sha256:" in reference:
        return
    assert DockerfileParser._is_moving_reference(reference) or bool(
        split_repository_and_tag(reference)[1]
    )


# ---------------------------------------------------------------------------
# dockerfile_validator: totality, and no regex that stops answering
# ---------------------------------------------------------------------------


def _all_patterns() -> dict[str, object]:
    patterns: dict[str, object] = {
        name: value
        for name, value in vars(dv).items()
        if name.isupper() and hasattr(value, "search")
    }
    patterns.update(
        {
            f"DockerfileParser.{name}": value
            for name, value in vars(DockerfileParser).items()
            if name.isupper() and hasattr(value, "search")
        }
    )
    patterns.update({f"_PACKAGE_MANAGERS[{pm}]": rx for pm, rx in dv._PACKAGE_MANAGERS.items()})
    return patterns


_PATTERNS = _all_patterns()


def test_the_pattern_sweep_actually_covers_the_patterns():
    """A guard on the guard: a renamed constant must not silently empty it."""
    assert len(_PATTERNS) >= 25
    assert "_SHELL_AT_HEAD" in _PATTERNS
    assert "_SETUID_BIT" in _PATTERNS
    assert "DockerfileParser.ENV_KV" in _PATTERNS


@given(st.text(alphabet=_HOSTILE, max_size=80))
@_PROPERTY
def test_no_dockerfile_pattern_backtracks_catastrophically(seed):
    """Every regex in the module answers in bounded time.

    `_SHELL_AT_HEAD` carried a catastrophic-backtracking shape CodeQL found
    (`\\S+=\\S+` around a single `=`). This sweeps the whole module rather
    than that one pattern: a hang here is a scanner that never reports.
    """
    for name, pattern in _PATTERNS.items():
        for candidate in (seed, seed * 8, seed + "!" * 60, " " * 60 + seed):
            started = time.perf_counter()
            pattern.search(candidate)  # type: ignore[attr-defined]
            elapsed = time.perf_counter() - started
            assert elapsed < 1.0, f"{name} took {elapsed:.3f}s on {candidate!r}"


@given(st.text(alphabet=_HOSTILE, max_size=80))
@_PROPERTY
def test_the_pipe_to_shell_check_answers_in_bounded_time(seed):
    for candidate in (seed, seed * 8, "curl https://x | " + seed * 6):
        started = time.perf_counter()
        result = dv._pipes_remote_script_to_shell(candidate)
        assert isinstance(result, bool)
        assert time.perf_counter() - started < 1.0


@given(st.text(alphabet=_HOSTILE, max_size=400))
@_PROPERTY
def test_parsing_arbitrary_text_is_total(content):
    """`parse` never raises on arbitrary bytes-as-text, and never hangs.

    It is handed whatever is in the file. An unhandled exception here is a
    Dockerfile that opted itself out of every rule at once -- the report
    shows a usage error, not an unchecked file.
    """
    started = time.perf_counter()
    info = DockerfileParser().parse(content)
    assert info.stages >= 1
    assert all(isinstance(port, int) for port in info.exposes_ports)
    assert time.perf_counter() - started < 2.0


@given(
    st.lists(
        st.sampled_from(
            [
                "FROM node:22-alpine",
                "FROM node@sha256:" + "a" * 64,
                "FROM registry.internal:5000/app",
                "FROM scratch",
                "FROM $BASE",
                "FROM builder AS final",
                "RUN sudo apt-get install -y curl",
                "RUN curl -fsSL https://x/i.sh | sh",
                "RUN chmod 4755 /bin/x",
                "ENV API_KEY=abc SAFE=1",
                "ARG TOKEN=abc",
                "USER app:1000",
                "USER 0",
                "EXPOSE 8080",
                "LABEL a=b",
                "HEALTHCHECK CMD x",
                'ENTRYPOINT ["/app"]',
                "COPY . /app",
                "ADD https://x/a.tar.gz /a",
                "RUN echo 'no sudo here' \\",
                "# comment",
                "",
                "   \\",
            ]
        ),
        max_size=25,
    )
)
@_PROPERTY
def test_parsing_shuffled_real_directives_is_total(lines):
    """Real directives in every order, including trailing continuations."""
    info = DockerfileParser().parse("\n".join(lines))
    assert info.stages >= 1
    if info.user_uid is not None:
        assert 0 <= info.user_uid <= 2**32 - 1


# ---------------------------------------------------------------------------
# Named regressions for what the properties above found
# ---------------------------------------------------------------------------


def test_a_second_host_shaped_segment_no_longer_hides_an_unpinned_base():
    """Regression: `a.io/b.io:5000/app` read as tag `5000/app`.

    A non-empty tag that is not `latest` made DF001 report the base as
    pinned, when the reference in fact carries no tag at all.
    """
    repository, tag = split_repository_and_tag("a.io/b.io:5000/app")
    assert (repository, tag) == ("a.io/b.io:5000/app", "")
    assert DockerfileParser._is_moving_reference("a.io/b.io:5000/app") is True


def test_a_registry_port_still_is_not_read_as_a_tag():
    """The DF013 case, still held by the narrower split."""
    assert split_repository_and_tag("registry.internal:5000/app") == (
        "registry.internal:5000/app",
        "",
    )
    assert split_repository_and_tag("registry.internal:5000/app:1.2") == (
        "registry.internal:5000/app",
        "1.2",
    )
    assert split_repository_and_tag("ghcr.io/org/app:latest-stable") == (
        "ghcr.io/org/app",
        "latest-stable",
    )


def test_an_oversized_port_does_not_abort_the_whole_validation():
    """Regression: `EXPOSE <4301 digits>` raised an unhandled ValueError.

    Python 3.11 refuses `int()` on a digit string that long. The exception
    escaped `parse`, so one line removed the file from every rule at once.
    """
    info = DockerfileParser().parse("FROM node:22-alpine\nEXPOSE " + "1" * 5000 + "\n")
    assert info.exposes_ports == []
    assert info.base_images == ["node:22-alpine"]


def test_an_oversized_uid_does_not_abort_the_whole_validation():
    info = DockerfileParser().parse("FROM node:22-alpine\nUSER app:" + "1" * 5000 + "\n")
    assert info.has_user_directive is True
    assert info.user_name == "app"
    assert info.user_uid is None


def test_a_padded_zero_uid_is_still_root():
    """Dropping the oversized value must not turn root into "no uid".

    `USER app:000...0` is uid 0. Reading it as "no uid given" would let it
    pass DF002 -- trading a crash for a false PASS, which is worse.
    """
    info = DockerfileParser().parse("FROM node:22-alpine\nUSER app:" + "0" * 5000 + "\n")
    assert info.user_uid == 0


def test_a_real_port_is_unaffected():
    info = DockerfileParser().parse("FROM node:22-alpine\nEXPOSE 8080\nEXPOSE 443\n")
    assert info.exposes_ports == [8080, 443]
