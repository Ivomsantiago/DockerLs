"""Run an external scanner and guarantee the child process is reaped.

`asyncio.wait_for(proc.communicate(), timeout=...)` cancels the *await*, not
the process. On timeout the coroutine raises and the caller returns a
`TIMEOUT` scan result, while the `trivy` or `grype` process it started keeps
running: still downloading, still matching, still holding the exclusive
BoltDB lock on its Trivy cache directory -- which is precisely the
contention `TrivyCachePool` exists to eliminate. With `--workers 10` a run
that trips its timeout could leave ten scanners behind, outliving the CLI
that spawned them and slowing down the next invocation that tries to take
the same lock.

The same applies to cancellation: Ctrl-C unwinds the event loop, and without
an explicit kill the children survive it.

`run_capture` closes both holes. Every path out -- success, timeout,
cancellation, or an error raised inside the body -- goes through a
`finally` that terminates the process and *waits* for it, so the process
table is clean before the caller sees the outcome.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Most a scanner may write to one stream before the run is abandoned.
#: `communicate()` accumulates the whole output in memory, so an image with a
#: pathological number of findings -- or a scanner that has been tampered
#: with -- was read without any bound at all. 256 MiB is far above any real
#: Trivy or Grype JSON (a very noisy image produces single-digit MiB) and far
#: below what would put the host under memory pressure.
MAX_OUTPUT_BYTES = 256 * 1024 * 1024

#: Read granularity. Large enough that the loop is not the bottleneck, small
#: enough that the cap is enforced promptly.
_CHUNK_BYTES = 256 * 1024

#: `--version` answers instantly or not at all; a scanner that hangs on it
#: must not hold up a run that could still proceed without knowing which
#: version it is talking to.
VERSION_TIMEOUT_SECONDS = 10.0

# How long a signalled scanner is given to exit on its own before SIGKILL.
# Trivy and Grype flush and exit promptly; this only bounds the pathological
# case of a process ignoring SIGTERM.
_TERMINATE_GRACE_SECONDS = 5.0


#: Se dá para desligar core dumps no filho. Só POSIX tem `resource`, e a
#: ausência não é erro: no Windows o mecanismo simplesmente não existe.
try:  # pragma: no cover - depende da plataforma
    import resource

    _CAN_LIMIT_CORE = True
except ImportError:  # pragma: no cover - Windows
    _CAN_LIMIT_CORE = False


def _no_core_dumps() -> None:  # pragma: no cover - roda no processo filho
    """Desliga core dumps no scanner, antes do `exec`.

    Um scanner que falha um pull autenticado tem, na memória, o token que
    usou. Se ele receber um SIGSEGV com core dump ligado, esse token vai
    para o disco num arquivo que ninguém redige e quase ninguém audita --
    e este projeto já redige log, evidência e exportação justamente para
    isso não acontecer. Fechar a última porta custa duas linhas.

    `RLIMIT_AS` continuaria sendo a escolha errada aqui e por isso não está:
    o Trivy é um binário Go, e o runtime do Go reserva um espaço de
    endereçamento virtual enorme na largada. Limitar isso mata o processo na
    inicialização, transformando uma medida de segurança numa falha de scan.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class OutputTooLargeError(RuntimeError):
    """A scanner wrote more than `MAX_OUTPUT_BYTES` to one stream.

    Raised rather than truncated: a JSON document cut in half does not parse,
    and a scan whose output could not be read in full has not been measured.
    Callers classify it as `INVALID_OUTPUT`, which is already a non-verified
    state -- the failure mode this codebase is built around.
    """


async def run_capture(
    argv: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    """Run `argv`, returning ``(returncode, stdout, stderr)``.

    `argv[0]` must already be an absolute path (see
    `dockerls.utils.executables.resolve_executable`); nothing here goes
    through a shell, and the arguments are passed as a list, so no quoting
    or escaping is involved at any point.

    Raises `TimeoutError` if the process does not finish within `timeout`,
    and `OutputTooLargeError` if either stream exceeds `max_output_bytes`.
    In every one of those cases -- and on cancellation -- the process is
    killed and reaped before the exception propagates.
    """
    proc = await asyncio.create_subprocess_exec(  # noqa: S603 -- argv list, no shell
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        preexec_fn=_no_core_dumps if _CAN_LIMIT_CORE else None,  # noqa: PLW1509
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            _communicate_capped(proc, max_output_bytes), timeout=timeout
        )
    finally:
        await _reap(proc, argv[0])
    return proc.returncode or 0, stdout, stderr


async def _communicate_capped(proc: asyncio.subprocess.Process, limit: int) -> tuple[bytes, bytes]:
    """`communicate()` with a ceiling on each stream.

    Both streams are drained concurrently for the same reason the stdlib
    does it: a child that fills the stderr pipe while the parent is reading
    stdout deadlocks, and a scanner that has just failed writes a great deal
    to stderr.
    """
    # `getattr` rather than attribute access: the fallback exists precisely
    # for process objects that do not model the stream readers at all, and
    # those raise AttributeError rather than answering None.
    stdout_reader = getattr(proc, "stdout", None)
    stderr_reader = getattr(proc, "stderr", None)
    if not isinstance(stdout_reader, asyncio.StreamReader) or not isinstance(
        stderr_reader, asyncio.StreamReader
    ):
        # A process object that does not expose stream readers -- a test
        # double modelling the documented `communicate()` contract, or a
        # future runner that pipes differently. Fall back rather than
        # refuse: `communicate()` is the interface everything implements,
        # and a real child created with PIPE above always has the readers,
        # so the ceiling applies wherever it can actually be exceeded.
        result: tuple[bytes, bytes] = await proc.communicate()
        return result

    stdout, stderr = await asyncio.gather(
        _read_capped(stdout_reader, limit, "stdout"),
        _read_capped(stderr_reader, limit, "stderr"),
    )
    await proc.wait()
    return stdout, stderr


async def _read_capped(stream: asyncio.StreamReader, limit: int, name: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise OutputTooLargeError(
                f"scanner wrote more than {limit} bytes to {name}; output discarded"
            )
        chunks.append(chunk)


async def _reap(proc: asyncio.subprocess.Process, name: str) -> None:
    """Terminate `proc` if it is still running, then wait for it.

    A no-op on the normal path: `communicate()` already returned, so
    `returncode` is set. Shielded from cancellation so that a Ctrl-C
    arriving *during* cleanup cannot skip the kill it is here to perform.
    """
    if proc.returncode is not None:
        return
    logger.warning(f"Killing unfinished subprocess {name} (pid {proc.pid})")
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=_TERMINATE_GRACE_SECONDS))
    except (TimeoutError, asyncio.CancelledError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.shield(proc.wait())
    finally:
        _close_transport(proc)


def _close_transport(proc: asyncio.subprocess.Process) -> None:
    """Release the child's pipes now rather than at garbage-collection time.

    A process killed mid-write leaves its transport holding open pipes. The
    transport closes them in `__del__`, and if that runs after the event loop
    is gone -- which is exactly what happens when the kill is the last thing
    a command does -- asyncio raises "Event loop is closed" from a
    destructor, where nothing can handle it.

    The transport is not part of the public `Process` API, so it is reached
    defensively: a Python release that renames it, or a process double that
    never had one, simply skips this and falls back to the old behaviour.
    """
    transport = getattr(proc, "_transport", None)
    close = getattr(transport, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()
