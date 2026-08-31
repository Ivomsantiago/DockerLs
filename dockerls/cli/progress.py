from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType

    from rich.status import Status


def scan_status(message: str) -> Status:
    """A transient one-line stderr spinner for the commands that have no
    per-image `RichScanObserver` (analyze, verify, compare, search, export,
    build).

    Before this, `use_case.execute(...)` in those commands ran in total
    silence: nothing was printed between the command starting and its final
    table, however long that took -- and on a first run, "however long"
    includes a several-hundred-MB vulnerability database download. A silent
    terminal for a minute or more reads as a hang, not as work in progress.

    A fresh stderr `Console` is used rather than the command's own (stdout)
    console so this can never interleave with `--format json` output: Rich
    already no-ops a `Status` against a non-terminal (a pipe, a CI log)
    instead of spamming it, so this is safe unconditionally.
    """
    return Console(stderr=True).status(message, spinner="dots")


class RichScanObserver:
    """Renders scan progress as a single self-updating line.

    Exactly one `Progress` (one Rich live display) exists per run, and it
    renders to **stderr** while results are printed to stdout. That split is
    what makes duplication structurally impossible: the live region and the
    results stream are different file objects, so a result can never be
    drawn into a progress frame, and piping stdout leaves the progress
    display on the terminal where it belongs.

    Anything that writes through `sys.stdout`/`sys.stderr` during the run
    (a stray print, a loguru console sink) is captured by Rich and re-emitted
    above the bar rather than tearing through the live region.
    """

    def __init__(self, console: Console | None = None, enabled: bool = True):
        # Default to a dedicated stderr console so the caller's stdout
        # console is never shared with the live display.
        self._console = console if console is not None else Console(stderr=True)
        self._enabled = enabled
        self._progress: Progress | None = None
        self._task_id: TaskID | None = None
        self._total = 0
        self._done = 0
        self._entered = False

    @property
    def progress(self) -> Progress | None:
        """The single live display, or None when disabled/not started."""
        return self._progress

    def __enter__(self) -> RichScanObserver:
        if self._entered:
            raise RuntimeError(
                "RichScanObserver is not re-entrant: a second live display "
                "would render a duplicate progress bar"
            )
        self._entered = True
        if self._enabled:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=24),
                TimeElapsedColumn(),
                console=self._console,
                transient=True,
                # Stray writes get rendered above the bar instead of
                # corrupting the live region into a duplicate.
                redirect_stdout=True,
                redirect_stderr=True,
                refresh_per_second=8,
            )
            self._progress.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
        self._task_id = None

    def _describe(self, image_reference: str) -> str:
        return f"Scanning {image_reference}... [{self._done + 1}/{self._total}]"

    def phase(self, description: str) -> None:
        if self._progress is None:
            return
        if self._task_id is None:
            self._task_id = self._progress.add_task(description, total=None)
        else:
            self._progress.update(self._task_id, description=description)

    def phase_result(self, title: str, facts: Sequence[tuple[str, str]]) -> None:
        """Print what a phase produced, above the live progress line.

        Rendered as a small tree so a run reads as a sequence of accounted
        steps rather than a spinner that may or may not be stuck:

            Discovering tags
            ├─ found            100
            ├─ unique digests    84
            └─ duplicates        16

        Written through `self._console` (stderr), so it never mixes with
        results on stdout and `dockerls recommend > out.txt` still yields a
        clean file. When the display is disabled -- `--no-progress`, or
        `--format json` -- nothing is emitted at all.
        """
        if self._progress is None or not facts:
            return
        width = max(len(label) for label, _ in facts)
        # Leading blank line: consecutive phases run together otherwise, and
        # in a CI log they are the only structure the reader gets.
        lines = ["", f"[bold]{title}[/bold]"]
        for index, (label, value) in enumerate(facts):
            branch = "└─" if index == len(facts) - 1 else "├─"
            lines.append(f"[dim]{branch}[/dim] {label:<{width}}  [cyan]{value}[/cyan]")
        # `Progress.console.print` routes through the live display, which
        # moves the bar down and prints above it instead of tearing it.
        self._progress.console.print("\n".join(lines))

    def start(self, total: int) -> None:
        self._total = total
        self._done = 0
        if self._progress is None:
            return
        if self._task_id is None:
            self._task_id = self._progress.add_task("Scanning...", total=total)
        else:
            self._progress.update(self._task_id, total=total, completed=0)

    def scanning(self, image_reference: str) -> None:
        if self._progress is None or self._task_id is None:
            return
        self._progress.update(self._task_id, description=self._describe(image_reference))

    def finished(self, image_reference: str, ok: bool) -> None:  # noqa: ARG002
        self._done += 1
        if self._progress is None or self._task_id is None:
            return
        self._progress.update(self._task_id, completed=self._done)
