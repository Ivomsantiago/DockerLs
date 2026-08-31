from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult

#: Leading characters that Excel/Sheets can interpret as the start of a
#: formula when a CSV cell is opened -- '=', '+', '-', '@', tab, and CR.
#: A cell built from external/attacker-influenceable data (image name, tag,
#: digest, source, ...) that starts with one of these is CSV/formula
#: injection waiting to happen.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value: str) -> str:
    """Neutralize CSV/formula injection in a string cell from external data.

    Prefixes the value with a leading apostrophe when it starts with a
    character Excel/Sheets would read as the start of a formula. Excel and
    Sheets both treat a cell that begins with `'` as literal text, so the
    apostrophe defuses the formula while leaving the rest of the value
    intact and visible to the reader.
    """
    if value.startswith(_FORMULA_TRIGGER_CHARS):
        return f"'{value}"
    return value


class CSVExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    def export_string(self, result: AnalysisResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Image",
                "Tag",
                "Score",
                "Tier",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Fixable",
                "Remediation Score",
                "EOL",
                "LTS",
                # Appended, never inserted: a consumer indexing by column
                # position keeps working, and one reading the header gets
                # the new dimensions.
                "Source",
                "Digest",
                "Pinned Reference",
                "Hardening",
                "Hardening Coverage",
                "Attack Surface",
                "Confidence",
                "Production Ready",
                "Readiness Blockers",
                "EOL Status",
                "Cross Validation",
            ]
        )
        for a in result.recommendations or result.alternatives:
            writer.writerow(
                [
                    _sanitize_cell(a.image.name),
                    _sanitize_cell(a.image.tag),
                    a.security_score,
                    a.tier,
                    a.scan.critical_count,
                    a.scan.high_count,
                    a.scan.medium_count,
                    a.scan.low_count,
                    a.scan.fixable_count,
                    a.remediation_score,
                    a.is_eol,
                    a.is_lts,
                    _sanitize_cell(a.image.source),
                    _sanitize_cell(a.image.digest),
                    _sanitize_cell(a.pinned_reference),
                    # "" rather than 0 when coverage was too thin: a zero
                    # here would be read as "no hardening", which is the
                    # opposite of "not determined".
                    a.hardening.score if a.hardening.reportable else "",
                    a.hardening.coverage,
                    a.attack_surface.score if a.attack_surface.reportable else "",
                    a.confidence.value,
                    a.production_ready,
                    # Codes, semicolon-separated: a CSV consumer gating on
                    # "NOT_MEASURED" should not have to parse a sentence.
                    ";".join(a.readiness_blockers),
                    a.eol_status.value,
                    a.cross_validation,
                ]
            )
        return output.getvalue()
