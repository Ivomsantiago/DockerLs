from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis


class HTMLExporter(ExporterInterface):
    def export_string(self, result: AnalysisResult) -> str:
        items = result.recommendations or result.alternatives
        rows = "\n".join(self._row(a) for a in items)
        status = "Baseline Met" if result.baseline_met else "Alternative Recommendations"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DockerLs Report - {_esc(result.query)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #fafafa; color: #1a1a1a; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: .5rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
.note {{ font-size: 0.9em; opacity: 0.8; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #333; color: #fff; }}
tr:nth-child(even) {{ background: #f2f2f2; }}
.s {{ color: #16a34a; font-weight: bold; }}
.a {{ color: #2563eb; font-weight: bold; }}
.b {{ color: #d97706; font-weight: bold; }}
.c {{ color: #dc2626; font-weight: bold; }}
.info {{ background: #fff; padding: 1rem; border: 1px solid #ddd;
  border-radius: 4px; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>DockerLs Security Report</h1>
<div class="info">
<p><strong>Query:</strong> {_esc(result.query)}</p>
<p><strong>Tags Scanned:</strong> {result.total_tags_scanned}</p>
<p><strong>Status:</strong> {status}</p>
</div>
<table>
<thead><tr>
<th>Image</th><th>Source</th><th>Score</th><th>Tier</th>
<th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
<th>Fixable</th><th>Remediation</th><th>EOL</th>
<th title="higher is better">Hardening</th>
<th title="LOWER is better">Attack Surface</th><th>Confidence</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
{self._why(result)}
<p class="note">Hardening and attack surface are scored over the facts that could be
determined about each image; "n/a" means too little was determined for a number to
mean anything. Neither is summed into the security score: a well-configured image with
CRITICAL findings is a well-configured vulnerable image.</p>
</body>
</html>"""

    def _why(self, result: AnalysisResult) -> str:
        """The case for the top pick, so the ranking is auditable in the report."""
        items = result.recommendations or result.alternatives
        if not items:
            return ""
        best = items[0]
        reasons = "".join(f"<li>{_esc(reason)}</li>" for reason in best.why)
        costs = "".join(f"<li>{_esc(cost)}</li>" for cost in best.trade_offs)
        pinned = (
            f"<p><strong>Pin to:</strong> <code>{_esc(best.pinned_reference)}</code></p>"
            if best.image.digest_known
            else ""
        )
        return (
            f"<h2>Why {_esc(best.image.full_reference)}?</h2>"
            f"<ul>{reasons}</ul>"
            + (f"<h3>Trade-offs</h3><ul>{costs}</ul>" if costs else "")
            + f"<p><strong>Confidence:</strong> {_esc(best.confidence.value)} "
            f"({_esc('; '.join(best.confidence_reasons))})</p>" + pinned
        )

    def _row(self, a: ImageAnalysis) -> str:
        t = a.tier.lower()
        return (
            f"<tr><td>{_esc(a.image.full_reference)}</td>"
            f"<td>{_esc(a.image.source)}</td><td>{a.security_score}</td>"
            f'<td class="{t}">{a.tier}</td>'
            f"<td>{a.scan.critical_count}</td><td>{a.scan.high_count}</td>"
            f"<td>{a.scan.medium_count}</td><td>{a.scan.low_count}</td>"
            f"<td>{a.scan.fixable_count}</td><td>{a.remediation_score}/100</td>"
            f"<td>{'Yes' if a.is_eol else 'No'}</td>"
            f"<td>{f'{a.hardening.score:.0f}' if a.hardening.reportable else 'n/a'}</td>"
            f"<td>{f'{a.attack_surface.score:.0f}' if a.attack_surface.reportable else 'n/a'}</td>"
            f"<td>{self._confidence_cell(a)}</td></tr>"
        )

    @staticmethod
    def _confidence_cell(a: ImageAnalysis) -> str:
        """The confidence value, with its own reasons -- every row, not
        only the first UNVERIFIED one in the report.

        A bare "UNVERIFIED" on row two reads as if nothing is wrong, right
        next to a row that explained itself; the project's own rule against
        presenting absence of measurement as safety applies here just as
        much as it does to the first row. `confidence_reasons` is the same
        field the "Why" section below already reads for the top pick.
        """
        cell = _esc(a.confidence.value)
        if a.confidence_reasons:
            cell += f' <span class="note">({_esc("; ".join(a.confidence_reasons))})</span>'
        return cell


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
