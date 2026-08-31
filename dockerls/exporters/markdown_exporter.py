from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class MarkdownExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    def export_string(self, result: AnalysisResult) -> str:
        items = result.recommendations or result.alternatives
        status = "Baseline Met" if result.baseline_met else "Alternative Recommendations"
        lines = [
            "# DockerLs Security Report",
            "",
            f"**Query:** {result.query}",
            f"**Tags Scanned:** {result.total_tags_scanned}",
            f"**Status:** {status}",
            "",
            "## Results",
            "",
            "| Image | Source | Score | Tier | Critical | High | Medium | Low | Fixable "
            "| Remediation | EOL | Hardening | Attack Surface | Confidence |",
            "|-------|--------|-------|------|----------|------|--------|-----|---------"
            "|-------------|-----|-----------|----------------|------------|",
        ]
        for a in items:
            eol = "Yes" if a.is_eol else "No"
            hardening = f"{a.hardening.score:.0f}" if a.hardening.reportable else "n/a"
            surface = f"{a.attack_surface.score:.0f}" if a.attack_surface.reportable else "n/a"
            confidence = a.confidence.value
            # Every row states its own reason, not only the first
            # UNVERIFIED one -- a bare "UNVERIFIED" on a later row read as
            # if nothing was wrong with it. `confidence_reasons` is the
            # same field the "Why this image" section below already reads
            # for the top pick.
            if a.confidence_reasons:
                confidence += f" ({'; '.join(a.confidence_reasons)})"
            lines.append(
                f"| {a.image.full_reference} | {a.image.source} | {a.security_score} | {a.tier} "
                f"| {a.scan.critical_count} | {a.scan.high_count} "
                f"| {a.scan.medium_count} | {a.scan.low_count} "
                f"| {a.scan.fixable_count} | {a.remediation_score}/100 | {eol} "
                f"| {hardening} | {surface} | {confidence} |"
            )

        if items:
            best = items[0]
            lines += ["", "## Why this image", ""]
            lines += [f"- {reason}" for reason in best.why] or ["- (no reasons recorded)"]
            if best.trade_offs:
                lines += ["", "### Trade-offs", ""]
                lines += [f"- {cost}" for cost in best.trade_offs]
            if best.image.digest_known:
                lines += ["", f"**Pin to:** `{best.pinned_reference}`"]
            lines += [
                "",
                f"**Confidence:** {best.confidence.value} ({'; '.join(best.confidence_reasons)})",
                "",
                "> Hardening is scored over the facts that could be determined, and its "
                "coverage is reported with it. It is never summed into the security score: "
                "a well-configured image with CRITICAL findings is a well-configured "
                "vulnerable image.",
            ]

        if items and items[0].recommendation:
            rec = items[0].recommendation
            lines += [
                "",
                "## Top Recommendation",
                "",
                f"**Image:** {rec.image_reference}",
                f"**Score:** {rec.security_score}",
                f"**Summary:** {rec.summary}",
            ]
            if rec.steps:
                lines += ["", "### Remediation Steps", ""]
                for s in rec.steps:
                    desc = s.description
                    if s.from_value and s.to_value:
                        desc += f" ({s.from_value} -> {s.to_value})"
                    lines.append(f"{s.step_number}. {desc}")

        lines.append("")
        return "\n".join(lines)
