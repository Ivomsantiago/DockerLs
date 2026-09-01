from __future__ import annotations

import json
from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import AnalysisResult


class JSONExporter(ExporterInterface):
    def export_string(self, result: AnalysisResult) -> str:
        return json.dumps(result.model_dump(), indent=2, default=str)
