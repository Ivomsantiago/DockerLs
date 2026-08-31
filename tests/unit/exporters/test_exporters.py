import csv
import io
import json

import pytest

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exporters.csv_exporter import CSVExporter
from dockerls.exporters.factory import ExporterFactory
from dockerls.exporters.html_exporter import HTMLExporter
from dockerls.exporters.json_exporter import JSONExporter
from dockerls.exporters.markdown_exporter import MarkdownExporter
from dockerls.exporters.sarif_exporter import SARIFExporter


@pytest.fixture
def analysis_result():
    img = DockerImage(name="node", tag="22-alpine", is_official=True)
    scan = ScanResult(image_reference="node:22-alpine")
    analysis = ImageAnalysis(
        image=img,
        scan=scan,
        security_score=98.0,
        tier="A",
        remediation_score=100,
    )
    return AnalysisResult(
        query="node",
        total_tags_scanned=50,
        baseline_met=True,
        recommendations=[analysis],
    )


class TestJSONExporter:
    def test_export_string(self, analysis_result):
        exporter = JSONExporter()
        output = exporter.export_string(analysis_result)
        data = json.loads(output)
        assert data["query"] == "node"
        assert data["baseline_met"] is True


class TestCSVExporter:
    def test_export_string(self, analysis_result):
        exporter = CSVExporter()
        output = exporter.export_string(analysis_result)
        assert "node" in output
        assert "22-alpine" in output
        assert "Image,Tag,Score" in output

    def test_sanitizes_formula_injection_in_external_fields(self, analysis_result):
        """A malicious image name starting with '=' must not be interpreted
        as a formula by Excel/Sheets: it must be prefixed with a leading
        apostrophe before being written to the CSV cell."""
        malicious_name = "=cmd|'/c calc'!A1"
        analysis_result.recommendations[0].image.name = malicious_name
        exporter = CSVExporter()
        output = exporter.export_string(analysis_result)
        rows = list(csv.reader(io.StringIO(output)))
        header, row = rows[0], rows[1]
        assert row[header.index("Image")] == f"'{malicious_name}"

    def test_legitimate_name_is_unaffected(self, analysis_result):
        exporter = CSVExporter()
        output = exporter.export_string(analysis_result)
        rows = list(csv.reader(io.StringIO(output)))
        header, row = rows[0], rows[1]
        assert row[header.index("Image")] == "node"
        assert row[header.index("Tag")] == "22-alpine"


class TestHTMLExporter:
    def test_export_string(self, analysis_result):
        exporter = HTMLExporter()
        output = exporter.export_string(analysis_result)
        assert "<html" in output
        assert "node:22-alpine" in output
        assert "DockerLs" in output


class TestMarkdownExporter:
    def test_export_string(self, analysis_result):
        exporter = MarkdownExporter()
        output = exporter.export_string(analysis_result)
        assert "# DockerLs" in output
        assert "node:22-alpine" in output


class TestSARIFExporter:
    def test_export_string_is_valid_sarif(self):
        img = DockerImage(name="node", tag="22-alpine", is_official=True)
        vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            severity=Severity.HIGH,
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
        )
        scan = ScanResult(image_reference="node:22-alpine", vulnerabilities=[vuln])
        analysis = ImageAnalysis(
            image=img,
            scan=scan,
            security_score=80.0,
            tier="B",
            remediation_score=100,
        )
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=False,
            alternatives=[analysis],
        )
        exporter = SARIFExporter()
        output = json.loads(exporter.export_string(result))
        assert output["version"] == "2.1.0"
        run = output["runs"][0]
        assert run["tool"]["driver"]["name"] == "DockerLs"
        assert run["results"][0]["ruleId"] == "CVE-2024-0001"

    def test_export_string_empty_result(self, analysis_result):
        exporter = SARIFExporter()
        output = json.loads(
            exporter.export_string(
                AnalysisResult(query="x", total_tags_scanned=0, baseline_met=False)
            )
        )
        assert output["runs"][0]["results"] == []


class TestExporterFactory:
    def test_create_json(self):
        e = ExporterFactory.create("json")
        assert isinstance(e, JSONExporter)

    def test_create_csv(self):
        e = ExporterFactory.create("csv")
        assert isinstance(e, CSVExporter)

    def test_create_html(self):
        e = ExporterFactory.create("html")
        assert isinstance(e, HTMLExporter)

    def test_create_markdown(self):
        e = ExporterFactory.create("markdown")
        assert isinstance(e, MarkdownExporter)

    def test_create_md(self):
        e = ExporterFactory.create("md")
        assert isinstance(e, MarkdownExporter)

    def test_create_sarif(self):
        e = ExporterFactory.create("sarif")
        assert isinstance(e, SARIFExporter)

    def test_unsupported(self):
        with pytest.raises(ValueError, match="Unsupported format"):
            ExporterFactory.create("xml")
