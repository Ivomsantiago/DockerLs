"""`doctor` and `health` must detect the failure they exist to detect.

Audit findings: `health` probed `https://hub.docker.com/v2/`, which answers
404 by design, so it reported the Hub as degraded on every healthy run --
an alarm that is always on tells you nothing. It also always exited 0, so
it could not gate anything.
"""

from __future__ import annotations

import httpx
from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.cli.commands import health as health_cmd

runner = CliRunner()

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _responder(status_by_host):
    def handler(request: httpx.Request) -> httpx.Response:
        for host, status in status_by_host.items():
            if host in request.url.host:
                if status == "error":
                    raise httpx.ConnectError("network unreachable")
                return httpx.Response(status, json={}, request=request)
        return httpx.Response(200, json={}, request=request)

    return httpx.MockTransport(handler)


def _run_health(monkeypatch, transport):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return runner.invoke(app, ["health"])


class TestHealthProbesRealEndpoints:
    def test_docker_hub_probe_is_not_a_404_by_design(self):
        """The old probe could never return 2xx, so the check was noise."""
        url = health_cmd.ENDPOINTS["Docker Hub API"]
        assert url != "https://hub.docker.com/v2/"
        assert "/repositories/" in url

    def test_all_services_healthy_reports_ok_and_exits_zero(self, monkeypatch):
        result = _run_health(monkeypatch, _responder({}))

        assert result.exit_code == health_cmd.EXIT_HEALTHY
        assert "All services reachable" in result.stdout
        assert result.stdout.count("OK (200)") == len(health_cmd.ENDPOINTS)


class TestHealthDetectsOutages:
    def test_unreachable_service_is_reported_and_exits_nonzero(self, monkeypatch):
        result = _run_health(monkeypatch, _responder({"hub.docker.com": "error"}))

        assert result.exit_code == health_cmd.EXIT_DEGRADED
        assert "Unreachable" in result.stdout
        assert "degraded" in result.stdout

    def test_total_network_outage_is_reported_for_every_service(self, monkeypatch):
        all_hosts = (
            "hub.docker.com",
            "cgr.dev",
            "gcr.io",
            "endoflife.date",
            "cisa.gov",
            "first.org",
            "gitlab.com",
        )
        result = _run_health(monkeypatch, _responder(dict.fromkeys(all_hosts, "error")))

        assert result.exit_code == health_cmd.EXIT_DEGRADED
        assert result.stdout.count("Unreachable") == len(health_cmd.ENDPOINTS)

    def test_http_error_status_counts_as_degraded(self, monkeypatch):
        result = _run_health(monkeypatch, _responder({"hub.docker.com": 503}))

        assert result.exit_code == health_cmd.EXIT_DEGRADED
        assert "HTTP 503" in result.stdout

    def test_one_outage_does_not_mask_the_healthy_ones(self, monkeypatch):
        result = _run_health(monkeypatch, _responder({"cisa.gov": "error"}))

        assert "OK (200)" in result.stdout
        assert "Unreachable" in result.stdout


class TestDoctorDetectsMissingScanners:
    def test_missing_scanners_are_reported_and_flagged(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        result = runner.invoke(app, ["doctor"])

        assert "Not found" in result.stdout
        assert "cannot measure anything" in result.stdout
        # It gates as well as reports: exiting 0 here let a runner with no
        # scanner installed pass its own pre-flight check.
        assert result.exit_code == 1

    def test_present_scanners_report_available(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        result = runner.invoke(app, ["doctor"])

        assert "Available" in result.stdout
        assert result.stdout.count("Not found") == 0
