from __future__ import annotations

from pathlib import Path

from dockerls.application.use_cases.build_image import (
    BuildImageUseCase,
    ScanResult,
)
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates


def test_insert_instruction_before_user():
    content = 'FROM node:22-alpine\nWORKDIR /app\nUSER node\nCMD ["node", "index.js"]\n'
    inst = "RUN apk upgrade --no-cache"
    updated = BuildImageUseCase._insert_instruction(content, inst)
    lines = updated.splitlines()
    assert "RUN apk upgrade --no-cache" in lines
    user_idx = lines.index("USER node")
    inst_idx = lines.index("RUN apk upgrade --no-cache")
    assert inst_idx < user_idx


def test_insert_instruction_after_from_when_no_user():
    content = 'FROM alpine:3.20\nWORKDIR /app\nCMD ["sh"]\n'
    inst = "RUN apk upgrade --no-cache"
    updated = BuildImageUseCase._insert_instruction(content, inst)
    lines = updated.splitlines()
    assert lines[0] == "FROM alpine:3.20"
    assert lines[1] == "RUN apk upgrade --no-cache"


def test_derive_remediated_dockerfile_applies_os_upgrade(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text('FROM node:22-alpine\nUSER node\nCMD ["node", "app.js"]\n', encoding="utf-8")

    validator = DockerfileValidator()
    templates = HardeningTemplates()
    use_case = BuildImageUseCase(validator, templates)

    scan_res = ScanResult(
        scan_tool="trivy",
        vulnerabilities=[
            {
                "cve_id": "CVE-2026-1",
                "package": "libssl3",
                "fixed_version": "3.3.1",
                "severity": "HIGH",
            }
        ],
        critical=0,
        high=1,
    )

    remediated_path, applied = use_case._derive_and_write_remediated_dockerfile(
        str(tmp_path), str(df), scan_res, 1
    )

    assert Path(remediated_path).exists()
    assert len(applied) == 1
    assert "Applied Alpine OS security upgrade" in applied[0]
    content = Path(remediated_path).read_text(encoding="utf-8")
    assert "RUN apk upgrade --no-cache" in content


def test_derive_remediated_dockerfile_applies_npm_upgrade(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text('FROM node:22-alpine\nUSER node\nCMD ["node", "app.js"]\n', encoding="utf-8")

    validator = DockerfileValidator()
    templates = HardeningTemplates()
    use_case = BuildImageUseCase(validator, templates)

    scan_res = ScanResult(
        scan_tool="trivy",
        vulnerabilities=[
            {
                "cve_id": "CVE-2026-NPM",
                "package": "npm",
                "fixed_version": "10.8.0",
                "severity": "HIGH",
            }
        ],
        critical=0,
        high=1,
    )

    remediated_path, applied = use_case._derive_and_write_remediated_dockerfile(
        str(tmp_path), str(df), scan_res, 1
    )

    assert Path(remediated_path).exists()
    # A mensagem descreve a ação, não promete o resultado: "latest patched
    # release" era uma afirmação sobre o efeito de um comando que ainda não
    # rodou, e quem mede é o scan da próxima rodada.
    assert any("npm install -g npm@latest" in a for a in applied)
    assert not any("patched" in a for a in applied)
    content = Path(remediated_path).read_text(encoding="utf-8")
    assert "RUN npm install -g npm@latest" in content
