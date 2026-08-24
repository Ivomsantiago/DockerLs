"""Conhecimento especializado de ecossistemas, runtimes e particularidades de segurança."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EcosystemInsight:
    ecosystem: str
    version: str
    runtime_features: list[str] = field(default_factory=list)
    base_distro_advice: list[str] = field(default_factory=list)
    security_guidelines: list[str] = field(default_factory=list)
    common_pitfalls: list[str] = field(default_factory=list)
    recommended_dockerfile_snippets: list[str] = field(default_factory=list)


#: Nome exato do repositório -> ecossistema. Consultado antes das palavras
#: soltas porque um nome exato não erra: `mongo` não é Go, e `maven` é Java
#: mesmo sem a palavra "java" aparecer em lugar nenhum.
_ECOSYSTEM_BY_NAME: dict[str, str] = {
    "node": "node",
    "nodejs": "node",
    "bun": "node",
    "deno": "node",
    "python": "python",
    "python3": "python",
    "pypy": "python",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    # Ferramentas de build são o ecossistema que constroem: quem roda `maven`
    # está num projeto Java, e a alternativa endurecida que interessa é a de
    # Java. Sem esta linha, `maven` caía em "generic" e não recebia conselho
    # nenhum -- e ferramenta de build é exatamente onde um projeto de verdade
    # começa o Dockerfile.
    "maven": "java",
    "gradle": "java",
    "ant": "java",
    "sbt": "java",
    "tomcat": "java",
    "jetty": "java",
    "jdk": "java",
    "jre": "java",
    "openjdk": "java",
    "temurin": "java",
    "eclipse-temurin": "java",
    "corretto": "java",
    "amazoncorretto": "java",
    "php": "php",
    "composer": "php",
    "ruby": "ruby",
    "jruby": "ruby",
    "dotnet": "dotnet",
    "aspnet": "dotnet",
}

#: Fragmentos, para nomes compostos que nenhuma tabela cobre inteiramente
#: (`nodejs22-debian12`, `python3-debian12`). A ordem importa: o primeiro que
#: casar vence, e os mais específicos vêm antes.
_ECOSYSTEM_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("nodejs", "node"),
    ("node", "node"),
    ("python", "python"),
    ("golang", "go"),
    ("rust", "rust"),
    ("temurin", "java"),
    ("openjdk", "java"),
    ("corretto", "java"),
    ("maven", "java"),
    ("gradle", "java"),
    ("java", "java"),
    ("aspnet", "dotnet"),
    ("dotnet", "dotnet"),
    ("php", "php"),
    ("ruby", "ruby"),
)


def detect_ecosystem_and_version(image_reference: str) -> tuple[str, str, str]:
    """Detecta ecossistema (node, python, go, etc.), versão e distribuição base."""
    ref_lower = image_reference.lower()
    # O nome do repositório, sem registry e sem tag. Casar contra a referência
    # inteira lia a tag e o host: `cgr.dev/chainguard/go:latest` não era
    # reconhecido como Go (o "go" estava no caminho, não na tag), enquanto
    # qualquer tag contendo "go" classificava a imagem errada.
    repository = ref_lower.split("@", 1)[0].split(":", 1)[0].rstrip("/")
    basename = repository.rsplit("/", 1)[-1]

    # 1. Ecossistema
    ecosystem = _ECOSYSTEM_BY_NAME.get(basename, "")
    if not ecosystem:
        for keyword, named in _ECOSYSTEM_KEYWORDS:
            if keyword in basename:
                ecosystem = named
                break
    ecosystem = ecosystem or "generic"

    # 2. Versão
    version = ""
    tag_part = ref_lower.split(":")[-1] if ":" in ref_lower else ref_lower
    v_match = re.search(r"(\d+(?:\.\d+)*)", tag_part)
    if v_match:
        version = v_match.group(1)

    # 3. Distro base
    distro = "debian/ubuntu"
    if "alpine" in ref_lower:
        distro = "alpine"
    elif "distroless" in ref_lower:
        distro = "distroless"
    elif "wolfi" in ref_lower or "chainguard" in ref_lower:
        distro = "wolfi/chainguard"
    elif "scratch" in ref_lower:
        distro = "scratch"
    elif "slim" in ref_lower:
        distro = "debian-slim"

    return ecosystem, version, distro


def get_ecosystem_insights(image_reference: str) -> EcosystemInsight:
    """Gera insights técnicos e de segurança detalhados para a imagem e versão."""
    ecosystem, version, distro = detect_ecosystem_and_version(image_reference)

    if ecosystem == "node":
        major = version.split(".")[0] if version else "22"
        runtime_features = [
            f"Node.js {major}.x V8 engine with optimised ECMAScript Modules (ESM) support.",
            "Native environment-file support (--env-file=.env), with no need for dotenv.",
            "Native WebSocket client and native fetch API (Undici).",
            "Native Corepack support for managing yarn/pnpm.",
        ]
        base_advice = []
        if distro == "alpine":
            base_advice.extend(
                [
                    "Alpine uses musl libc: native C++ packages (sharp, bcrypt, sqlite3) "
                    "must be compiled, or need 'libc6-compat'.",
                    "For full compatibility without the build overhead, consider "
                    "'node:22-bookworm-slim' (glibc).",
                    "Official 'node:alpine' images already ship the non-root user "
                    "'node' (UID 1000, GID 1000).",
                ]
            )
        else:
            base_advice.extend(
                [
                    "Debian Slim is fully compatible with pre-built glibc binaries.",
                    "Consider 'distroless/nodejs22-debian12' to drop the shell.",
                ]
            )

        security = [
            "Set 'ENV NODE_ENV=production' to enable runtime optimisations and "
            "disable devDependencies.",
            "The bundled npm CLI has its own CVE cycle: run "
            "'RUN npm install -g npm@latest', or drop it in a multi-stage build.",
            "Tune '--max-old-space-size' so Node stays within the container memory limit.",
            "Use 'USER node' (or create UID 10001) so the process never runs as root.",
        ]
        pitfalls = [
            "Avoid running 'npm start' as PID 1 (npm does not forward SIGTERM); "
            'use \'CMD ["node", "dist/index.js"]\'.',
            "Do not leave 'node_modules' in the build context root without a .dockerignore.",
        ]
        snippets = [
            'ENV NODE_ENV=production\nUSER node\nCMD ["--enable-source-maps", "dist/index.js"]',
            'HEALTHCHECK --interval=30s --timeout=5s CMD node -e "'
            "require('http').get('http://localhost:3000/health', (r) => {"
            "if (r.statusCode !== 200) process.exit(1)"
            "}).on('error', () => process.exit(1))\"",
        ]
        return EcosystemInsight(
            ecosystem="Node.js",
            version=version or "22.x",
            runtime_features=runtime_features,
            base_distro_advice=base_advice,
            security_guidelines=security,
            common_pitfalls=pitfalls,
            recommended_dockerfile_snippets=snippets,
        )

    elif ecosystem == "python":
        runtime_features = [
            "Python runtime with dependency isolation through a multi-stage builder.",
            "Supports Python 3.11/3.12/3.13, with execution-speed improvements.",
        ]
        base_advice = []
        if distro == "alpine":
            base_advice.extend(
                [
                    "Alpine musl does not support manylinux wheels. Libraries such as "
                    "pandas, numpy and cryptography compile from source (slow, needs gcc).",
                    "For Python with C/C++ dependencies, 'python:3.12-slim-bookworm' "
                    "builds far faster and produces smaller images.",
                ]
            )
        else:
            base_advice.extend(
                [
                    "Debian Slim supports every pre-built manylinux wheel on PyPI, "
                    "so the final container needs no compilers.",
                ]
            )

        security = [
            "Set 'ENV PYTHONUNBUFFERED=1' for unbuffered, real-time logs.",
            "Set 'ENV PYTHONDONTWRITEBYTECODE=1' so no .pyc files are written.",
            "Install dependencies with "
            "'pip install --no-cache-dir --user -r requirements.txt' in the builder, "
            "then copy '/root/.local' across for the non-root user.",
            "Create an 'appuser' (UID 10001) to run the process.",
        ]
        pitfalls = [
            "Do not write healthchecks that depend on the external 'requests' "
            "package; use 'urllib.request.urlopen' from the standard library.",
        ]
        snippets = [
            (
                "ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1\n"
                'USER appuser\nCMD ["python", "-u", "main.py"]'
            ),
            (
                'HEALTHCHECK --interval=30s --timeout=5s CMD python -c "'
                "import urllib.request; "
                "urllib.request.urlopen('http://localhost:8000/health', timeout=3)\" || exit 1"
            ),
        ]
        return EcosystemInsight(
            ecosystem="Python",
            version=version or "3.12.x",
            runtime_features=runtime_features,
            base_distro_advice=base_advice,
            security_guidelines=security,
            common_pitfalls=pitfalls,
            recommended_dockerfile_snippets=snippets,
        )

    elif ecosystem == "go":
        return EcosystemInsight(
            ecosystem="Go",
            version=version or "1.23.x",
            runtime_features=[
                "Statically linked native binaries, with no interpreter or runtime dependency.",
            ],
            base_distro_advice=[
                "'scratch' or distroless images give the smallest surface (zero CVEs).",
                "Copy '/etc/ssl/certs/ca-certificates.crt' from the builder for HTTPS calls.",
            ],
            security_guidelines=[
                "Build with 'CGO_ENABLED=0 GOOS=linux go build -ldflags=\"-s -w\" -o app .'.",
                "On 'scratch', use 'USER 65534:65534' (nobody): there is no /etc/passwd.",
            ],
            common_pitfalls=[
                "Do not use shell-form healthchecks on scratch; "
                'use exec form: CMD ["/app", "-health"].',
            ],
            recommended_dockerfile_snippets=[
                "FROM scratch\n"
                "COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/\n"
                'COPY --from=builder /app/app /app\nUSER 65534:65534\nENTRYPOINT ["/app"]',
            ],
        )

    elif ecosystem == "java":
        return EcosystemInsight(
            ecosystem="Java / JVM",
            version=version or "21 LTS",
            runtime_features=[
                "Eclipse Temurin / Amazon Corretto JRE with container awareness.",
            ],
            base_distro_advice=[
                "Use 'eclipse-temurin:21-jre-alpine' rather than the full JDK: it "
                "drops over 300MB of tooling the runtime does not need.",
            ],
            security_guidelines=[
                "Set 'JAVA_OPTS=\"-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 "
                "-Djava.security.egd=file:/dev/./urandom\"'.",
                "Run as the non-root user 'appuser' (UID 10001).",
            ],
            common_pitfalls=[
                "Avoid pinning heap size (-Xmx) without accounting for the container memory limit.",
            ],
            recommended_dockerfile_snippets=[
                'ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"\n'
                "USER appuser\n"
                'ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]',
            ],
        )

    elif ecosystem == "rust":
        return EcosystemInsight(
            ecosystem="Rust",
            version=version or "1.82",
            runtime_features=[
                "Statically linked native binaries with musl and target-feature=+crt-static.",
            ],
            base_distro_advice=[
                "'scratch' or distroless images reduce CVEs to zero.",
            ],
            security_guidelines=[
                "Use 'cargo build --release --target x86_64-unknown-linux-musl'.",
                "Run as non-root: 'USER 65534:65534'.",
            ],
            common_pitfalls=[],
            recommended_dockerfile_snippets=[
                (
                    "FROM scratch\n"
                    "COPY --from=builder /app/binary /app\n"
                    'USER 65534:65534\nENTRYPOINT ["/app"]'
                ),
            ],
        )

    elif ecosystem == "php":
        return EcosystemInsight(
            ecosystem="PHP",
            version=version or "8.3",
            runtime_features=[
                "PHP 8.3 with JIT and Opcache enabled.",
            ],
            base_distro_advice=[
                "Use a multi-stage build with 'composer:2' in the builder, copying "
                "only '/app/vendor'.",
            ],
            security_guidelines=[
                "Enable Opcache for performance, and run as non-root (UID 10001).",
            ],
            common_pitfalls=[],
            recommended_dockerfile_snippets=[
                'USER appuser\nCMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]',
            ],
        )

    return EcosystemInsight(
        ecosystem="Generic Container",
        version=version or "latest",
        runtime_features=["Standard Linux container."],
        base_distro_advice=["Prefer minimal distributions such as Alpine or Distroless."],
        security_guidelines=[
            "Never run as root (USER 10001).",
            "Keep a tidy .dockerignore.",
            "Use healthchecks for liveness/readiness monitoring.",
        ],
        common_pitfalls=[],
        recommended_dockerfile_snippets=[],
    )
