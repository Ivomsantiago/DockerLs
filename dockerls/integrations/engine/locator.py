"""Onde está o binário da engine Go, e se dá para usá-lo.

A engine é opcional de propósito. Ela não é uma dependência nova do
projeto: se o binário não estiver ali, o pipeline Python roda como sempre
rodou. Um caminho de execução que só funciona quando um artefato compilado
está presente teria de ser a *única* forma de rodar, ou não ser nenhuma --
e a segunda opção quebraria `pip install dockerls`.

Ordem de busca, da mais explícita para a mais geral:

1. `DOCKERLS_ENGINE_PATH`, para quem construiu o binário e sabe onde pôs;
2. `engine/bin/dockerls-engine` dentro do repositório, que é onde o
   `make engine` deposita;
3. `dockerls-engine` no PATH.

Um binário encontrado ainda precisa falar a mesma versão de protocolo, e é
por isso que `probe()` existe: descobrir a incompatibilidade no `--version`
custa milissegundos, descobri-la no meio de um lote de cem imagens custa o
lote inteiro.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 -- argv fixo, sem shell; ver `probe`
from pathlib import Path

from loguru import logger

#: Versão do contrato JSON. Tem de bater com `protocol.Version` do Go.
PROTOCOL_VERSION = 1

#: Quanto o `--version` da engine pode demorar. Ele responde na hora ou não
#: responde: um binário que trava aqui não vai medir imagem nenhuma.
_PROBE_TIMEOUT_SECONDS = 5.0

_ENV_VAR = "DOCKERLS_ENGINE_PATH"
_BINARY_NAME = "dockerls-engine"


def _repository_build() -> Path:
    """O caminho onde o build local deposita o binário."""
    # dockerls/integrations/engine/locator.py -> raiz do repositório
    return Path(__file__).resolve().parents[3] / "engine" / "bin" / _BINARY_NAME


def find_engine() -> str:
    """O caminho absoluto do binário, ou "" quando não há um utilizável."""
    override = os.environ.get(_ENV_VAR, "").strip()
    if override:
        # Um caminho explícito que não existe é erro de configuração, e
        # cair calado no PATH esconderia justamente o engano que a
        # variável foi criada para evitar.
        path = Path(override)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        logger.warning(f"{_ENV_VAR} points at {override}, which is not an executable file")
        return ""

    local = _repository_build()
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)

    found = shutil.which(_BINARY_NAME)
    return found or ""


def probe(path: str) -> bool:
    """True quando o binário em `path` fala a versão de protocolo desta CLI."""
    if not path:
        return False
    try:
        completed = subprocess.run(  # noqa: S603 -- argv fixo, caminho absoluto, sem shell
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Could not probe the Go engine at {path}: {e}")
        return False

    if completed.returncode != 0:
        logger.warning(f"The Go engine at {path} exited {completed.returncode} on --version")
        return False

    expected = f"protocol {PROTOCOL_VERSION}"
    if expected not in completed.stdout:
        logger.warning(
            f"The Go engine at {path} speaks {completed.stdout.strip()!r}, "
            f"but this CLI speaks {expected!r}; falling back to the Python pipeline"
        )
        return False
    return True
