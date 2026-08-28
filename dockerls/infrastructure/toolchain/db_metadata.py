"""Lê a data de construção da base de vulnerabilidades de cada scanner.

Os dois publicam um JSON de metadados ao lado da base, com nomes de campo
diferentes:

    Trivy   <cache>/db/metadata.json   ->  "UpdatedAt" (e "NextUpdate")
    Grype   <cache>/db/<schema>/metadata.json  ->  "built"

Nada aqui levanta. Um arquivo ausente, ilegível, com JSON quebrado ou com
um campo que este código não reconhece devolve `None` **com o motivo**, e
quem chama transforma isso em `UNKNOWN` -- que é diferente de "atualizada",
e é justamente a distinção que este módulo existe para preservar.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from loguru import logger

#: Teto do arquivo de metadados. Ele tem centenas de bytes; qualquer coisa
#: maior não é ele, e ler sem limite um arquivo que o scanner escreveu é
#: confiar demais num caminho de disco.
MAX_METADATA_BYTES = 64 * 1024


def trivy_cache_dir() -> Path:
    """Onde o Trivy guarda a base, pela mesma resolução que ele usa."""
    env = os.environ.get("TRIVY_CACHE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "trivy"
    return Path.home() / ".cache" / "trivy"


def grype_cache_dir() -> Path:
    """Onde o Grype guarda a base."""
    env = os.environ.get("GRYPE_DB_CACHE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "grype"
    return Path.home() / ".cache" / "grype"


def read_trivy_built_at(cache_dir: Path | None = None) -> tuple[datetime | None, str]:
    """A data da base do Trivy, ou `(None, motivo)`."""
    base = cache_dir or trivy_cache_dir()
    return _read(base / "db" / "metadata.json", ("UpdatedAt", "updatedAt", "built"))


def read_grype_built_at(cache_dir: Path | None = None) -> tuple[datetime | None, str]:
    """A data da base do Grype, ou `(None, motivo)`.

    O Grype versiona a base por esquema (`db/5/metadata.json`), e o número
    muda entre versões da ferramenta. Procurar o mais recente é mais
    robusto que fixar um número que envelhece junto com o código.
    """
    base = (cache_dir or grype_cache_dir()) / "db"
    candidates = sorted(base.glob("*/metadata.json"), key=lambda p: p.parent.name, reverse=True)
    if not candidates:
        return None, f"no metadata under {base}"
    return _read(candidates[0], ("built", "Built", "UpdatedAt"))


def _read(path: Path, fields: tuple[str, ...]) -> tuple[datetime | None, str]:
    """O primeiro campo de data que existir, ou o motivo de não haver um."""
    try:
        if not path.is_file():
            return None, f"{path} is not there"
        if path.stat().st_size > MAX_METADATA_BYTES:
            return None, f"{path} is larger than a metadata file should be"
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        return None, f"could not read {path}: {e}"
    except json.JSONDecodeError as e:
        return None, f"{path} is not valid JSON: {e}"

    if not isinstance(payload, dict):
        return None, f"{path} does not contain an object"

    for field in fields:
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            parsed = _parse_timestamp(value)
            if parsed is not None:
                return parsed, ""
            return None, f"{path}: {field} is not a timestamp this code understands"
    return None, f"{path} carries none of {', '.join(fields)}"


def _parse_timestamp(value: str) -> datetime | None:
    """Interpreta o carimbo, tolerando o `Z` que os dois escrevem."""
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        # Alguns carimbos trazem mais de seis casas de fração de segundo,
        # que o `fromisoformat` não aceita. Cortar é melhor que desistir.
        if "." in text:
            head, _, tail = text.partition(".")
            digits = "".join(c for c in tail if c.isdigit())[:6]
            offset = tail[len(digits) :] if len(tail) > len(digits) else ""
            with_offset = f"{head}.{digits}{offset}" if digits else head + offset
            try:
                return datetime.fromisoformat(with_offset)
            except ValueError:
                logger.debug(f"Unparseable database timestamp: {value!r}")
        return None
