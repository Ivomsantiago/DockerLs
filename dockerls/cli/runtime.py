"""As Settings do processo e o logging, sem o contêiner de dependências.

Isto morava em `cli/dependencies.py`, e o problema não era o código: era o
módulo. `dependencies.py` importa a aplicação inteira -- pipeline de scan,
clientes HTTP, pydantic-settings, SQLAlchemy -- e o callback que roda antes
de *todo* subcomando só precisava daqui. `dockerls version`, que imprime
uma string, pagava ~250ms para configurar um sink de log.

Separado, o callback importa este módulo (Settings + logging, e nada mais)
e os comandos que de fato trabalham seguem importando `dependencies`, que
reexporta estes nomes para não mudar nada do lado de quem chama.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from dockerls.infrastructure.config.settings import Settings
from dockerls.infrastructure.logging.setup import setup_logging

if TYPE_CHECKING:
    from pathlib import Path

# Populated by _settings() on first use; exposed so commands can tell the
# user exactly which file the run's diagnostics landed in.
_LOG_FILE: Path | None = None


@lru_cache(maxsize=1)
def _settings() -> Settings:
    global _LOG_FILE
    s = Settings()
    s.ensure_dirs()
    _LOG_FILE = setup_logging(s.log_level, log_dir=s.log_dir)
    return s


def current_log_file() -> Path | None:
    _settings()
    return _LOG_FILE


def configure_logging() -> None:
    """Detach loguru's default stderr sink before any command runs.

    Until a sink is configured, loguru logs everything from DEBUG up to
    stderr. Commands that never touched Settings -- `build` was one --
    inherited that default and leaked INFO lines into the terminal.
    """
    _settings()


def enable_console_logging() -> None:
    """Re-attach the stderr sink (``--verbose``) on top of the file sink.

    The stderr sink runs at the configured `log_level` here (INFO by
    default, DEBUG via DOCKERLS_LOG_LEVEL) rather than the WARNING floor
    that applies without ``--verbose``.
    """
    s = _settings()
    global _LOG_FILE
    _LOG_FILE = setup_logging(
        s.log_level, log_dir=s.log_dir, console=True, console_level=s.log_level
    )
