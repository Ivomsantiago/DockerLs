"""Ler `.dockerls-policy.yaml` -- e recusar o que não se entende.

Aqui mora a única diferença de comportamento importante entre este arquivo e
o `.dockerls-ignore.yaml`: **um arquivo de política malformado é erro, não
ausência de política**.

O motivo é a direção da falha. Uma regra de ignore que não carrega deixa de
esconder uma CVE -- o resultado é mais alarme, e alarme a mais é seguro. Uma
regra de política que não carrega deixa de exigir alguma coisa, e o build
passa parecendo ter sido conferido. Uma chave digitada errado (`require_non_root`
em vez de `require_nonroot`) viraria um portão aberto com cara de fechado, e
ninguém descobre isso olhando a saída verde.

Por isso: chave desconhecida é erro, tipo errado é erro, YAML quebrado é erro,
severidade inexistente é erro. Só a ausência do arquivo é silêncio -- e é
silêncio explícito, porque aí ninguém declarou nada.

O YAML passa pelo `safe_load_yaml`, que já recusa documentos grandes demais,
profundos demais ou expandidos demais antes de construir qualquer coisa: um
arquivo de política pode perfeitamente vir de um repositório que não é seu.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dockerls.domain.value_objects.build_policy import (
    GATE_THRESHOLDS,
    SEVERITY_ORDER,
    BuildPolicy,
)
from dockerls.utils.safe_yaml import UnsafeYAMLError, safe_load_yaml

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_POLICY_FILENAME = ".dockerls-policy.yaml"

#: As chaves aceitas. Qualquer outra é erro -- ver o docstring do módulo.
_KNOWN_KEYS = frozenset(
    {
        "fail_on",
        "max_vulnerabilities",
        "require_scan",
        "require_pinned_bases",
        "require_nonroot",
        "required_labels",
        "allowed_base_registries",
        "require_provenance",
    }
)


class PolicyFileError(ValueError):
    """O arquivo existe e não pôde ser entendido. Nunca vira política vazia."""


def find_policy_file(context: Path) -> Path | None:
    """O arquivo de política do contexto de build, se houver um."""
    candidate = context / DEFAULT_POLICY_FILENAME
    return candidate if candidate.is_file() else None


def load_policy(path: Path) -> BuildPolicy:
    """Carrega a política declarada, ou levanta explicando o que está errado."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise PolicyFileError(f"não foi possível ler {path}: {e}") from e

    try:
        data = safe_load_yaml(raw, origin=str(path))
    except UnsafeYAMLError as e:
        raise PolicyFileError(f"{path}: {e}") from e

    if data is None:
        raise PolicyFileError(
            f"{path} está vazio. Um arquivo de política vazio quase sempre é um "
            "engano; remova-o se a intenção é não ter política."
        )
    if not isinstance(data, dict):
        raise PolicyFileError(f"{path}: o documento precisa ser um mapa de regras")

    desconhecidas = sorted(set(data) - _KNOWN_KEYS)
    if desconhecidas:
        raise PolicyFileError(
            f"{path}: regra(s) desconhecida(s): {', '.join(desconhecidas)}. "
            f"As aceitas são: {', '.join(sorted(_KNOWN_KEYS))}. "
            "Uma chave digitada errado seria um portão aberto com cara de fechado."
        )

    policy = BuildPolicy(
        fail_on=_severity(data, "fail_on", path),
        max_vulnerabilities=_ceilings(data, path),
        require_scan=_flag(data, "require_scan", path),
        require_pinned_bases=_flag(data, "require_pinned_bases", path),
        require_nonroot=_flag(data, "require_nonroot", path),
        required_labels=_strings(data, "required_labels", path),
        allowed_base_registries=_strings(data, "allowed_base_registries", path),
        require_provenance=_flag(data, "require_provenance", path),
    )
    if policy.is_empty:
        raise PolicyFileError(
            f"{path}: nenhuma regra foi declarada. Um arquivo presente que não exige "
            "nada é indistinguível de um portão desligado."
        )
    return policy


def _flag(data: dict[str, Any], key: str, path: Path) -> bool:
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise PolicyFileError(f"{path}: {key} precisa ser true ou false, não {value!r}")
    return value


def _severity(data: dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key, "")
    if not value:
        return ""
    # `unknown` é severidade válida numa contagem e não é limiar válido: o
    # portão não sabe avaliá-lo. Recusar aqui é o que evita um build que morre
    # com erro técnico no meio do caminho por causa de uma linha de YAML.
    if not isinstance(value, str) or value.strip().lower() not in GATE_THRESHOLDS:
        raise PolicyFileError(
            f"{path}: {key} precisa ser uma de {', '.join(GATE_THRESHOLDS)}, não {value!r}"
        )
    return value.strip().lower()


def _ceilings(data: dict[str, Any], path: Path) -> dict[str, int]:
    value = data.get("max_vulnerabilities", {})
    if not value:
        return {}
    if not isinstance(value, dict):
        raise PolicyFileError(
            f"{path}: max_vulnerabilities precisa ser um mapa de severidade para número"
        )
    ceilings: dict[str, int] = {}
    for severity, limit in value.items():
        chave = str(severity).strip().lower()
        if chave not in SEVERITY_ORDER:
            raise PolicyFileError(
                f"{path}: severidade desconhecida em max_vulnerabilities: {severity!r}"
            )
        # `bool` é subclasse de `int` em Python: `high: true` passaria como
        # teto de 1, que não é o que ninguém quis dizer.
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise PolicyFileError(
                f"{path}: o teto de {chave} precisa ser um inteiro >= 0, não {limit!r}"
            )
        ceilings[chave] = limit
    return ceilings


def _strings(data: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    value = data.get(key, [])
    if not value:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyFileError(f"{path}: {key} precisa ser uma lista de textos")
    itens = tuple(v.strip() for v in value if v.strip())
    if not itens:
        raise PolicyFileError(f"{path}: {key} foi declarado sem nenhum valor útil")
    return itens
