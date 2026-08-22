"""Um retrato de todos os Dockerfiles de uma vez.

Cada comando desta ferramenta olha para um artefato: um Dockerfile, uma
imagem, um build. Isso resolve a pergunta de quem está com o arquivo aberto e
não resolve nenhuma das perguntas de quem responde por trinta repositórios --
"quantos ainda rodam como root?", "quantos fixam a base?", "por onde eu
começo?". Sem resposta, a resposta na prática vira "por onde alguém reclamar".

Este módulo é a agregação, e é pura: recebe o que foi lido de cada arquivo e
devolve o retrato. O que ele **não** faz é tão importante quanto o que faz:
uma varredura de frota lê Dockerfiles, não constrói imagens nem chama scanner.
Portanto ela nunca diz que uma imagem está limpa -- ela diz o que o arquivo
declara, e nada além. Chamar isso de "auditoria de segurança da frota" seria
exatamente a promessa que esta ferramenta existe para não fazer.

A ordenação é por número de violações e depois por caminho. O empate resolvido
pelo caminho não é detalhe: sem ele, a mesma frota produziria uma ordem
diferente a cada varredura, e nenhum relatório seria comparável com o
anterior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.domain.value_objects.build_policy import PolicyViolation


@dataclass(frozen=True)
class FleetEntry:
    """Um Dockerfile da frota, com o que se conseguiu ler dele."""

    path: str
    #: Bases declaradas, na ordem dos `FROM`.
    bases: tuple[str, ...] = ()
    pinned_bases: int = 0
    total_bases: int = 0
    nonroot: Tristate = Tristate.UNKNOWN
    stages: int = 1
    violations: tuple[PolicyViolation, ...] = ()
    #: Preenchido quando o arquivo não pôde ser lido ou analisado. Uma entrada
    #: com erro nunca conta como conforme: é ausência de leitura.
    error: str = ""

    @property
    def fully_pinned(self) -> bool:
        return bool(self.total_bases) and self.pinned_bases == self.total_bases

    @property
    def readable(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "bases": list(self.bases),
            "pinned_bases": self.pinned_bases,
            "total_bases": self.total_bases,
            "fully_pinned": self.fully_pinned,
            "nonroot": str(self.nonroot),
            "stages": self.stages,
            "violations": [v.to_dict() for v in self.violations],
            "error": self.error,
        }


@dataclass(frozen=True)
class FleetReport:
    """O retrato agregado, e a fila de trabalho que sai dele."""

    root: str
    entries: tuple[FleetEntry, ...] = field(default_factory=tuple)
    #: Diretórios que a varredura não conseguiu percorrer. Reportar é o que
    #: impede um relatório de parecer completo quando não é.
    unreadable_paths: tuple[str, ...] = ()
    #: Se a varredura parou no teto de arquivos. Um retrato truncado que não
    #: diz que foi truncado é pior do que nenhum retrato.
    truncated: bool = False
    #: Se havia política declarada. Sem ela, `violations` está sempre vazio --
    #: e isso não significa conformidade.
    policy_applied: bool = False

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def readable(self) -> tuple[FleetEntry, ...]:
        return tuple(e for e in self.entries if e.readable)

    @property
    def unreadable(self) -> tuple[FleetEntry, ...]:
        return tuple(e for e in self.entries if not e.readable)

    @property
    def fully_pinned(self) -> int:
        return sum(1 for e in self.readable if e.fully_pinned)

    @property
    def running_as_root(self) -> int:
        return sum(1 for e in self.readable if e.nonroot.is_false)

    @property
    def undetermined_user(self) -> int:
        """Arquivos em que não se conseguiu decidir o usuário.

        Contado separado de `running_as_root` de propósito: juntar os dois
        transformaria ausência de medida em acusação, e a fila de trabalho de
        cada um é diferente."""
        return sum(1 for e in self.readable if not e.nonroot.is_known)

    @property
    def with_violations(self) -> int:
        return sum(1 for e in self.entries if e.violations)

    @property
    def total_violations(self) -> int:
        return sum(len(e.violations) for e in self.entries)

    def worst_first(self) -> tuple[FleetEntry, ...]:
        """A fila de trabalho: mais violações primeiro, caminho desempata.

        O desempate por caminho é o que torna duas varreduras comparáveis --
        sem ele a mesma frota sairia em ordem diferente a cada execução.
        """
        return tuple(sorted(self.entries, key=lambda e: (-len(e.violations), e.path)))

    def summary(self) -> str:
        """A frase que resume o retrato sem prometer o que não foi medido."""
        if not self.total:
            return "nenhum Dockerfile encontrado"
        partes = [
            f"{self.total} Dockerfile(s)",
            f"{self.fully_pinned} com todas as bases fixadas",
        ]
        if self.running_as_root:
            partes.append(f"{self.running_as_root} rodando como root")
        if self.undetermined_user:
            partes.append(f"{self.undetermined_user} com usuário indeterminado")
        if self.unreadable:
            partes.append(f"{len(self.unreadable)} ilegível(is)")
        return ", ".join(partes)

    def caveat(self) -> str:
        """O que este relatório deliberadamente não afirma."""
        return (
            "esta varredura lê Dockerfiles: não constrói imagem nem chama scanner. "
            "Ela diz o que os arquivos declaram, e nada sobre as vulnerabilidades "
            "das imagens que eles produzem"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "summary": self.summary(),
            "caveat": self.caveat(),
            "policy_applied": self.policy_applied,
            "truncated": self.truncated,
            "unreadable_paths": list(self.unreadable_paths),
            "totals": {
                "dockerfiles": self.total,
                "fully_pinned": self.fully_pinned,
                "running_as_root": self.running_as_root,
                "undetermined_user": self.undetermined_user,
                "with_violations": self.with_violations,
                "violations": self.total_violations,
                "unreadable": len(self.unreadable),
            },
            "dockerfiles": [e.to_dict() for e in self.worst_first()],
        }
