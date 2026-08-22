"""Assinar e verificar imagens com cosign.

Uma assinatura responde a uma pergunta que nada mais nesta ferramenta
responde: *quem* publicou estes bytes. O scan diz o que há dentro, a
procedência diz de onde veio, e nenhum dos dois impede alguém com acesso de
escrita ao registry de sobrescrever a tag com outra coisa. A assinatura é o
elo que fecha isso, e ela vale exatamente pelo cuidado com que é tratada --
uma assinatura conferida com displicência é pior que nenhuma, porque produz
confiança sem base.

Daí as três regras deste módulo:

* **Cosign ausente é `SIGNER_MISSING`, nunca "não assinado" nem "verificado".**
  Não ter a ferramenta é ausência de resposta. Reportar isso como falta de
  assinatura acusaria alguém injustamente; reportar como verificado seria a
  falha silenciosa que este projeto inteiro existe para evitar.
* **Só se assina por digest.** Assinar `app:1.0` assina o que a tag aponta no
  instante do comando, e a tag pode mover no instante seguinte -- a assinatura
  continuaria válida, cobrindo bytes que ninguém mediu. O digest não move.
* **Nada de senha ou token em log.** A invocação passa por lista de argumentos,
  sem shell, e a saída do cosign é repassada como está apenas quando não há
  material sensível envolvido; a variável de ambiente com a senha da chave
  nunca é ecoada.

A verificação keyless (OIDC) é o padrão porque é o que funciona em CI sem
segredo de longa duração no repositório -- e um segredo de longa duração num
repositório é a coisa que a assinatura deveria estar protegendo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum

from loguru import logger

from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable
from dockerls.utils.subprocess_runner import OutputTooLargeError, run_capture

#: Tempo máximo de uma operação do cosign. Assinar e verificar falam com o
#: registry e com o log de transparência; minutos seriam patologia, não
#: lentidão.
COSIGN_TIMEOUT_SECONDS = 120.0

_COSIGN = "cosign"


class SignatureStatus(StrEnum):
    """O resultado de uma operação de assinatura, com a ausência explícita."""

    #: A assinatura existe e confere.
    VERIFIED = "VERIFIED"
    #: A assinatura foi produzida agora.
    SIGNED = "SIGNED"
    #: O cosign respondeu que não há assinatura válida para esta imagem.
    UNSIGNED = "UNSIGNED"
    #: O cosign não está instalado. Ausência de resposta, não veredito.
    SIGNER_MISSING = "SIGNER_MISSING"
    #: O cosign rodou e falhou por outro motivo (rede, permissão, timeout).
    FAILED = "FAILED"

    @property
    def is_conclusive(self) -> bool:
        """Se este estado permite afirmar alguma coisa sobre a imagem.

        `SIGNER_MISSING` e `FAILED` não permitem: são falhas do medidor, e
        tratá-las como veredito é a substituição que esta ferramenta recusa.
        """
        return self in (
            SignatureStatus.VERIFIED,
            SignatureStatus.SIGNED,
            SignatureStatus.UNSIGNED,
        )


@dataclass(frozen=True)
class SignatureResult:
    """O que se conseguiu apurar sobre a assinatura de uma referência."""

    reference: str
    status: SignatureStatus
    detail: str = ""
    #: Identidades que assinaram, quando a verificação as revelou.
    identities: tuple[str, ...] = field(default_factory=tuple)

    @property
    def trustworthy(self) -> bool:
        """Só `VERIFIED` autoriza confiar. Nem `SIGNER_MISSING`, nem `FAILED`."""
        return self.status is SignatureStatus.VERIFIED

    def explain(self) -> str:
        if self.status is SignatureStatus.VERIFIED:
            quem = ", ".join(self.identities) if self.identities else "identidade não revelada"
            return f"assinatura válida ({quem})"
        if self.status is SignatureStatus.SIGNED:
            return "assinatura publicada no registry"
        if self.status is SignatureStatus.UNSIGNED:
            return (
                "o cosign não encontrou assinatura válida para esta imagem: ninguém "
                "atestou publicamente que a publicou"
            )
        if self.status is SignatureStatus.SIGNER_MISSING:
            return (
                "cosign não está instalado: isto é ausência de resposta, e não "
                "confirmação de que a imagem não está assinada"
            )
        return f"a verificação não pôde ser concluída: {self.detail or 'motivo desconhecido'}"

    def to_dict(self) -> dict[str, object]:
        return {
            "reference": self.reference,
            "status": str(self.status),
            "trustworthy": self.trustworthy,
            "explanation": self.explain(),
            "identities": list(self.identities),
            "detail": self.detail,
        }


class CosignClient:
    """Invoca o cosign, sempre por lista de argumentos e sem shell."""

    def __init__(self, timeout: float = COSIGN_TIMEOUT_SECONDS):
        self._timeout = timeout

    async def sign(self, reference: str, *, keyless: bool = True) -> SignatureResult:
        """Assina uma referência **por digest**.

        Assinar uma tag assinaria o que ela aponta agora, e ela pode mover no
        instante seguinte: a assinatura seguiria válida cobrindo outros bytes.
        """
        if "@sha256:" not in reference:
            return SignatureResult(
                reference=reference,
                status=SignatureStatus.FAILED,
                detail=(
                    "só se assina por digest: uma tag pode mover, e a assinatura "
                    "continuaria válida cobrindo bytes que ninguém mediu"
                ),
            )

        argv = ["sign", "--yes", reference]
        if not keyless:
            argv = ["sign", "--yes", "--key", "cosign.key", reference]

        code, _, err = await self._run(argv)
        if code is None:
            return _missing(reference)
        if code != 0:
            return SignatureResult(
                reference=reference, status=SignatureStatus.FAILED, detail=_tail(err)
            )
        return SignatureResult(reference=reference, status=SignatureStatus.SIGNED)

    async def verify(
        self,
        reference: str,
        *,
        certificate_identity_regexp: str = "",
        certificate_oidc_issuer: str = "",
    ) -> SignatureResult:
        """Confere a assinatura de uma referência.

        Sem identidade e emissor declarados, o cosign aceita **qualquer**
        assinante -- o que responde "está assinada" e não responde "por quem",
        que é a única pergunta que importa. Este método passa os dois adiante
        e diz na saída quando não recebeu nenhum.
        """
        argv = ["verify", "--output", "json", reference]
        if certificate_identity_regexp:
            argv[1:1] = ["--certificate-identity-regexp", certificate_identity_regexp]
        if certificate_oidc_issuer:
            argv[1:1] = ["--certificate-oidc-issuer", certificate_oidc_issuer]

        code, out, err = await self._run(argv)
        if code is None:
            return _missing(reference)
        if code != 0:
            # O cosign devolve o mesmo código para "não há assinatura" e para
            # "não consegui falar com o registry". Distinguir importa: um é
            # veredito sobre a imagem, o outro é falha do medidor.
            texto = _tail(err)
            if _looks_unsigned(texto):
                return SignatureResult(
                    reference=reference, status=SignatureStatus.UNSIGNED, detail=texto
                )
            return SignatureResult(reference=reference, status=SignatureStatus.FAILED, detail=texto)

        identities = _identities(out)
        detail = ""
        if not certificate_identity_regexp and not certificate_oidc_issuer:
            detail = (
                "verificado sem restringir identidade nem emissor: isto confirma que "
                "*alguém* assinou, não que quem você espera assinou"
            )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.VERIFIED,
            identities=identities,
            detail=detail,
        )

    async def _run(self, argv: list[str]) -> tuple[int | None, bytes, bytes]:
        """Executa o cosign. `None` como código significa "não está instalado"."""
        try:
            binary = resolve_executable(_COSIGN)
        except ExecutableNotFoundError:
            return None, b"", b""

        try:
            return await run_capture([binary, *argv], timeout=self._timeout)
        except TimeoutError:
            return 1, b"", b"o cosign nao respondeu dentro do tempo limite"
        except OutputTooLargeError:  # pragma: no cover - saida do cosign e pequena
            return 1, b"", b"o cosign produziu saida grande demais"
        except OSError as e:  # pragma: no cover - falha de processo e rara
            logger.debug(f"Falha ao executar cosign: {e}")
            return 1, b"", str(e).encode("utf-8", errors="replace")


def _missing(reference: str) -> SignatureResult:
    return SignatureResult(reference=reference, status=SignatureStatus.SIGNER_MISSING)


def _tail(stream: bytes, limit: int = 400) -> str:
    """As últimas linhas do erro, cortadas. Mensagem de erro do cosign pode
    conter caminho local; o corte reduz o que vaza para um log de CI."""
    text = stream.decode("utf-8", errors="replace").strip()
    return text[-limit:] if len(text) > limit else text


def _looks_unsigned(message: str) -> bool:
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "no signatures found",
            "no matching signatures",
            "manifest unknown",
            "no such file or directory: signature",
        )
    )


def _identities(stdout: bytes) -> tuple[str, ...]:
    """Os assinantes que o cosign revelou, quando o JSON os traz."""
    try:
        payload = json.loads(stdout.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, list):
        return ()

    found: list[str] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        optional = entry.get("optional")
        if not isinstance(optional, dict):
            continue
        subject = optional.get("Subject") or optional.get("subject")
        if isinstance(subject, str) and subject.strip():
            found.append(subject.strip())
    return tuple(dict.fromkeys(found))
