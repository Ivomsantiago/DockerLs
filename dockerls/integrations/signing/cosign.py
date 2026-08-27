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
            quem = ", ".join(self.identities) if self.identities else "identity not disclosed"
            return f"valid signature ({quem})"
        if self.status is SignatureStatus.SIGNED:
            return "signature published in the registry"
        if self.status is SignatureStatus.UNSIGNED:
            return (
                "cosign found no valid signature for this image: nobody publicly "
                "attested to publishing it"
            )
        if self.status is SignatureStatus.SIGNER_MISSING:
            return (
                "cosign is not installed: this is an absence of an answer, not "
                "confirmation that the image is unsigned"
            )
        return f"the check could not be completed: {self.detail or 'reason unknown'}"

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
                    "only digests get signed: a tag can move, and the signature would "
                    "stay valid over bytes nobody measured"
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
                "verified without constraining identity or issuer: this confirms that "
                "*someone* signed, not that whoever you expect signed"
            )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.VERIFIED,
            identities=identities,
            detail=detail,
        )

    async def verify_blob(
        self,
        blob: str,
        *,
        signature: str,
        certificate: str,
        certificate_identity_regexp: str = "",
        certificate_oidc_issuer: str = "",
    ) -> bool | None:
        """Confere a assinatura keyless de um arquivo local.

        `None` quer dizer **não foi possível conferir** -- cosign ausente, ou
        o cosign falhando por um motivo que não é "assinatura inválida". Só
        `False` é veredito: os bytes não são os que aquela identidade
        assinou. A distinção é a mesma de sempre neste projeto, e aqui ela
        decide se uma instalação é abortada ou apenas não é atestada.

        Sem identidade e emissor declarados o cosign aceita qualquer
        assinante, o que responderia "está assinado" sem responder "por
        quem". Quem chama passa os dois; este método não inventa um padrão,
        porque um padrão errado seria pior que nenhum.
        """
        argv = [
            "verify-blob",
            "--signature",
            signature,
            "--certificate",
            certificate,
            blob,
        ]
        if certificate_identity_regexp:
            argv[1:1] = ["--certificate-identity-regexp", certificate_identity_regexp]
        if certificate_oidc_issuer:
            argv[1:1] = ["--certificate-oidc-issuer", certificate_oidc_issuer]

        code, _, err = await self._run(argv)
        if code is None:
            return None
        if code == 0:
            return True
        texto = _tail(err)
        if _looks_like_a_bad_signature(texto):
            return False
        # Rede fora do ar, Rekor indisponível, certificado que o cosign não
        # soube ler: nada disso diz que os bytes estão errados.
        logger.debug(f"cosign verify-blob could not conclude: {texto}")
        return None

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


def _looks_like_a_bad_signature(message: str) -> bool:
    """Se o cosign disse que a assinatura **não confere**.

    Existe para separar veredito de indisponibilidade: o cosign devolve o
    mesmo código de saída para "estes bytes não são os assinados" e para
    "não consegui falar com o Rekor", e tratar o segundo como o primeiro
    abortaria instalações por causa de uma rede instável.
    """
    texto = (message or "").lower()
    return any(
        marker in texto
        for marker in (
            "signature verification failed",
            "invalid signature",
            "failed to verify signature",
            "error verifying blob",
            "certificate identity",
            "none of the expected identities matched",
        )
    )


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
