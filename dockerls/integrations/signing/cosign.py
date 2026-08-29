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
    #: O cosign respondeu que não há assinatura nenhuma para esta imagem.
    UNSIGNED = "UNSIGNED"
    #: **Existe assinatura, e ela não confere** -- bytes adulterados, ou
    #: assinados por alguém que não é quem se esperava. É veredito, e o mais
    #: grave dos três: `UNSIGNED` diz que ninguém atestou nada, este diz que
    #: alguém atestou e a atestação não bate.
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
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
            SignatureStatus.VERIFICATION_FAILED,
        )


@dataclass(frozen=True)
class SignatureResult:
    """O que se conseguiu apurar sobre a assinatura de uma referência."""

    reference: str
    status: SignatureStatus
    detail: str = ""
    #: Identidades que assinaram, quando a verificação as revelou.
    identities: tuple[str, ...] = field(default_factory=tuple)
    #: Se a verificação restringiu identidade **e/ou** emissor. `False` num
    #: `VERIFIED` quer dizer "alguém assinou", não "quem você espera assinou".
    #: Sai no JSON porque um consumidor que só olha `trustworthy` não teria
    #: como saber que a pergunta feita foi a fraca.
    identity_constrained: bool = False

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
        if self.status is SignatureStatus.VERIFICATION_FAILED:
            return (
                "SIGNATURE VERIFICATION FAILED: cosign found signing material for this "
                "image and it did not check out -- the bytes do not match what was "
                "signed, or the signer is not the identity you required. This is worse "
                "than an unsigned image, not the same thing"
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
            "conclusive": self.status.is_conclusive,
            "identity_constrained": self.identity_constrained,
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

    async def attest(
        self,
        reference: str,
        *,
        predicate: str,
        predicate_type: str,
        keyless: bool = True,
    ) -> SignatureResult:
        """Anexa um documento ao manifesto de uma imagem, assinado.

        Uma atestação é uma afirmação sobre bytes específicos -- "este SBOM
        descreve *esta* imagem" --, e por isso vale a mesma regra do
        `sign`: **só por digest**. Atestar uma tag anexaria o documento ao
        que ela aponta agora, e ela pode mover no instante seguinte; a
        atestação seguiria válida, descrevendo outra imagem.

        Isto é o que fecha o círculo com `registry-audit`, que já pergunta
        se há atestação publicada e, até agora, respondia "não há" para
        toda imagem que esta própria ferramenta construiu.
        """
        if "@sha256:" not in reference:
            return SignatureResult(
                reference=reference,
                status=SignatureStatus.FAILED,
                detail=(
                    "only digests get attested: a tag can move, and the attestation "
                    "would stay valid while describing a different image"
                ),
            )

        argv = [
            "attest",
            "--yes",
            "--predicate",
            predicate,
            "--type",
            predicate_type,
            reference,
        ]
        if not keyless:
            argv[1:1] = ["--key", "cosign.key"]

        code, _, err = await self._run(argv)
        if code is None:
            return _missing(reference)
        if code != 0:
            return SignatureResult(
                reference=reference, status=SignatureStatus.FAILED, detail=_tail(err)
            )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.SIGNED,
            detail=f"attested with a {predicate_type} predicate",
        )

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

        Os três desfechos negativos são separados de propósito, e a ordem em
        que são testados é a correção de um erro real:

        * **`VERIFICATION_FAILED`** -- há material de assinatura e ele não
          confere. Testado **primeiro**, porque o cosign anuncia uma
          identidade que não bate como `no matching signatures: none of the
          expected identities matched what was in the certificate`, e o
          marcador `no matching signatures` também aparece numa imagem sem
          assinatura nenhuma. Enquanto "não assinado" era testado antes, uma
          imagem assinada **por outra pessoa** saía como `UNSIGNED`: a falha
          exata que restringir a identidade existe para pegar era reportada
          como se ninguém tivesse assinado, que é o desfecho *menos* grave.
        * **`UNSIGNED`** -- o cosign procurou e não achou nada.
        * **`FAILED`** -- o medidor não respondeu (rede, permissão, timeout).
        """
        constrained = bool(certificate_identity_regexp or certificate_oidc_issuer)
        argv = ["verify", "--output", "json", reference]
        if certificate_identity_regexp:
            argv[1:1] = ["--certificate-identity-regexp", certificate_identity_regexp]
        if certificate_oidc_issuer:
            argv[1:1] = ["--certificate-oidc-issuer", certificate_oidc_issuer]

        code, out, err = await self._run(argv)
        if code is None:
            return _missing(reference)
        if code != 0:
            # O cosign devolve o mesmo código para "não há assinatura", para
            # "a assinatura não confere" e para "não consegui falar com o
            # registry". Distinguir importa: dois são veredito sobre a
            # imagem -- e não o mesmo veredito --, o terceiro é falha do
            # medidor.
            texto = _tail(err)
            if _looks_like_a_bad_signature(texto):
                return SignatureResult(
                    reference=reference,
                    status=SignatureStatus.VERIFICATION_FAILED,
                    detail=texto,
                    identity_constrained=constrained,
                )
            if _looks_unsigned(texto):
                return SignatureResult(
                    reference=reference,
                    status=SignatureStatus.UNSIGNED,
                    detail=texto,
                    identity_constrained=constrained,
                )
            return SignatureResult(
                reference=reference,
                status=SignatureStatus.FAILED,
                detail=texto,
                identity_constrained=constrained,
            )

        identities = _identities(out)
        detail = ""
        if not constrained:
            detail = (
                "verified without constraining identity or issuer: this confirms that "
                "*someone* signed, not that whoever you expect signed"
            )
        elif not _is_readable_output(out):
            # Saída malformada num cosign que saiu com 0: a verificação
            # aconteceu contra as restrições passadas, mas o documento que
            # nomeia o assinante não pôde ser lido. Dizer isso é melhor do
            # que uma lista de identidades vazia que se lê como "não havia".
            detail = (
                "cosign exited cleanly but its JSON output could not be parsed: "
                "the signature was checked against the identity you required, "
                "but the signer could not be read back to show you"
            )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.VERIFIED,
            identities=identities,
            detail=detail,
            identity_constrained=constrained,
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
            # Em inglês porque `detail` sai no JSON e na tabela do `verify`.
            return 1, b"", b"cosign did not answer within the time limit"
        except OutputTooLargeError:  # pragma: no cover - saida do cosign e pequena
            return 1, b"", b"cosign produced more output than will be read"
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


def _is_readable_output(stdout: bytes) -> bool:
    """Se a saída do cosign é um documento JSON que este módulo sabe ler.

    Separado de `_identities` porque uma lista válida e vazia (`[]`) e uma
    saída ilegível produzem as mesmas zero identidades, e só a segunda é uma
    ausência de resposta que vale a pena declarar.
    """
    try:
        payload = json.loads(stdout.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError:
        return False
    return isinstance(payload, list)


def _looks_like_a_bad_signature(message: str) -> bool:
    """Se o cosign disse que a assinatura **não confere**.

    Existe para separar veredito de indisponibilidade: o cosign devolve o
    mesmo código de saída para "estes bytes não são os assinados" e para
    "não consegui falar com o Rekor", e tratar o segundo como o primeiro
    abortaria instalações por causa de uma rede instável.

    E, na outra direção, para separar veredito de veredito: uma imagem
    assinada por outra identidade não é uma imagem sem assinatura, e é esta
    função -- consultada **antes** de `_looks_unsigned` -- que impede a
    primeira de ser reportada como a segunda.
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
            # O cosign nomeia assim a assinatura cujo certificado é válido
            # mas cujo emissor não é o exigido.
            "none of the expected issuers matched",
            # Adulteração do payload: a assinatura existe e cobre outros bytes.
            "payload hash does not match",
            # Cadeia de confiança recusada -- material presente, e rejeitado.
            # Deliberadamente restrito a frases que o cosign só emite depois
            # de ter o certificado em mãos: um marcador largo faria uma rede
            # instável abortar instalações, que é o erro simétrico.
            "certificate verification failed",
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
