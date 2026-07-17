"""
CORS Misconfiguration Scanner — Custom Module
==============================================
Cross-Origin Resource Sharing noto'g'ri sozlanishini tekshiradi.
"""
import logging
from typing import List

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)


class CorsScanner(BaseScanner):
    """CORS noto'g'ri konfiguratsiyasini tekshiruvchi custom scanner."""
    name = "Custom-CORS-Scanner"
    description = "CORS misconfiguration zaifliklarini aniqlaydi"

    TEST_ORIGINS = [
        "https://evil-attacker.com",
        "null",
        "https://subdomain.evil.com",
    ]

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"CORS scan boshlandi: {target.url}")

        for origin in self.TEST_ORIGINS:
            response = await self.get(
                target.url,
                headers={"Origin": origin, "User-Agent": "WebAuditAgent/1.0"}
            )
            if not response:
                continue

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if not acao:
                continue

            # Wildcard CORS
            if acao == "*":
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="CORS Wildcard Origin Allowed",
                    severity="MEDIUM",
                    description=(
                        "CORS konfiguratsiyasida 'Access-Control-Allow-Origin: *' ishlatilmoqda. "
                        "Har qanday domen saytning API javoblarini o'qishi mumkin."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    proof_of_concept={"origin_tested": origin, "acao_response": acao},
                    cwe_id="CWE-942",
                    cvss_score=5.3,
                    remediation=(
                        "Wildcard (*) o'rniga aniq domenlar ro'yxatini bering. "
                        "Misol: Access-Control-Allow-Origin: https://yourdomain.com"
                    ),
                    confidence="HIGH",
                ))
                break

            # Arbitrary origin reflected
            elif acao == origin:
                severity = "HIGH"
                cvss = 8.1

                # Credentials bilan birgalikda yanada xavfli
                if acac.lower() == "true":
                    severity = "CRITICAL"
                    cvss = 9.0

                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="CORS Arbitrary Origin Reflected" +
                                       (" with Credentials" if acac.lower() == "true" else ""),
                    severity=severity,
                    description=(
                        f"Server ixtiyoriy origin'ni ({origin}) CORS header'ida qaytarmoqda. "
                        + ("Credentials (cookie/auth header) ham ruxsat etilgan — juda xavfli!" if acac.lower() == "true" else "")
                    ),
                    evidence=(
                        f"Test Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'yo\'q'}"
                    ),
                    proof_of_concept={
                        "origin_tested": origin,
                        "acao_response": acao,
                        "acac_response": acac,
                        "with_credentials": acac.lower() == "true",
                    },
                    cwe_id="CWE-942",
                    cvss_score=cvss,
                    remediation=(
                        "CORS origin'larini server tomonida whitelist orqali tekshiring. "
                        "Ixtiyoriy origin'larni hech qachon reflect qilmang. "
                        "Credentials bilan wildcard ishlatmang."
                    ),
                    confidence="HIGH",
                ))

            # null origin
            elif acao == "null" and origin == "null":
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="CORS null Origin Allowed",
                    severity="HIGH",
                    description=(
                        "'null' origin ruxsat etilgan. "
                        "Sandbox iframe yoki lokal fayl orqali hujum amalga oshirilishi mumkin."
                    ),
                    evidence=f"Access-Control-Allow-Origin: null",
                    proof_of_concept={"origin_tested": "null", "acao_response": acao},
                    cwe_id="CWE-942",
                    cvss_score=7.4,
                    remediation="'null' origin'ni hech qachon ruxsat etmang.",
                    confidence="HIGH",
                ))

        logger.info(f"CORS scan yakunlandi. {len(findings)} ta finding topildi.")
        return findings
