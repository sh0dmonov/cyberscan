"""
HTTP Security Headers Scanners — Custom Modules
=================================================
Har bir muhim header alohida scanner klassi ko'rinishida yozilgan.
Bu skanerlar sonini ko'paytirish va hisobotni batafsil qilish imkonini beradi.
"""
import logging
from typing import List, Optional

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding
from agent.config import settings

logger = logging.getLogger(__name__)


class CspHeaderScanner(BaseScanner):
    """Content-Security-Policy headerini tekshiradi."""
    name = "CSP-Header-Scanner"
    description = "Content-Security-Policy headerining mavjudligi va xavfsizligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        csp = headers.get("content-security-policy", "")
        config = settings.SECURITY_HEADERS["Content-Security-Policy"]

        if not csp:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: Content-Security-Policy",
                severity=config["severity"],
                description=config["description"],
                evidence=f"Content-Security-Policy headeri topilmadi.",
                proof_of_concept={"header": "Content-Security-Policy", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="Content-Security-Policy headerini qo'shing. Misol: Content-Security-Policy: default-src 'self'",
                confidence="HIGH",
            ))
        else:
            value_lower = csp.lower()
            issue = ""
            if "unsafe-inline" in value_lower and "unsafe-eval" in value_lower:
                issue = "CSP 'unsafe-inline' va 'unsafe-eval' bilan sozlangan — inline script va eval ruxsat etilgan."
            elif "unsafe-inline" in value_lower:
                issue = "CSP 'unsafe-inline' bilan sozlangan — inline script'larga ruxsat berilgan."
            elif "*" in csp and "default-src" in value_lower:
                issue = "CSP 'default-src *' bilan sozlangan — ixtiyoriy manbaga ruxsat."

            if issue:
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="Misconfigured Header: Content-Security-Policy",
                    severity="LOW",
                    description=issue,
                    evidence=f"Content-Security-Policy: {csp}",
                    proof_of_concept={"header": "Content-Security-Policy", "value": csp, "issue": issue},
                    cwe_id=config["cwe"],
                    cvss_score=2.5,
                    remediation="CSP direktivalarini kuchaytiring va 'unsafe-inline' kabi xavfli qiymatlarni cheklang.",
                    confidence="HIGH",
                ))
        return findings


class HstsHeaderScanner(BaseScanner):
    """Strict-Transport-Security headerini tekshiradi."""
    name = "HSTS-Header-Scanner"
    description = "HTTP Strict Transport Security (HSTS) mavjudligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        hsts = headers.get("strict-transport-security", "")
        config = settings.SECURITY_HEADERS["Strict-Transport-Security"]

        if not hsts:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: Strict-Transport-Security",
                severity=config["severity"],
                description=config["description"],
                evidence="Strict-Transport-Security headeri topilmadi.",
                proof_of_concept={"header": "Strict-Transport-Security", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="HSTS headerini qo'shing. Misol: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                confidence="HIGH",
            ))
        else:
            value_lower = hsts.lower()
            issue = ""
            if "max-age=0" in value_lower:
                issue = "HSTS max-age 0 ga tenglashtirilgan — HSTS o'chirilgan."
            elif "max-age=" not in value_lower:
                issue = "HSTS max-age direktivi mavjud emas."

            if issue:
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="Misconfigured Header: Strict-Transport-Security",
                    severity="LOW",
                    description=issue,
                    evidence=f"Strict-Transport-Security: {hsts}",
                    proof_of_concept={"header": "Strict-Transport-Security", "value": hsts, "issue": issue},
                    cwe_id=config["cwe"],
                    cvss_score=2.5,
                    remediation="HSTS max-age qiymatini kamida 1 yil qilib belgilang (31536000 soniya).",
                    confidence="HIGH",
                ))
        return findings


class XFrameHeaderScanner(BaseScanner):
    """X-Frame-Options headerini tekshiradi."""
    name = "X-Frame-Header-Scanner"
    description = "X-Frame-Options (Clickjacking himoyasi) mavjudligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        xfo = headers.get("x-frame-options", "")
        config = settings.SECURITY_HEADERS["X-Frame-Options"]

        if not xfo:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: X-Frame-Options",
                severity=config["severity"],
                description=config["description"],
                evidence="X-Frame-Options headeri topilmadi.",
                proof_of_concept={"header": "X-Frame-Options", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="X-Frame-Options headerini qo'shing. Misol: X-Frame-Options: SAMEORIGIN",
                confidence="HIGH",
            ))
        else:
            if xfo.lower() not in ("deny", "sameorigin"):
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="Misconfigured Header: X-Frame-Options",
                    severity="LOW",
                    description=f"X-Frame-Options noto'g'ri qiymatga ega: {xfo}",
                    evidence=f"X-Frame-Options: {xfo}",
                    proof_of_concept={"header": "X-Frame-Options", "value": xfo},
                    cwe_id=config["cwe"],
                    cvss_score=2.5,
                    remediation="X-Frame-Options qiymatini DENY yoki SAMEORIGIN qilib sozlang.",
                    confidence="HIGH",
                ))
        return findings


class XContentTypeHeaderScanner(BaseScanner):
    """X-Content-Type-Options headerini tekshiradi."""
    name = "X-Content-Type-Header-Scanner"
    description = "X-Content-Type-Options (MIME sniffing himoyasi) mavjudligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        xcto = headers.get("x-content-type-options", "")
        config = settings.SECURITY_HEADERS["X-Content-Type-Options"]

        if not xcto:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: X-Content-Type-Options",
                severity=config["severity"],
                description=config["description"],
                evidence="X-Content-Type-Options headeri topilmadi.",
                proof_of_concept={"header": "X-Content-Type-Options", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="X-Content-Type-Options: nosniff headerini qo'shing.",
                confidence="HIGH",
            ))
        return findings


class ReferrerPolicyHeaderScanner(BaseScanner):
    """Referrer-Policy headerini tekshiradi."""
    name = "Referrer-Policy-Header-Scanner"
    description = "Referrer-Policy headeri mavjudligi va xavfsizligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        ref = headers.get("referrer-policy", "")
        config = settings.SECURITY_HEADERS["Referrer-Policy"]

        if not ref:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: Referrer-Policy",
                severity=config["severity"],
                description=config["description"],
                evidence="Referrer-Policy headeri topilmadi.",
                proof_of_concept={"header": "Referrer-Policy", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="Referrer-Policy headerini qo'shing. Misol: Referrer-Policy: strict-origin-when-cross-origin",
                confidence="HIGH",
            ))
        return findings


class PermissionsPolicyHeaderScanner(BaseScanner):
    """Permissions-Policy headerini tekshiradi."""
    name = "Permissions-Policy-Header-Scanner"
    description = "Permissions-Policy headeri mavjudligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        perm = headers.get("permissions-policy", "")
        config = settings.SECURITY_HEADERS["Permissions-Policy"]

        if not perm:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing Security Header: Permissions-Policy",
                severity=config["severity"],
                description=config["description"],
                evidence="Permissions-Policy headeri topilmadi.",
                proof_of_concept={"header": "Permissions-Policy", "found": False},
                cwe_id=config["cwe"],
                cvss_score=config["cvss"],
                remediation="Permissions-Policy headerini qo'shib, brauzer API'larini cheklang.",
                confidence="HIGH",
            ))
        return findings


class ServerHeaderScanner(BaseScanner):
    """Server headeri versiyasini tekshiradi."""
    name = "Server-Header-Scanner"
    description = "Server headeri orqali web-server versiyasi oshkor bo'lishini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        server = headers.get("server", "")

        if server and any(char.isdigit() for char in server):
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Server Version Disclosure",
                severity="LOW",
                description=f"Server header'i versiya ma'lumotini oshkor qilmoqda: {server}",
                evidence=f"Server: {server}",
                proof_of_concept={"server_header": server},
                cwe_id="CWE-200",
                cvss_score=3.1,
                remediation="Server header'idan versiya ma'lumotini yashiring yoki o'chiring.",
                confidence="HIGH",
            ))
        return findings


class XPoweredByScanner(BaseScanner):
    """X-Powered-By headerini tekshiradi."""
    name = "X-Powered-By-Scanner"
    description = "X-Powered-By headeri orqali texnologiya oshkor bo'lishini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        powered_by = headers.get("x-powered-by", "")

        if powered_by:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Technology Disclosure via X-Powered-By",
                severity="LOW",
                description=f"X-Powered-By header'i ostki texnologiyani oshkor qilmoqda: {powered_by}",
                evidence=f"X-Powered-By: {powered_by}",
                proof_of_concept={"header": "X-Powered-By", "value": powered_by},
                cwe_id="CWE-200",
                cvss_score=2.5,
                remediation="X-Powered-By header'ini o'chiring.",
                confidence="HIGH",
            ))
        return findings
