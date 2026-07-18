"""
HTTP Method Scanner — Custom Module
=====================================
Xavfli HTTP metodlarini (PUT, DELETE, TRACE, OPTIONS) tekshiradi.
Deep scan rejimida ishlaydi.
"""
import logging
from typing import List

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)

DANGEROUS_METHODS = {
    "PUT":     ("CWE-650", 7.5, "PUT metodi fayl yuklash va mavjudini o'zgartirish imkonini beradi."),
    "DELETE":  ("CWE-650", 8.1, "DELETE metodi server resurslarini o'chirish imkonini beradi."),
    "TRACE":   ("CWE-16",  5.8, "TRACE metodi XST (Cross-Site Tracing) hujumiga yo'l ochishi mumkin."),
    "CONNECT": ("CWE-441", 6.5, "CONNECT metodi proxy tunnel yaratishga imkon beradi."),
}


class HttpMethodScanner(BaseScanner):
    """
    Xavfli HTTP metodlarini tekshiruvchi custom scanner.
    OPTIONS metodi orqali serverning qaysi metodlarni qo'llashini aniqlaydi.
    """
    name = "HTTP-Method-Scanner"
    description = "Xavfli HTTP metodlarini (PUT, DELETE, TRACE) tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"HTTP Method scan boshlandi: {target.url}")

        # OPTIONS orqali ruxsat etilgan metodlarni so'rash
        options_resp = await self._request("OPTIONS", target.url)
        allowed_methods: set[str] = set()

        if options_resp:
            allow_header = options_resp.headers.get("allow", "")
            allowed_methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}

        # Har bir xavfli metodni alohida sinab ko'rish
        for method, (cwe, cvss, risk_desc) in DANGEROUS_METHODS.items():
            if method in allowed_methods:
                # OPTIONS dan topildi — xavfli
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name=f"Dangerous HTTP Method Allowed: {method}",
                    severity="HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                    description=(
                        f"Server {method} HTTP metodini qabul qilmoqda. {risk_desc}"
                    ),
                    evidence=(
                        f"OPTIONS javobi Allow header'i: {allow_header}\n"
                        f"Xavfli metod: {method}"
                    ),
                    proof_of_concept={
                        "method": method,
                        "url": target.url,
                        "detected_via": "OPTIONS Allow header",
                        "allow_header": allow_header,
                    },
                    cwe_id=cwe,
                    cvss_score=cvss,
                    remediation=(
                        f"Web server konfiguratsiyasida {method} metodini o'chiring. "
                        f"Nginx: limit_except GET POST {{ deny all; }}\n"
                        f"Apache: <LimitExcept GET POST> Deny from all </LimitExcept>"
                    ),
                    confidence="HIGH",
                ))
            else:
                # Amalda sinab ko'rish (false positive kamaytirish uchun tekshiruv)
                if method == "TRACE":
                    resp = await self._request("TRACE", target.url)
                    if resp and resp.status_code in (200, 405):
                        if resp.status_code == 200:
                            findings.append(self._make_finding(
                                target_url=target.url,
                                vulnerability_name="HTTP TRACE Method Enabled",
                                severity="MEDIUM",
                                description=risk_desc,
                                evidence=f"TRACE {target.url} → HTTP {resp.status_code}",
                                proof_of_concept={
                                    "method": "TRACE",
                                    "status_code": resp.status_code,
                                    "url": target.url,
                                },
                                cwe_id=cwe,
                                cvss_score=cvss,
                                remediation=(
                                    "TRACE metodini o'chiring: "
                                    "Apache: TraceEnable Off | Nginx: if ($request_method = TRACE) { return 405; }"
                                ),
                                confidence="HIGH",
                            ))

        logger.info(f"HTTP Method scan yakunlandi. {len(findings)} ta finding.")
        return findings
