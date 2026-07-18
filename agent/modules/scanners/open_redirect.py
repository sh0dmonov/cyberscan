"""
Open Redirect Scanner — Custom Module
=======================================
URL parametrlarida ochiq yo'naltirish (Open Redirect) zaifliklarini tekshiradi.
Deep scan rejimida ishlaydi.
"""
import logging
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)

# Ochiq yo'naltirish uchun test payloadlari
REDIRECT_PAYLOADS = [
    "https://evil-attacker.com",
    "//evil-attacker.com",
    "https://evil-attacker.com%2F@legitimate.com",
    "/%09/evil-attacker.com",
]

# Odatda redirect uchun ishlatiladigan parametr nomlari
REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnto", "next", "target", "url", "goto", "destination", "dest",
    "rurl", "r", "callback", "continue", "forward", "location",
]


class OpenRedirectScanner(BaseScanner):
    """
    Open Redirect zaifliklarini tekshiruvchi custom scanner.
    URL parametrlari va forma action'larida redirect parametrlarini aniqlaydi.
    """
    name = "Open-Redirect-Scanner"
    description = "URL parametrlardagi ochiq yo'naltirish (Open Redirect) zaifliklarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"Open Redirect scan boshlandi: {target.url}")

        # 1. Mavjud URL parametrlarini tekshirish
        parsed = urlparse(target.url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in params:
                if param_name.lower() in REDIRECT_PARAMS:
                    finding = await self._test_redirect_param(
                        target.url, param_name
                    )
                    if finding:
                        findings.append(finding)
                        break

        # 2. Umumiy redirect parametr nomlarini URL ga qo'shib sinash
        if not findings:
            for param_name in REDIRECT_PARAMS[:5]:  # Eng ko'p uchraydigan 5 ta
                test_url = f"{target.url.rstrip('/')}/?{param_name}=https://example.com"
                finding = await self._test_redirect_param(test_url, param_name)
                if finding:
                    findings.append(finding)
                    break

        logger.info(f"Open Redirect scan yakunlandi. {len(findings)} ta finding.")
        return findings

    async def _test_redirect_param(
        self, url: str, param_name: str
    ) -> "RawFinding | None":
        """Bitta parametrni redirect payloadlari bilan sinaydi."""
        for payload in REDIRECT_PAYLOADS:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            # allow_redirects=False — redirect bo'lsa ushlaymiz
            try:
                client = await self._get_client()
                resp = await client.get(test_url, follow_redirects=False)
            except Exception:
                continue

            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                # Tashqi domenga yo'naltirishmi?
                if location and (
                    "evil-attacker.com" in location
                    or payload.lstrip("/") in location
                ):
                    return self._make_finding(
                        target_url=url,
                        vulnerability_name="Open Redirect Vulnerability",
                        severity="MEDIUM",
                        description=(
                            f"'{param_name}' parametriga tashqi URL kiritilganda "
                            f"server foydalanuvchini tashqi saytga yo'naltirmoqda. "
                            f"Phishing hujumlari uchun ishlatilishi mumkin."
                        ),
                        evidence=(
                            f"Test URL: {test_url}\n"
                            f"HTTP Status: {resp.status_code}\n"
                            f"Location header: {location}"
                        ),
                        proof_of_concept={
                            "parameter": param_name,
                            "payload": payload,
                            "test_url": test_url,
                            "redirect_status": resp.status_code,
                            "redirect_location": location,
                        },
                        cwe_id="CWE-601",
                        cvss_score=6.1,
                        remediation=(
                            "Redirect URL'larni whitelist (ruxsat etilgan ro'yxat) orqali tekshiring. "
                            "Foydalanuvchi kiritgan URL'larni to'g'ridan-to'g'ri ishlatmang. "
                            "Faqat ichki sahifalarga yo'naltirishga ruxsat bering."
                        ),
                        confidence="HIGH",
                    )
        return None
