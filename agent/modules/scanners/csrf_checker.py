"""
CSRF & Cookie Security Scanners — Custom Modules
==================================================
CSRF form tokenlari va Cookie flags (HttpOnly, Secure, SameSite) alohida klasslar sifatida.
Bu skanerlash tarkibini ko'paytirish va batafsil tahlil qilish imkonini beradi.
"""
import logging
from typing import List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)


class CsrfFormScanner(BaseScanner):
    """POST formalarida CSRF tokenlar mavjudligini tekshiradi."""
    name = "CSRF-Form-Scanner"
    description = "HTML formalarida CSRF himoya tokenlari borligini tekshiradi"

    SENSITIVE_PATTERNS = [
        "password", "email", "account", "profile", "settings",
        "transfer", "payment", "delete", "admin", "change",
        "update", "register", "signup", "login",
    ]

    CSRF_TOKEN_NAMES = [
        "csrf_token", "csrftoken", "_token", "csrf", "_csrf",
        "authenticity_token", "xsrf_token", "__requestverificationtoken",
        "nonce", "anti_csrf", "csrf_field",
    ]

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"CSRF form scan boshlandi: {target.url}")

        response = await self.get(target.url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, "lxml")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").upper()

            if method != "POST":
                continue

            form_url = urljoin(target.url, action) if action else target.url
            all_inputs = form.find_all("input")

            has_csrf = False
            for inp in all_inputs:
                name = (inp.get("name") or "").lower()
                inp_id = (inp.get("id") or "").lower()
                if any(token in name for token in self.CSRF_TOKEN_NAMES) or \
                   any(token in inp_id for token in self.CSRF_TOKEN_NAMES):
                    has_csrf = True
                    break

            if not has_csrf:
                is_sensitive = any(
                    p in (action or "").lower() or p in form.get("id", "").lower()
                    for p in self.SENSITIVE_PATTERNS
                )
                severity = "HIGH" if is_sensitive else "MEDIUM"
                cvss = 7.1 if is_sensitive else 5.4

                findings.append(self._make_finding(
                    target_url=form_url,
                    vulnerability_name="Missing CSRF Token in POST Form",
                    severity=severity,
                    description=f"POST formada CSRF token topilmadi. Form action: '{action or '(joriy sahifa)'}'.",
                    evidence=f"Form action: {form_url}\nMethod: POST\nCSRF token: YO'Q\nInputs: {[i.get('name') for i in all_inputs if i.get('name')]}",
                    proof_of_concept={
                        "form_url": form_url,
                        "method": "POST",
                        "csrf_found": False,
                        "is_sensitive": is_sensitive
                    },
                    cwe_id="CWE-352",
                    cvss_score=cvss,
                    remediation="Har bir POST forma uchun CSRF token yoki anti-forgery token qo'shing. (Laravel: @csrf, Django: {% csrf_token %}).",
                    confidence="HIGH",
                ))
        return findings


class CookieSecurityScanner(BaseScanner):
    """Cookie xavfsizlik atributlarini (HttpOnly, Secure, SameSite) tekshiradi."""
    name = "Cookie-Security-Scanner"
    description = "Cookie flaglarini (HttpOnly, Secure, SameSite) tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        # Set-Cookie headerlarini o'qish (httpx multi_items orqali)
        set_cookie_values = [
            v for k, v in response.headers.multi_items()
            if k.lower() == "set-cookie"
        ]

        for cookie_str in set_cookie_values:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"
            issues = []

            if "httponly" not in parts:
                issues.append("HttpOnly atributi yo'q — JavaScript orqali o'qilishi mumkin")

            if "secure" not in parts and target.url.startswith("https://"):
                issues.append("Secure atributi yo'q — HTTP (shifrsiz) orqali uzatilishi mumkin")

            if issues:
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name=f"Insecure Cookie Configuration: {cookie_name}",
                    severity="MEDIUM",
                    description=f"Cookie xavfsiz sozlanmagan: {'; '.join(issues)}.",
                    evidence=f"Set-Cookie: {cookie_str[:150]}\nMuammolar: {'; '.join(issues)}",
                    proof_of_concept={"cookie_name": cookie_name, "issues": issues, "cookie_header": cookie_str[:150]},
                    cwe_id="CWE-614",
                    cvss_score=4.3,
                    remediation=f"Set-Cookie headeriga xavfsiz flaglarni qo'shing: Set-Cookie: {cookie_name}=value; HttpOnly; Secure; SameSite=Lax",
                    confidence="HIGH",
                ))

            # SameSite tekshiruvi
            if "samesite" not in "".join(parts):
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name=f"Missing SameSite Attribute: {cookie_name}",
                    severity="LOW",
                    description=f"'{cookie_name}' cookie'sida SameSite atributi yo'q. CSRF hujumiga qarshi zaiflik ortadi.",
                    evidence=f"Set-Cookie: {cookie_str[:150]}",
                    proof_of_concept={"cookie_name": cookie_name, "cookie_header": cookie_str[:150]},
                    cwe_id="CWE-352",
                    cvss_score=3.5,
                    remediation=f"Set-Cookie: {cookie_name}=value; SameSite=Strict yoki SameSite=Lax",
                    confidence="HIGH",
                ))

        return findings
