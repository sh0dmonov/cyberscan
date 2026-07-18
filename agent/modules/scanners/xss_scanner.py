"""
Reflected XSS Scanner — Custom Module
======================================
HTML formalarni topib, input parametrlarini aniqlaydi
va payload injection orqali Reflected XSS ni tekshiradi.
"""
import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlencode, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding
from agent.config import settings

logger = logging.getLogger(__name__)


class XssScanner(BaseScanner):
    """
    Reflected XSS tekshiruvchi custom scanner.
    Formalar va URL parametrlarini tahlil qilib, payload injection amalga oshiradi.
    """
    name = "Custom-XSS-Scanner"
    description = "Reflected XSS zaifliklarini aniqlaydi (form inputs va URL params)"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"XSS scan boshlandi: {target.url}")

        # Asosiy sahifani yuklab olish
        response = await self.get(target.url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, "lxml")

        # 1. URL parametrlarini tekshirish
        url_findings = await self._check_url_params(target.url)
        findings.extend(url_findings)

        # 2. Formalarni topib tekshirish
        forms = soup.find_all("form")
        logger.info(f"{len(forms)} ta forma topildi")

        for form in forms:
            form_findings = await self._check_form(target.url, form)
            findings.extend(form_findings)
            if findings:  # Quick mode'da birinchi topilgandan keyin to'xtash
                if target.depth == "quick":
                    break

        logger.info(f"XSS scan yakunlandi. {len(findings)} ta finding topildi.")
        return findings

    async def _check_url_params(self, url: str) -> List[RawFinding]:
        """URL'dagi mavjud query parametrlarini XSS uchun tekshiradi."""
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in settings.XSS_PAYLOADS[:3]:  # Asosiy payloadlar
                test_url = self._inject_url_param(url, param_name, payload)
                finding = await self._test_payload(
                    test_url, payload, param_name, "GET", None
                )
                if finding:
                    findings.append(finding)
                    break  # Bitta payload ishlasa, keyingiga o'tish

        return findings

    async def _check_form(self, base_url: str, form) -> List[RawFinding]:
        """Bitta HTML formani XSS uchun tekshiradi."""
        findings = []

        action = form.get("action", base_url)
        method = form.get("method", "get").upper()
        form_url = urljoin(base_url, action)

        # Input fieldlarni topish
        inputs = form.find_all(["input", "textarea", "select"])
        text_inputs = [
            inp for inp in inputs
            if inp.get("type", "text").lower()
               not in ("hidden", "submit", "button", "checkbox", "radio", "file")
        ]

        if not text_inputs:
            return findings

        for payload in settings.XSS_PAYLOADS[:4]:
            # Barcha text inputlarga payload joylash
            form_data = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                inp_type = inp.get("type", "text").lower()
                if inp_type in ("hidden",):
                    form_data[name] = inp.get("value", "")
                elif inp_type in ("submit", "button"):
                    form_data[name] = inp.get("value", "Submit")
                else:
                    form_data[name] = payload  # Payload joylash

            if not form_data:
                continue

            finding = await self._test_payload(
                form_url, payload, str(list(form_data.keys())), method, form_data
            )
            if finding:
                findings.append(finding)
                break

        return findings

    async def _test_payload(
        self,
        url: str,
        payload: str,
        parameter: str,
        method: str,
        data: Optional[dict],
    ) -> Optional[RawFinding]:
        """Payload'ni yuborib, response'da qaytib kelganini tekshiradi."""
        if method == "POST":
            response = await self.post(url, data=data)
        else:
            response = await self.get(url, params=data)

        if not response:
            return None

        response_text = response.text

        # Payload encode qilinmagan holda response'da mavjudmi?
        payload_in_response = payload in response_text

        if payload_in_response:
            # Payload faqat encode qilingan holda mavjudmi tekshirish
            # Agar encode qilinmagan holda HAM bo'lsa — zaiflik aniq
            encoded_versions = [
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace("<", "%3C").replace(">", "%3E"),
            ]
            # Agar payload faqat encoded holda bo'lsa — xavfsiz
            # Lekin encode qilinmagan holda mavjud bo'lsa — ZAIFLIK
            # (oldingi noto'g'ri mantiq: encoded version bo'lsa ham None qaytarardi)
            only_encoded = all(enc in response_text for enc in encoded_versions) and \
                           not any(enc == payload for enc in encoded_versions)
            if only_encoded:
                # Faqat encoded — xavfsiz
                return None

            return self._make_finding(
                target_url=url,
                vulnerability_name="Reflected Cross-Site Scripting (XSS)",
                severity="HIGH",
                description=(
                    f"Reflected XSS topildi. '{parameter}' parametriga yuborilgan payload "
                    f"HTML response'da encode qilinmagan holda qaytdi."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Method: {method}\n"
                    f"Parameter: {parameter}\n"
                    f"Payload: {payload}\n"
                    f"Natija: Payload response'da topildi (encode qilinmagan)"
                ),
                proof_of_concept={
                    "url": str(url),
                    "method": method,
                    "parameter": parameter,
                    "payload": payload,
                    "evidence": "Payload reflected in response without HTML encoding",
                    "response_status": response.status_code,
                },
                cwe_id="CWE-79",
                cvss_score=7.2,
                remediation=(
                    "Barcha foydalanuvchi kiritgan ma'lumotlarni HTML encode qiling. "
                    "Content-Security-Policy header'ini qo'shing. "
                    "Output encoding uchun kutubxonalardan foydalaning "
                    "(Python: html.escape(), PHP: htmlspecialchars())."
                ),
                confidence="HIGH",
            )

        return None

    def _inject_url_param(self, url: str, param_name: str, value: str) -> str:
        """URL'dagi ma'lum parametr qiymatini almashtiradi."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()
