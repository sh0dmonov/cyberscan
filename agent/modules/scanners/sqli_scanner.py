"""
SQL Injection Scanners — Custom Modules
========================================
Error-based va Boolean-based SQL Injection testlari uchun alohida klasslar.
Bu skanerlash tarkibini ko'paytirish va batafsil tahlil qilish imkonini beradi.
"""
import logging
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from bs4 import BeautifulSoup

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding
from agent.config import settings

logger = logging.getLogger(__name__)


class SqliErrorScanner(BaseScanner):
    """Error-based SQL Injection zaifligini tekshiradi."""
    name = "SQLi-Error-Scanner"
    description = "SQL xato xabarlari orqali SQL Injection zaifliklarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        logger.info(f"Sqli Error scan boshlandi: {target.url}")

        response = await self.get(target.url)
        if not response:
            return findings

        # 1. URL query parametrlari error-based SQLi
        parsed = urlparse(target.url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                test_url = self._inject_param(target.url, param_name, "'")
                test_resp = await self.get(test_url)
                if test_resp and self._has_sql_error(test_resp.text):
                    db_type = self._detect_db_type(test_resp.text)
                    findings.append(self._make_finding(
                        target_url=target.url,
                        vulnerability_name="SQL Injection (Error-Based)",
                        severity="CRITICAL",
                        description=f"URL parametri '{param_name}' SQL xatosiga sabab bo'ldi. Ma'lumotlar bazasi: {db_type}.",
                        evidence=f"URL: {test_url}\nParameter: {param_name}\nPayload: '\nDatabase: {db_type}",
                        proof_of_concept={"url": test_url, "parameter": param_name, "payload": "'", "db_type": db_type},
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation="SQL so'rovlarini to'liq parametrli (Prepared Statements) ko'rinishga keltiring. ORM ishlating.",
                        confidence="HIGH",
                    ))
                    break  # bitta param yetarli

        # 2. HTML formalari error-based SQLi
        soup = BeautifulSoup(response.text, "lxml")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", target.url)
            method = form.get("method", "get").upper()
            form_url = urljoin(target.url, action)

            inputs = form.find_all(["input", "textarea"])
            text_inputs = [
                inp for inp in inputs
                if inp.get("type", "text").lower()
                   not in ("submit", "button", "checkbox", "radio", "file", "image")
            ]

            for inp in text_inputs:
                name = inp.get("name")
                if not name:
                    continue

                test_data = {}
                for i in inputs:
                    n = i.get("name")
                    if n:
                        test_data[n] = "'" if n == name else i.get("value", "test")

                if method == "POST":
                    test_resp = await self.post(form_url, data=test_data)
                else:
                    test_resp = await self.get(form_url, params=test_data)

                if test_resp and self._has_sql_error(test_resp.text):
                    findings.append(self._make_finding(
                        target_url=form_url,
                        vulnerability_name="SQL Injection (Error-Based) via Form",
                        severity="CRITICAL",
                        description=f"Forma parametri '{name}' SQL xatosiga sabab bo'ldi. SQL Injection aniqlandi.",
                        evidence=f"URL: {form_url}\nMethod: {method}\nParameter: {name}\nPayload: '",
                        proof_of_concept={"url": form_url, "method": method, "parameter": name, "payload": "'"},
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                        remediation="Foydalanuvchi kiritgan form ma'lumotlarini SQL so'roviga to'g'ridan-to'g'ri qo'shmang (Prepared Statements).",
                        confidence="HIGH",
                    ))
                    break
        return findings

    def _has_sql_error(self, text: str) -> bool:
        text_lower = text.lower()
        return any(sig in text_lower for sig in settings.SQLI_ERROR_SIGNATURES)

    def _detect_db_type(self, text: str) -> str:
        text_lower = text.lower()
        if "mysql" in text_lower or "mariadb" in text_lower:
            return "MySQL/MariaDB"
        if "postgresql" in text_lower or "pg::" in text_lower:
            return "PostgreSQL"
        if "sqlite" in text_lower:
            return "SQLite"
        if "oracle" in text_lower or "ora-" in text_lower:
            return "Oracle"
        if "microsoft" in text_lower or "mssql" in text_lower or "sql server" in text_lower:
            return "Microsoft SQL Server"
        return "Noma'lum"

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()


class SqliBooleanScanner(BaseScanner):
    """Boolean-based Blind SQL Injection zaifligini tekshiradi."""
    name = "SQLi-Boolean-Scanner"
    description = "TRUE va FALSE shartlari orqali Blind SQL Injection zaifligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        if target.depth == "quick":
            return findings  # boolean-based blind test quick rejimda o'tkazib yuboriladi

        logger.info(f"Sqli Boolean scan boshlandi: {target.url}")

        # 1. URL query parametrlari
        parsed = urlparse(target.url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                finding = await self._test_boolean_url(target.url, param_name)
                if finding:
                    findings.append(finding)
                    return findings  # bitta topilsa yetarli

        # 2. HTML formalar — avval yo'q edi (kamchilik tuzatildi)
        response = await self.get(target.url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, "lxml")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", target.url)
            method = form.get("method", "get").upper()
            form_url = urljoin(target.url, action)

            inputs = form.find_all(["input", "textarea"])
            text_inputs = [
                inp for inp in inputs
                if inp.get("type", "text").lower()
                   not in ("submit", "button", "checkbox", "radio", "file", "image", "hidden")
            ]

            for inp in text_inputs:
                param_name = inp.get("name")
                if not param_name:
                    continue

                base_data = {}
                for i in inputs:
                    n = i.get("name")
                    if n:
                        base_data[n] = i.get("value", "test")

                finding = await self._test_boolean_form(
                    form_url, param_name, method, base_data, target.url
                )
                if finding:
                    findings.append(finding)
                    return findings

        return findings

    async def _test_boolean_url(self, url: str, param_name: str) -> Optional[RawFinding]:
        """URL parametri uchun boolean SQLi testi."""
        true_url = self._inject_param(url, param_name, "1 AND 1=1")
        false_url = self._inject_param(url, param_name, "1 AND 1=2")

        true_resp = await self.get(true_url)
        false_resp = await self.get(false_url)

        if not true_resp or not false_resp:
            return None

        return self._evaluate_diff(
            param_name, true_resp.text, false_resp.text, url
        )

    async def _test_boolean_form(
        self, form_url: str, param_name: str, method: str,
        base_data: dict, target_url: str
    ) -> Optional[RawFinding]:
        """HTML forma parametri uchun boolean SQLi testi."""
        true_data = {**base_data, param_name: "1 AND 1=1"}
        false_data = {**base_data, param_name: "1 AND 1=2"}

        if method == "POST":
            true_resp = await self.post(form_url, data=true_data)
            false_resp = await self.post(form_url, data=false_data)
        else:
            true_resp = await self.get(form_url, params=true_data)
            false_resp = await self.get(form_url, params=false_data)

        if not true_resp or not false_resp:
            return None

        return self._evaluate_diff(
            param_name, true_resp.text, false_resp.text, target_url,
            via_form=True, method=method
        )

    def _evaluate_diff(
        self, param_name: str, true_text: str, false_text: str, target_url: str,
        via_form: bool = False, method: str = "GET"
    ) -> Optional[RawFinding]:
        """Response hajmidagi farqni baholaydi."""
        true_len = len(true_text)
        false_len = len(false_text)

        if true_len > 0 and false_len > 0:
            diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
            if diff_ratio > 0.15:  # 15% dan yuqori farq bo'lsa
                source = f"Form ({method})" if via_form else "URL param"
                return self._make_finding(
                    target_url=target_url,
                    vulnerability_name="SQL Injection (Boolean-Based -- Ehtimoliy)",
                    severity="HIGH",
                    description=(
                        f"Parametr '{param_name}' uchun TRUE va FALSE SQL so'rovlar "
                        f"har xil uzunlikdagi sahifalarni qaytardi ({diff_ratio:.0%} farq). "
                        f"Manba: {source}."
                    ),
                    evidence=(
                        f"TRUE payload ({true_len} bayt)\n"
                        f"FALSE payload ({false_len} bayt)\n"
                        f"Farq: {diff_ratio:.0%}"
                    ),
                    proof_of_concept={
                        "parameter": param_name,
                        "true_payload": "1 AND 1=1",
                        "false_payload": "1 AND 1=2",
                        "difference_ratio": round(diff_ratio, 3),
                        "via_form": via_form,
                    },
                    cwe_id="CWE-89",
                    cvss_score=8.5,
                    remediation="Barcha query parametrlarini SQL so'rovlariga Prepared Statements orqali uzating.",
                    confidence="MEDIUM",
                )
        return None

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()
