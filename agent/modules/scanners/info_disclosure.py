"""
Information Disclosure Scanners — Custom Modules
==================================================
Har bir maxfiy fayl va yo'l alohida scanner klassi sifatida yozilgan.
Bu skanerlash sonini ko'paytirish va monitoringni kuchaytirish imkonini beradi.
"""
import logging
from typing import List, Optional
from urllib.parse import urljoin

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)


class EnvFileScanner(BaseScanner):
    """.env fayli ochiqligini tekshiradi."""
    name = "Env-File-Scanner"
    description = ".env va muhit sozlamalari fayllarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/.env", "/.env.local", "/.env.production", "/.env.backup"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response and response.status_code == 200 and len(response.content) > 0:
                # Soft 404 test: agar response HTML bo'lsa yoki shunchaki default sahifa bo'lsa o'tkazib yuborish
                content_lower = response.text.lower()
                if "html" in content_lower or "<body" in content_lower:
                    continue

                secrets_found = []
                for keyword in ("password", "secret", "key", "token", "database"):
                    if keyword in content_lower:
                        secrets_found.append(keyword)

                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="Sensitive File Exposed: .env",
                    severity="CRITICAL",
                    description=f".env fayli internet orqali ochiq holda topildi! Aniqlangan kalit so'zlar: {', '.join(secrets_found)}",
                    evidence=f"HTTP 200 OK\nSize: {len(response.content)} bytes\nContent-Type: {response.headers.get('content-type', '')}",
                    proof_of_concept={"path": path, "secrets_found": secrets_found},
                    cwe_id="CWE-538",
                    cvss_score=9.8,
                    remediation=".env faylini web root'dan tashqariga ko'chiring. Serverda .env ga kirishni taqiqlang.",
                    confidence="HIGH",
                ))
                break # bitta topilsa yetarli
        return findings


class GitRepoScanner(BaseScanner):
    """.git papkasi ochiqligini tekshiradi."""
    name = "Git-Repo-Scanner"
    description = ".git/config va boshqa git fayllarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        url = base_url + "/.git/config"

        response = await self.get(url)
        if response:
            if response.status_code == 200 and "[core]" in response.text:
                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="Git Repository Exposed",
                    severity="HIGH",
                    description="Git repository (.git/config) ochiq holda topildi. Bu butun kod bazasini yuklab olish imkonini beradi.",
                    evidence=f"HTTP 200 OK\nContent:\n{response.text[:200]}",
                    proof_of_concept={"path": "/.git/config"},
                    cwe_id="CWE-200",
                    cvss_score=7.5,
                    remediation=".git papkasiga veb orqali kirishni bloklang. production serverdan .git papkasini butunlay o'chiring.",
                    confidence="HIGH",
                ))
            elif response.status_code == 403:
                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="Sensitive Path Exists (Access Denied): /.git/config",
                    severity="INFO",
                    description="/.git/config yo'li mavjud, biroq serverda kirish cheklangan (403).",
                    evidence="HTTP 403 Forbidden",
                    proof_of_concept={"status_code": 403},
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    remediation="Yo'l himoyalangan, ammo xavfsizlik uchun serverdan butunlay o'chirish tavsiya etiladi.",
                    confidence="MEDIUM",
                ))
        return findings


class BackupFileScanner(BaseScanner):
    """Zaxira (backup) fayllarini tekshiradi."""
    name = "Backup-File-Scanner"
    description = "backup.zip, backup.sql, database.sql kabi fayllarni tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/database.sql", "/dump.sql"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response and response.status_code == 200 and len(response.content) > 100:
                if "html" in response.text.lower() or "<body" in response.text.lower():
                    continue

                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name=f"Sensitive File Exposed: {path}",
                    severity="CRITICAL",
                    description=f"Backup yoki ma'lumotlar bazasi dump fayli ({path}) ommaviy kirishda topildi.",
                    evidence=f"HTTP 200 OK\nSize: {len(response.content)} bytes",
                    proof_of_concept={"path": path, "size": len(response.content)},
                    cwe_id="CWE-538",
                    cvss_score=9.5,
                    remediation="Zaxira fayllarini web root'dan tashqariga saqlang. Ushbu ochiq fayllarni darhol o'chiring.",
                    confidence="HIGH",
                ))
        return findings


class PhpInfoScanner(BaseScanner):
    """phpinfo() sahifasi ochiqligini tekshiradi."""
    name = "PHPInfo-Scanner"
    description = "phpinfo.php va info.php sahifalarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/phpinfo.php", "/info.php", "/test.php"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response and response.status_code == 200 and "php version" in response.text.lower():
                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="PHPInfo Page Exposed",
                    severity="HIGH",
                    description="phpinfo() sahifasi ommaviy ochiq holda topildi. Bu server yo'llari, versiyalar va muhit o'zgaruvchilarini oshkor qiladi.",
                    evidence=f"HTTP 200 OK\nPHP Version identified in response body",
                    proof_of_concept={"path": path},
                    cwe_id="CWE-200",
                    cvss_score=7.2,
                    remediation="Ushbu phpinfo() sahifasini serverdan darhol o'chiring.",
                    confidence="HIGH",
                ))
                break
        return findings


class PhpMyAdminScanner(BaseScanner):
    """phpMyAdmin panelini tekshiradi."""
    name = "PHPMyAdmin-Scanner"
    description = "phpmyadmin, pma admin panellarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/phpmyadmin/", "/pma/", "/dbadmin/"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response:
                if response.status_code == 200 and "phpmyadmin" in response.text.lower():
                    findings.append(self._make_finding(
                        target_url=url,
                        vulnerability_name="PHPMyAdmin Panel Exposed",
                        severity="HIGH",
                        description="PHPMyAdmin kirish paneli ommaviy ochiq holda topildi. Brute-force xavfi yuqori.",
                        evidence="HTTP 200 OK\nPHPMyAdmin login screen detected",
                        proof_of_concept={"path": path},
                        cwe_id="CWE-200",
                        cvss_score=7.8,
                        remediation="PHPMyAdmin kirishini faqat ma'lum IP manzillar (whitelist) yoki VPN orqali cheklang.",
                        confidence="HIGH",
                    ))
                    break
                elif response.status_code == 403:
                    findings.append(self._make_finding(
                        target_url=url,
                        vulnerability_name=f"Sensitive Path Exists (Access Denied): {path}",
                        severity="INFO",
                        description=f"'{path}' yo'li serverda mavjud, ammo kirish cheklangan (403).",
                        evidence="HTTP 403 Forbidden",
                        proof_of_concept={"path": path, "status_code": 403},
                        cwe_id="CWE-200",
                        cvss_score=2.0,
                        remediation="Panel himoyalangan, biroq port/url'ni butunlay yopish tavsiya etiladi.",
                        confidence="MEDIUM",
                    ))
                    break
        return findings


class SwaggerApiScanner(BaseScanner):
    """API dokumentatsiyasi ochiqligini tekshiradi."""
    name = "Swagger-API-Scanner"
    description = "swagger-ui, openapi.json kabi API hujjatlarini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/api/swagger.json", "/api/openapi.json", "/swagger-ui.html", "/swagger/index.html"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response and response.status_code == 200 and ("swagger" in response.text.lower() or "openapi" in response.text.lower()):
                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="API Documentation Exposed",
                    severity="MEDIUM",
                    description=f"API hujjatlari ({path}) ommaga ochiq. Barcha endpoint va parametrlar oshkor bo'lmoqda.",
                    evidence=f"HTTP 200 OK\nSwagger/OpenAPI UI detected",
                    proof_of_concept={"path": path},
                    cwe_id="CWE-200",
                    cvss_score=5.3,
                    remediation="API hujjatlarini faqat autentifikatsiyadan o'tgan administratorlar uchun ruxsat bering.",
                    confidence="HIGH",
                ))
                break
        return findings


class SpringBootActuatorScanner(BaseScanner):
    """Spring Boot Actuator ochiqligini tekshiradi."""
    name = "SpringBoot-Actuator-Scanner"
    description = "/actuator, /actuator/env Spring Boot endpoint'larini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        base_url = target.url.rstrip("/")
        paths = ["/actuator", "/actuator/env", "/actuator/health"]

        for path in paths:
            url = base_url + path
            response = await self.get(url)
            if response and response.status_code == 200 and ("_links" in response.text or "health" in response.text):
                findings.append(self._make_finding(
                    target_url=url,
                    vulnerability_name="Spring Boot Actuator Exposed",
                    severity="HIGH",
                    description=f"Spring Boot Actuator API ({path}) ochiq. Server sozlamalari va metrikalar oshkor bo'lishi mumkin.",
                    evidence=f"HTTP 200 OK\nActuator response body detected",
                    proof_of_concept={"path": path},
                    cwe_id="CWE-200",
                    cvss_score=8.1,
                    remediation="Actuator endpoint'larini Spring Security orqali to'liq yoping yoki autentifikatsiyali qiling.",
                    confidence="HIGH",
                ))
                break
        return findings
