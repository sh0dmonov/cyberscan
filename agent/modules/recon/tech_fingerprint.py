"""
Recon: Tech Fingerprinting + Robots/Sitemap + DNS Audits
=========================================================
CMS/framework, robots.txt, sitemap.xml, DNS SPF, DMARC, MX, Zone Transfer.
"""
import asyncio
import logging
import socket
from typing import List, Optional
from urllib.parse import urljoin

import dns.resolver
from bs4 import BeautifulSoup

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

logger = logging.getLogger(__name__)


class TechFingerprintScanner(BaseScanner):
    """CMS, framework va server texnologiyalarini aniqlaydi."""
    name = "Tech-Fingerprint"
    description = "CMS/framework versiyalari va texnologiyalarini aniqlaydi"

    CMS_SIGNATURES = {
        "WordPress": {
            "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
            "headers": {"x-powered-by": "php"},
            "meta": ["generator.*wordpress"],
            "body": ["wp-content", "wp-includes"],
        },
        "Joomla": {
            "paths": ["/administrator/", "/components/", "/modules/"],
            "body": ["joomla", "/components/com_"],
        },
        "Drupal": {
            "headers": {"x-generator": "drupal"},
            "body": ["drupal.settings", "sites/default/files"],
        },
        "Laravel": {
            "headers": {"x-powered-by": "php"},
            "cookies": ["laravel_session", "XSRF-TOKEN"],
            "body": ["laravel"],
        },
        "Django": {
            "headers": {"x-frame-options": "sameorigin"},
            "cookies": ["csrftoken", "sessionid"],
        },
        "React": {
            "body": ["react", "__react", "reactroot", "data-reactroot"],
        },
        "Angular": {
            "body": ["ng-version", "angular", "_angular_"],
        },
        "Next.js": {
            "headers": {"x-powered-by": "next.js"},
            "body": ["__NEXT_DATA__", "_next/static"],
        },
        "Bootstrap": {
            "body": ["bootstrap.min.css", "bootstrap.min.js"],
        },
    }

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        response = await self.get(target.url)
        if not response:
            return findings

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        body = response.text.lower()
        soup = BeautifulSoup(response.text, "lxml")
        cookies = [c.lower() for c in response.cookies.keys()]

        detected_tech = []
        for tech_name, sigs in self.CMS_SIGNATURES.items():
            score = 0
            for h_key, h_val in sigs.get("headers", {}).items():
                if h_key in headers and h_val in headers[h_key]:
                    score += 2
            for pattern in sigs.get("body", []):
                if pattern.lower() in body:
                    score += 1
            for cookie_name in sigs.get("cookies", []):
                if any(cookie_name in c for c in cookies):
                    score += 3

            if target.depth != "quick":
                for path in sigs.get("paths", []):
                    path_resp = await self.get(urljoin(target.url, path))
                    if path_resp and path_resp.status_code == 200:
                        score += 3

            if score >= 2:
                detected_tech.append(tech_name)

        if detected_tech:
            tech_list = ", ".join(detected_tech)
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Technology Stack Identified",
                severity="INFO",
                description=f"Quyidagi texnologiyalar aniqlandi: {tech_list}.",
                evidence=f"Aniqlangan texnologiyalar: {tech_list}",
                proof_of_concept={"detected_technologies": detected_tech},
                cwe_id="CWE-200",
                cvss_score=0.0,
                remediation="Texnologiya va versiya ma'lumotlarini yashiring.",
                confidence="HIGH",
            ))

        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            gen_content = generator["content"]
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="CMS Version Disclosure via Meta Generator",
                severity="LOW",
                description=f"Meta generator tagi versiyani oshkor qilmoqda: {gen_content}",
                evidence=f'<meta name="generator" content="{gen_content}">',
                proof_of_concept={"generator": gen_content},
                cwe_id="CWE-200",
                cvss_score=3.1,
                remediation="Meta generator tag'ini o'chiring.",
                confidence="HIGH",
            ))

        return findings


class RobotsScanner(BaseScanner):
    """robots.txt tahlili."""
    name = "Robots-Scanner"
    description = "robots.txt faylidagi yashirin yo'llarni aniqlaydi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        robots_url = urljoin(target.url, "/robots.txt")
        response = await self.get(robots_url)
        if response and response.status_code == 200 and "disallow" in response.text.lower():
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in response.text.splitlines()
                if line.lower().startswith("disallow:")
            ]
            disallowed = [d for d in disallowed if d and d != "/"]
            if disallowed:
                findings.append(self._make_finding(
                    target_url=robots_url,
                    vulnerability_name="Sensitive Paths Disclosed in robots.txt",
                    severity="INFO",
                    description=f"robots.txt faylida {len(disallowed)} ta Disallow yo'li topildi.",
                    evidence=f"Disallowed paths:\n" + "\n".join(disallowed[:20]),
                    proof_of_concept={"disallowed_paths": disallowed[:20]},
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    remediation="robots.txt'da maxfiy yo'llarni ro'yxatlamang.",
                    confidence="HIGH",
                ))
        return findings


class SitemapScanner(BaseScanner):
    """sitemap.xml tahlili."""
    name = "Sitemap-Scanner"
    description = "sitemap.xml faylini va undagi sahifalar ro'yxatini aniqlaydi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        sitemap_url = urljoin(target.url, "/sitemap.xml")
        response = await self.get(sitemap_url)
        if response and response.status_code == 200:
            findings.append(self._make_finding(
                target_url=sitemap_url,
                vulnerability_name="Sitemap File Discovered",
                severity="INFO",
                description="Sitemap.xml fayli ochiq holda topildi. Bu sayt xaritasi va tuzilishini ochib beradi.",
                evidence=f"Sitemap URL: {sitemap_url}",
                proof_of_concept={"sitemap_url": sitemap_url},
                cwe_id="CWE-200",
                cvss_score=0.0,
                remediation="Sayt xaritasini oshkor qilish xavfsizlikka to'g'ridan-to'g'ri ta'sir qilmaydi, ammo yashirin sahifalarni kiritmang.",
                confidence="HIGH",
            ))
        return findings


class DnsSpfScanner(BaseScanner):
    """DNS SPF yozuvini tekshiradi."""
    name = "DNS-SPF-Scanner"
    description = "Domenning SPF xavfsizlik yozuvini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            txt_records = resolver.resolve(target.host, "TXT")
            has_spf = any("v=spf1" in str(r) for r in txt_records)
            if not has_spf:
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="Missing SPF Record",
                    severity="MEDIUM",
                    description="SPF DNS yozuvi yo'q — email spoofing xavfi mavjud.",
                    evidence=f"Domain: {target.host}\nSPF TXT yozuvi topilmadi",
                    proof_of_concept={"domain": target.host, "has_spf": False},
                    cwe_id="CWE-346",
                    cvss_score=5.3,
                    remediation='SPF yozuvi qo\'shing: v=spf1 include:_spf.google.com ~all',
                    confidence="HIGH",
                ))
        except Exception:
            pass
        return findings


class DnsDmarcScanner(BaseScanner):
    """DNS DMARC yozuvini tekshiradi."""
    name = "DNS-DMARC-Scanner"
    description = "Domenning DMARC siyosatini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            dmarc = resolver.resolve(f"_dmarc.{target.host}", "TXT")
            has_dmarc = any("v=DMARC1" in str(r) for r in dmarc)
            if not has_dmarc:
                raise ValueError("DMARC record missing")
        except Exception:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Missing DMARC Record",
                severity="MEDIUM",
                description="DMARC DNS yozuvi yo'q — email phishing xavfi.",
                evidence=f"Domain: {target.host}\nDMARC TXT yozuvi topilmadi",
                proof_of_concept={"domain": target.host, "has_dmarc": False},
                cwe_id="CWE-346",
                cvss_score=5.0,
                remediation='DMARC yozuvi qo\'shing: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                confidence="HIGH",
            ))
        return findings


class DnsMxScanner(BaseScanner):
    """DNS MX (Pochta serverlari) yozuvlarini tekshiradi."""
    name = "DNS-MX-Scanner"
    description = "Domenning MX yozuvlarini va pochta serverlari xavfsizligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            mx_records = resolver.resolve(target.host, "MX")
            if mx_records:
                mx_list = [str(r.exchange) for r in mx_records]
                findings.append(self._make_finding(
                    target_url=target.url,
                    vulnerability_name="MX Mail Server Records Discovered",
                    severity="INFO",
                    description=f"Domen uchun pochta serverlari (MX) topildi: {', '.join(mx_list)}",
                    evidence=f"MX exchange servers: {mx_list}",
                    proof_of_concept={"mx_records": mx_list},
                    cwe_id="CWE-200",
                    cvss_score=0.0,
                    remediation="MX yozuvlari ommaviy bo'lishi normal, ammo ushbu pochta serverlari xavfsizligini alohida tekshiring.",
                    confidence="HIGH",
                ))
        except Exception:
            pass
        return findings


class DnsZoneTransferScanner(BaseScanner):
    """DNS Zone Transfer (AXFR) zaifligini tekshiradi."""
    name = "DNS-Zone-Transfer-Scanner"
    description = "DNS Zone Transfer zaifligini tekshiradi"

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        # DNS AXFR test (Zone Transfer check)
        try:
            import dns.zone
            import dns.query
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(target.host, "NS")
            for ns in ns_records:
                ns_ip = socket.gethostbyname(str(ns))
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, target.host, timeout=3))
                    if z:
                        findings.append(self._make_finding(
                            target_url=target.url,
                            vulnerability_name="DNS Zone Transfer (AXFR) Allowed",
                            severity="HIGH",
                            description=f"DNS Server ({ns}) Zone Transfer (AXFR) so'roviga ruxsat bermoqda. Butun DNS zonasi oshkor bo'ldi.",
                            evidence=f"Name Server: {ns} ({ns_ip}) AXFR SUCCESS",
                            proof_of_concept={"ns": str(ns), "ns_ip": ns_ip},
                            cwe_id="CWE-16",
                            cvss_score=7.5,
                            remediation="DNS server konfiguratsiyasida Zone Transfer'ni faqat ikkilamchi (secondary) DNS serverlar uchun ruxsatlang (allow-transfer directives).",
                            confidence="HIGH",
                        ))
                        break
                except Exception:
                    pass
        except Exception:
            pass
        return findings
