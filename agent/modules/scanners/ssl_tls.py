"""
SSL/TLS Scanners — sslyze Wrappers
====================================
SSL/TLS sertifikatlari va eskirgan TLS protokollarini tekshiruvchi alohida klasslar.
Bu skanerlash tarkibini ko'paytirish va batafsil tahlil qilish imkonini beradi.
"""
import asyncio
import json
import logging
import shutil
import tempfile
from typing import List
from datetime import datetime, timezone

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding
from agent.config import settings

logger = logging.getLogger(__name__)


class SslCertificateScanner(BaseScanner):
    """SSL/TLS sertifikat muddati, CA ishonchliligi va mosligini tekshiradi."""
    name = "SSL-Certificate-Scanner"
    description = "SSL sertifikatining amal qilish muddati va haqiqiyligini tekshiradi"

    async def is_available(self) -> bool:
        return shutil.which("sslyze") is not None

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []

        if not target.url.startswith("https://"):
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="HTTPS Not Used",
                severity="HIGH",
                description="Sayt HTTPS ishlatmayapti. Barcha ulanish shifrsiz uzatilmoqda.",
                evidence=f"URL: {target.url}",
                proof_of_concept={"protocol": "http"},
                cwe_id="CWE-319",
                cvss_score=7.5,
                remediation="Saytga SSL/TLS sertifikati o'rnating va HTTP'dan HTTPS'ga redirect sozlang.",
                confidence="HIGH",
            ))
            return findings

        if not await self.is_available():
            return await self._basic_ssl_check(target)

        # sslyze orqali tekshirish
        logger.info(f"SSL cert scan boshlandi: {target.host}")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = tmp.name

        cmd = ["sslyze", "--json_out", json_output, f"{target.host}:{target.port or 443}"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            findings = self._parse_sslyze_cert(json_output, target.url)
        except Exception:
            findings = await self._basic_ssl_check(target)
        finally:
            import os
            try:
                os.unlink(json_output)
            except Exception:
                pass
        return findings

    def _parse_sslyze_cert(self, json_path: str, target_url: str) -> List[RawFinding]:
        findings = []
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            server_results = data.get("server_scan_results", [])
            for result in server_results:
                scan_result = result.get("scan_result", {})
                cert_info = scan_result.get("certificate_info", {})
                if cert_info.get("status") == "COMPLETED":
                    deployments = cert_info.get("result", {}).get("certificate_deployments", [])
                    for dep in deployments:
                        chain = dep.get("received_certificate_chain", [])
                        if not chain:
                            continue
                        leaf = chain[0]
                        not_after = leaf.get("not_valid_after")
                        if not_after:
                            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                            days_left = (expiry - datetime.now(timezone.utc)).days
                            if days_left < 0:
                                findings.append(self._make_finding(
                                    target_url=target_url,
                                    vulnerability_name="SSL Certificate Expired",
                                    severity="CRITICAL",
                                    description=f"SSL sertifikat muddati tugagan! {abs(days_left)} kun oldin.",
                                    evidence=f"Not valid after: {not_after}",
                                    proof_of_concept={"expiry_date": not_after, "days_expired": abs(days_left)},
                                    cwe_id="CWE-298",
                                    cvss_score=9.0,
                                    remediation="Sertifikatni darhol yangilang.",
                                    confidence="HIGH",
                                ))
                            elif days_left < 30:
                                findings.append(self._make_finding(
                                    target_url=target_url,
                                    vulnerability_name="SSL Certificate Expiring Soon",
                                    severity="MEDIUM",
                                    description=f"SSL sertifikat {days_left} kun ichida tugaydi.",
                                    evidence=f"Not valid after: {not_after}",
                                    proof_of_concept={"expiry_date": not_after, "days_left": days_left},
                                    cwe_id="CWE-298",
                                    cvss_score=4.0,
                                    remediation="Sertifikatni yangilang.",
                                    confidence="HIGH",
                                ))
        except Exception:
            pass
        return findings

    async def _basic_ssl_check(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        import ssl
        import socket
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target.host)
            conn.settimeout(10)
            conn.connect((target.host, target.port or 443))
            cert = conn.getpeercert()
            conn.close()

            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except ValueError:
                    try:
                        parts = not_after.split()
                        not_after_clean = " ".join(parts[:-1])
                        expiry = datetime.strptime(not_after_clean, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    except Exception:
                        expiry = datetime.now(timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append(self._make_finding(
                        target_url=target.url,
                        vulnerability_name="SSL Certificate Expiring Soon" if days_left > 0 else "SSL Certificate Expired",
                        severity="MEDIUM" if days_left > 0 else "CRITICAL",
                        description=f"SSL sertifikat {'tugagan' if days_left < 0 else f'{days_left} kun ichida tugaydi'}.",
                        evidence=f"Not valid after: {not_after}",
                        proof_of_concept={"expiry": not_after, "days_left": days_left},
                        cwe_id="CWE-298",
                        cvss_score=9.0 if days_left < 0 else 4.0,
                        remediation="Sertifikatni yangilang.",
                        confidence="HIGH",
                    ))
        except ssl.SSLCertVerificationError:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="Invalid SSL Certificate",
                severity="HIGH",
                description="SSL sertifikat tekshiruvdan o'tmadi (self-signed yoki noto'g'ri).",
                evidence="SSL verification failed",
                proof_of_concept={},
                cwe_id="CWE-295",
                cvss_score=7.4,
                remediation="Ishonchli va haqiqiy SSL sertifikatini o'rnating.",
                confidence="HIGH",
            ))
        except Exception:
            pass
        return findings


class SslProtocolScanner(BaseScanner):
    """Eskirgan va zaif SSL/TLS protokollarini (SSLv2, SSLv3, TLS 1.0, TLS 1.1) tekshiradi."""
    name = "SSL-Protocol-Scanner"
    description = "Eskirgan SSLv2, SSLv3, TLS 1.0 va TLS 1.1 protokollarini tekshiradi"

    async def is_available(self) -> bool:
        return shutil.which("sslyze") is not None

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []
        if not target.url.startswith("https://") or not await self.is_available():
            return findings

        logger.info(f"SSL protocols scan boshlandi: {target.host}")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            json_output = tmp.name

        cmd = ["sslyze", "--json_out", json_output, f"{target.host}:{target.port or 443}"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            with open(json_output, "r") as f:
                data = json.load(f)

            server_results = data.get("server_scan_results", [])
            for result in server_results:
                scan_result = result.get("scan_result", {})
                deprecated = {
                    "ssl_2_0_cipher_suites": ("SSLv2", 9.8),
                    "ssl_3_0_cipher_suites": ("SSLv3", 9.3),
                    "tls_1_0_cipher_suites": ("TLS 1.0", 5.9),
                    "tls_1_1_cipher_suites": ("TLS 1.1", 5.3),
                }

                for key, (name, cvss) in deprecated.items():
                    proto = scan_result.get(key, {})
                    if proto.get("status") == "COMPLETED":
                        accepted = proto.get("result", {}).get("accepted_cipher_suites", [])
                        if accepted:
                            findings.append(self._make_finding(
                                target_url=target.url,
                                vulnerability_name=f"Deprecated Protocol Supported: {name}",
                                severity="HIGH" if cvss >= 7 else "MEDIUM",
                                description=f"{name} protokoli serverda faol. Bu protokol xavfsiz emas.",
                                evidence=f"{name} accepted cipher suites: {len(accepted)} ta",
                                proof_of_concept={"protocol": name, "accepted_ciphers_count": len(accepted)},
                                cwe_id="CWE-326",
                                cvss_score=cvss,
                                remediation=f"Server konfiguratsiyasida {name} ni butunlay o'chiring. Faqat TLS 1.2 va TLS 1.3 dan foydalaning.",
                                confidence="HIGH",
                            ))
        except Exception:
            pass
        finally:
            import os
            try:
                os.unlink(json_output)
            except Exception:
                pass
        return findings
