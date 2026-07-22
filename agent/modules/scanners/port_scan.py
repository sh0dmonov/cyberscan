"""
Nmap Port Scanner — Wrapper Module
=====================================
Nmap'ni subprocess orqali chaqirib, XML natijalarini parse qiladi.
"""
import asyncio
import logging
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import List

from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding
from agent.config import settings

logger = logging.getLogger(__name__)

# Yuqori xavfli portlar va ularning tarifi
HIGH_RISK_PORTS = {
    21:   ("FTP", "FTP ochiq — ma'lumot uzatish xavfsiz emas, brute-force xavfi"),
    23:   ("Telnet", "Telnet ochiq — ma'lumotlar shifrsiz uzatiladi"),
    25:   ("SMTP", "SMTP to'g'ridan-to'g'ri ochiq — spam relay xavfi"),
    445:  ("SMB", "SMB ochiq — EternalBlue (MS17-010) kabi zaifliklar xavfi"),
    1433: ("MSSQL", "MS SQL Server internet'ga ochiq"),
    1521: ("Oracle DB", "Oracle Database internet'ga ochiq"),
    2049: ("NFS", "NFS internet'ga ochiq — fayllarni masofadan o'qish xavfi"),
    3306: ("MySQL", "MySQL internet'ga ochiq — to'g'ridan-to'g'ri DB kirishiga xavf"),
    3389: ("RDP", "RDP ochiq — Brute-force va BlueKeep zaiflik xavfi"),
    4848: ("GlassFish", "GlassFish Admin panel ochiq"),
    5432: ("PostgreSQL", "PostgreSQL internet'ga ochiq"),
    5900: ("VNC", "VNC ochiq — masofaviy boshqaruv xavfi"),
    6379: ("Redis", "Redis ochiq — autentifikatsiyasiz kirish xavfi"),
    8080: ("HTTP Alt", "Alternativ HTTP port ochiq"),
    8443: ("HTTPS Alt", "Alternativ HTTPS port ochiq"),
    9200: ("Elasticsearch", "Elasticsearch ochiq — ma'lumotlar oshkor bo'lish xavfi"),
    27017: ("MongoDB", "MongoDB internet'ga ochiq — autentifikatsiyasiz kirish ehtimoli"),
}


class NmapScanner(BaseScanner):
    """
    Nmap wrapper scanner.
    Port scan natijalarini XML formatida olib, parse qiladi.
    """
    name = "Nmap-Port-Scanner"
    description = "Ochiq portlar va servis versiyalarini aniqlaydi (Nmap wrapper)"

    async def is_available(self) -> bool:
        return shutil.which(settings.nmap_path) is not None

    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings = []

        if not await self.is_available():
            logger.warning("Nmap topilmadi. Port scan o'tkazib yuborildi.")
            return findings

        logger.info(f"Nmap scan boshlandi: {target.host}")

        # Scan chuqurligiga qarab Nmap argumentlarini belgilash
        depth_args = {
            "quick":    ["-Pn", "-T4", "--top-ports", "100",  "-sV", "--version-intensity", "2"],
            "standard": ["-Pn", "-T4", "--top-ports", "1000", "-sV", "--version-intensity", "5"],
            "deep":     ["-Pn", "-T3", "-p-",          "-sV", "--version-intensity", "7", "-sC"],
        }
        nmap_args = depth_args.get(target.depth, depth_args["standard"])

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_output = tmp.name

        cmd = [
            settings.nmap_path,
            *nmap_args,
            "-oX", xml_output,
            "--open",
            target.host
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # timeout: quick=5min, standard=10min, deep=30min
            scan_timeout = {"quick": 300, "standard": 600, "deep": 1800}.get(target.depth, 600)
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=scan_timeout)

            if proc.returncode != 0:
                logger.error(f"Nmap xato: {stderr.decode()[:500]}")
                return findings

            # XML natijalarini parse qilish
            findings = self._parse_nmap_xml(xml_output, target.url)

        except asyncio.TimeoutError:
            logger.error("Nmap timeout — scan bekor qilindi")
        except Exception as e:
            logger.error(f"Nmap xato: {e}")
        finally:
            import os
            try:
                os.unlink(xml_output)
            except Exception:
                pass

        logger.info(f"Nmap scan yakunlandi. {len(findings)} ta finding topildi.")
        return findings

    def _parse_nmap_xml(self, xml_path: str, target_url: str) -> List[RawFinding]:
        """Nmap XML chiqishini parse qilib RawFinding ro'yxatiga aylantiradi."""
        findings = []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall("host"):
                address = host.find("address")
                ip = address.get("addr", "unknown") if address is not None else "unknown"

                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port in ports_elem.findall("port"):
                    state_elem = port.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    port_num = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")

                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    service_product = service_elem.get("product", "") if service_elem is not None else ""
                    service_version = service_elem.get("version", "") if service_elem is not None else ""
                    service_info = f"{service_product} {service_version}".strip()

                    # Yuqori xavfli portmi?
                    if port_num in HIGH_RISK_PORTS:
                        port_name, risk_desc = HIGH_RISK_PORTS[port_num]
                        severity = "HIGH"
                        cvss = 7.5
                        if port_num in (3306, 5432, 27017, 6379, 9200):
                            severity = "CRITICAL"
                            cvss = 9.1
                    else:
                        severity = "INFO"
                        cvss = 2.0
                        risk_desc = f"Port {port_num}/{protocol} ochiq"

                    findings.append(self._make_finding(
                        target_url=target_url,
                        vulnerability_name=f"Open Port: {port_num}/{protocol} ({service_name})",
                        severity=severity,
                        description=(
                            f"Port {port_num}/{protocol} ochiq. "
                            f"Servis: {service_info or service_name}. "
                            f"{risk_desc}"
                        ),
                        evidence=(
                            f"IP: {ip}\n"
                            f"Port: {port_num}/{protocol}\n"
                            f"Holat: OPEN\n"
                            f"Servis: {service_name}\n"
                            f"Versiya: {service_info or 'noma\'lum'}"
                        ),
                        proof_of_concept={
                            "ip": ip,
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "version": service_info,
                            "is_high_risk": port_num in HIGH_RISK_PORTS,
                        },
                        cwe_id="CWE-284",
                        cvss_score=cvss,
                        remediation=(
                            f"Port {port_num}'ni firewall orqali yoping yoki "
                            f"faqat kerakli IP manzillarga ruxsat bering."
                            if port_num in HIGH_RISK_PORTS
                            else f"Port {port_num} kerak emasligini tekshiring."
                        ),
                        confidence="HIGH",
                    ))

        except ET.ParseError as e:
            logger.error(f"Nmap XML parse xato: {e}")

        return findings
