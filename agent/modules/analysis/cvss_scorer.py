"""
CVSS v3.1 Scorer & Verifier
==============================
Har bir RawFinding'ga CVSS ball beradi va false positive kamaytiradi.
"""
import logging
from typing import List, Optional
from dataclasses import dataclass

from agent.modules.base_scanner import RawFinding

logger = logging.getLogger(__name__)

# CVSS v3.1 severity thresholds
CVSS_SEVERITY_MAP = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9):  "HIGH",
    (4.0, 6.9):  "MEDIUM",
    (0.1, 3.9):  "LOW",
    (0.0, 0.0):  "INFO",
}

# Zaiflik turi → (CVSS v3.1 bazaviy ball, CVSS v3.1 vector string)
DEFAULT_CVSS_DATA = {
    "SQL Injection": (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ),
    "Reflected Cross-Site Scripting": (
        7.2,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    ),
    "Stored Cross-Site Scripting": (
        8.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
    ),
    "CORS Arbitrary Origin": (
        8.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    ),
    "CORS Wildcard": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ),
    "Missing CSRF Token": (
        5.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    ),
    "HSTS": (
        5.9,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
    ),
    "Missing CSP": (
        6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    ),
    "Information Disclosure": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ),
    "SSL Certificate Expired": (
        9.0,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ),
    "Open Port": (
        5.0,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ),
    "Directory Traversal": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    ),
    "Server Version Disclosure": (
        3.1,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ),
    "Open Redirect": (
        6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    ),
    "Dangerous HTTP Method": (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    ),
    "Insecure Cookie": (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
    ),
}


class CvssScorer:
    """
    RawFinding ro'yxatiga CVSS v3.1 ball va vector beradi.
    """

    def score_findings(self, findings: List[RawFinding]) -> List[RawFinding]:
        """Barcha finding'larga CVSS ball beradi."""
        return [self._apply_cvss(f) for f in findings]

    def _apply_cvss(self, finding: RawFinding) -> RawFinding:
        """Bitta finding'ga CVSS ball va vector beradi."""
        # Agar scanner o'zi ball bergan bo'lsa, uni ishlatamiz
        if finding.cvss_score is not None:
            finding.severity = self._cvss_to_severity(finding.cvss_score)
            # Vector yo'q bo'lsa — zaiflik nomiga qarab olishga harakat qilamiz
            if not finding.cvss_vector:
                _, vector = self._lookup_default_data(finding.vulnerability_name)
                finding.cvss_vector = vector
            return finding

        # Zaiflik nomiga qarab default ball va vector berish
        score, vector = self._lookup_default_data(finding.vulnerability_name)
        finding.cvss_score = score
        finding.cvss_vector = vector
        finding.severity = self._cvss_to_severity(score)
        return finding

    def _lookup_default_data(self, vuln_name: str) -> tuple[float, str]:
        """Zaiflik nomi asosida standart CVSS ball va vektorini topadi."""
        vuln_lower = vuln_name.lower()
        for keyword, (score, vector) in DEFAULT_CVSS_DATA.items():
            if keyword.lower() in vuln_lower:
                return score, vector
        return 5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # Default: Medium

    def _cvss_to_severity(self, score: float) -> str:
        """CVSS ball asosida severity darajasini qaytaradi."""
        if score == 0.0:
            return "INFO"
        elif score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "INFO"


class Verifier:
    """
    False positive kamaytirish uchun ikkilamchi tekshiruv.
    Confidence score'ni baholaydi.
    """

    def verify_findings(self, findings: List[RawFinding]) -> List[RawFinding]:
        """
        Har bir finding'ning ishonchliligini baholaydi.
        False positive ehtimoli yuqori bo'lsa, confidence'ni pasaytiradi.
        """
        return [self._verify(f) for f in findings]

    def _verify(self, finding: RawFinding) -> RawFinding:
        """Bitta finding'ni tekshiradi."""
        # Boolean-based SQLi: confidence pastroq
        if "boolean-based" in finding.vulnerability_name.lower():
            finding.confidence = "MEDIUM"

        # Ehtimoliy deb belgilangan topilmalar
        if "ehtimoliy" in finding.vulnerability_name.lower() or \
           "possible" in finding.vulnerability_name.lower():
            finding.confidence = "LOW"

        # Evidence yo'q bo'lsa — past ishonch
        if not finding.evidence:
            finding.confidence = "LOW"
            return finding

        # PoC ma'lumotlari bor va evidence ham bo'lsa — yuqori ishonch
        if finding.proof_of_concept and len(finding.proof_of_concept) > 2:
            if finding.confidence != "LOW":
                finding.confidence = "HIGH"

        return finding
