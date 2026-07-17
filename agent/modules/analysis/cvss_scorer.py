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

# Zaiflik turi → CVSS v3.1 bazaviy ball (standart)
DEFAULT_CVSS_SCORES = {
    "SQL Injection":              9.8,
    "Reflected Cross-Site Scripting": 7.2,
    "CORS Arbitrary Origin":      8.1,
    "Missing CSRF Token":         5.4,
    "HSTS":                       5.9,
    "Missing CSP":                6.1,
    "Information Disclosure":     5.3,
    "SSL Certificate Expired":    9.0,
    "Open Port":                  5.0,
    "Directory Traversal":        7.5,
    "Server Version Disclosure":  3.1,
}


class CvssScorer:
    """
    RawFinding ro'yxatiga CVSS ball beradi va severity ni belgilaydi.
    """

    def score_findings(self, findings: List[RawFinding]) -> List[RawFinding]:
        """Barcha finding'larga CVSS ball beradi."""
        scored = []
        for finding in findings:
            finding = self._apply_cvss(finding)
            scored.append(finding)
        return scored

    def _apply_cvss(self, finding: RawFinding) -> RawFinding:
        """Bitta finding'ga CVSS ball beradi."""
        # Agar scanner o'zi ball bergan bo'lsa, uni ishlatamiz
        if finding.cvss_score is not None:
            finding.severity = self._cvss_to_severity(finding.cvss_score)
            return finding

        # Zaiflik nomiga qarab default ball berish
        score = self._lookup_default_score(finding.vulnerability_name)
        finding.cvss_score = score
        finding.severity = self._cvss_to_severity(score)
        return finding

    def _lookup_default_score(self, vuln_name: str) -> float:
        """Zaiflik nomi asosida standart CVSS ballini topadi."""
        vuln_lower = vuln_name.lower()
        for keyword, score in DEFAULT_CVSS_SCORES.items():
            if keyword.lower() in vuln_lower:
                return score
        return 5.0  # Default: Medium

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
        verified = []
        for finding in findings:
            finding = self._verify(finding)
            verified.append(finding)
        return verified

    def _verify(self, finding: RawFinding) -> RawFinding:
        """Bitta finding'ni tekshiradi."""
        issues = []

        # Boolean-based SQLi: confidence pastroq
        if "boolean-based" in finding.vulnerability_name.lower():
            issues.append("Boolean-based SQLi — qo'shimcha tasdiq kerak")
            finding.confidence = "MEDIUM"

        # Ehtimoliy deb belgilangan topilmalar
        if "ehtimoliy" in finding.vulnerability_name.lower() or \
           "possible" in finding.vulnerability_name.lower():
            finding.confidence = "LOW"

        # PoC ma'lumotlari bor bo'lsa — yuqori ishonch
        if finding.proof_of_concept and len(finding.proof_of_concept) > 2:
            if finding.confidence != "LOW":
                finding.confidence = "HIGH"

        # Evidence mavjudligi
        if not finding.evidence:
            finding.confidence = "LOW"

        return finding
