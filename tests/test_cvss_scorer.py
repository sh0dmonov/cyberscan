"""
CvssScorer va Verifier uchun unit testlar.
"""
import pytest
from agent.modules.base_scanner import RawFinding
from agent.modules.analysis.cvss_scorer import CvssScorer, Verifier


def make_finding(**kwargs) -> RawFinding:
    """Test uchun RawFinding yaratuvchi helper."""
    defaults = {
        "tool_name": "Test-Scanner",
        "target_url": "https://example.com",
        "vulnerability_name": "Test Vulnerability",
        "severity": "INFO",
        "description": "Test description",
        "evidence": "Test evidence",
    }
    defaults.update(kwargs)
    return RawFinding(**defaults)


class TestCvssScorer:
    """CvssScorer klassini testlash."""

    def setup_method(self):
        self.scorer = CvssScorer()

    def test_sql_injection_score(self):
        """SQL Injection uchun 9.8 ball va CRITICAL severity."""
        finding = make_finding(vulnerability_name="SQL Injection (Error-Based)")
        scored = self.scorer._apply_cvss(finding)
        assert scored.cvss_score == 9.8
        assert scored.severity == "CRITICAL"

    def test_xss_score(self):
        """Reflected XSS uchun 7.2 ball va HIGH severity."""
        finding = make_finding(vulnerability_name="Reflected Cross-Site Scripting (XSS)")
        scored = self.scorer._apply_cvss(finding)
        assert scored.cvss_score == 7.2
        assert scored.severity == "HIGH"

    def test_existing_score_preserved(self):
        """Scanner bergan ball o'zgarmasligi kerak."""
        finding = make_finding(cvss_score=3.5)
        scored = self.scorer._apply_cvss(finding)
        assert scored.cvss_score == 3.5
        assert scored.severity == "LOW"

    def test_cvss_vector_populated(self):
        """cvss_vector maydoni to'ldirilishi kerak."""
        finding = make_finding(vulnerability_name="SQL Injection (Error-Based)")
        scored = self.scorer._apply_cvss(finding)
        assert scored.cvss_vector is not None
        assert scored.cvss_vector.startswith("CVSS:3.1/")

    def test_default_medium_score(self):
        """Noma'lum zaiflik uchun 5.0 (MEDIUM) berilib, vector ham qo'shilishi kerak."""
        finding = make_finding(vulnerability_name="Unknown Weird Vulnerability")
        scored = self.scorer._apply_cvss(finding)
        assert scored.cvss_score == 5.0
        assert scored.severity == "MEDIUM"
        assert scored.cvss_vector is not None

    def test_severity_thresholds(self):
        """CVSS → Severity konversiyasi to'g'ri ishlashi kerak."""
        scorer = self.scorer
        assert scorer._cvss_to_severity(9.5) == "CRITICAL"
        assert scorer._cvss_to_severity(7.5) == "HIGH"
        assert scorer._cvss_to_severity(5.0) == "MEDIUM"
        assert scorer._cvss_to_severity(2.0) == "LOW"
        assert scorer._cvss_to_severity(0.0) == "INFO"

    def test_score_multiple_findings(self):
        """Bir nechta finding'ga bir vaqtda ball berish."""
        findings = [
            make_finding(vulnerability_name="SQL Injection (Error-Based)"),
            make_finding(vulnerability_name="Reflected Cross-Site Scripting (XSS)"),
            make_finding(vulnerability_name="Unknown Vuln"),
        ]
        scored = self.scorer.score_findings(findings)
        assert len(scored) == 3
        assert scored[0].cvss_score == 9.8
        assert scored[1].cvss_score == 7.2
        assert scored[2].cvss_score == 5.0


class TestVerifier:
    """Verifier klassini testlash."""

    def setup_method(self):
        self.verifier = Verifier()

    def test_boolean_sqli_confidence_medium(self):
        """Boolean-based SQLi (Ehtimoliy yo'q) → MEDIUM confidence."""
        finding = make_finding(
            vulnerability_name="SQL Injection (Boolean-Based Blind)",
            confidence="HIGH",
        )
        verified = self.verifier._verify(finding)
        assert verified.confidence == "MEDIUM"

    def test_ehtimoliy_boolean_sqli_low_confidence(self):
        """Boolean-based SQLi + Ehtimoliy → LOW confidence (ikkalasi ta'sir qiladi)."""
        finding = make_finding(
            vulnerability_name="SQL Injection (Boolean-Based -- Ehtimoliy)",
            confidence="HIGH",
        )
        verified = self.verifier._verify(finding)
        assert verified.confidence == "LOW"


    def test_no_evidence_low_confidence(self):
        """Evidence yo'q bo'lsa → LOW confidence."""
        finding = make_finding(evidence="", confidence="HIGH")
        verified = self.verifier._verify(finding)
        assert verified.confidence == "LOW"

    def test_rich_poc_high_confidence(self):
        """Katta PoC va evidence → HIGH confidence."""
        finding = make_finding(
            evidence="Real evidence here",
            proof_of_concept={
                "url": "https://example.com",
                "payload": "<script>",
                "response": "200 OK",
                "parameter": "q",
            },
            confidence="MEDIUM",
        )
        verified = self.verifier._verify(finding)
        assert verified.confidence == "HIGH"

    def test_ehtimoliy_low_confidence(self):
        """'Ehtimoliy' so'zi bor topilma → LOW confidence."""
        finding = make_finding(
            vulnerability_name="Open Port Ehtimoliy",
            confidence="HIGH",
        )
        verified = self.verifier._verify(finding)
        assert verified.confidence == "LOW"
