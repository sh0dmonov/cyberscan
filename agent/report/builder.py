"""
ReportBuilder — Shablon-asosli hisobot generatori
====================================================
AI ishlatilmaydi. Knowledge base + Jinja2 + deterministik mantiq.
"""
import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import jinja2
from markupsafe import Markup

logger = logging.getLogger(__name__)

KB_PATH = Path(__file__).parent / "knowledge_base.json"
TMPL_PATH = Path(__file__).parent / "templates"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#28a745",
    "INFO":     "#17a2b8",
}


@dataclass
class FindingData:
    """Hisobot uchun finding ma'lumotlari."""
    tool_name: str
    target_url: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    description: str
    evidence: str
    proof_of_concept: Dict
    remediation: str
    cwe_id: Optional[str]
    cve_id: Optional[str]
    confidence: str
    # Knowledge base'dan boyitiladi
    kb_title: str = ""
    kb_impact: str = ""
    kb_remediation: str = ""
    kb_owasp: str = ""
    kb_references: List[str] = field(default_factory=list)


class ReportBuilder:
    """
    Findings ro'yxatidan HTML va PDF hisobot yaratadi.
    Hech qanday LLM/AI ishlatilmaydi — to'liq deterministik.
    """

    def __init__(self):
        self.kb = self._load_kb()
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TMPL_PATH)),
            autoescape=jinja2.select_autoescape(["html"]),
        )
        self._env.filters["tojson"] = lambda v, **kw: Markup(
            json.dumps(v, ensure_ascii=False, default=str, **kw)
        )

    # ── Knowledge Base ─────────────────────────────────────────────────────

    def _load_kb(self) -> Dict:
        try:
            with open(KB_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Knowledge base yuklanmadi: {e}")
            return {}

    def _match_kb(self, vuln_name: str) -> Optional[Dict]:
        """Zaiflik nomiga mos KB yozuvini topadi."""
        vuln_lower = vuln_name.lower()
        for key, val in self.kb.items():
            if key.lower() in vuln_lower or any(
                word in vuln_lower for word in key.lower().split("-")
            ):
                return val
        # Qisman moslik
        for key, val in self.kb.items():
            kb_title_words = val["title"].lower().split()
            if any(w in vuln_lower for w in kb_title_words if len(w) > 4):
                return val
        return None

    # ── Finding'larni boyitish ─────────────────────────────────────────────

    def enrich_findings(self, raw_findings: List[Dict]) -> List[FindingData]:
        """
        RawFinding ro'yxatini KB bilan boyitadi va saralaydi.
        """
        enriched = []
        for rf in raw_findings:
            sev = rf.get("severity", "INFO").upper()
            kb = self._match_kb(rf.get("vulnerability_name", ""))

            fd = FindingData(
                tool_name=rf.get("tool_name", "Unknown"),
                target_url=rf.get("target_url", ""),
                vulnerability_name=rf.get("vulnerability_name", ""),
                severity=sev,
                cvss_score=rf.get("cvss_score") or 0.0,
                description=rf.get("description", ""),
                evidence=rf.get("evidence", ""),
                proof_of_concept=rf.get("proof_of_concept") or {},
                remediation=rf.get("remediation", ""),
                cwe_id=rf.get("cwe_id"),
                cve_id=rf.get("cve_id"),
                confidence=rf.get("confidence", "MEDIUM"),
                kb_title=kb["title"] if kb else rf.get("vulnerability_name", ""),
                kb_impact=kb.get("impact", "") if kb else "",
                kb_remediation=kb.get("remediation", "") if kb else rf.get("remediation", ""),
                kb_owasp=kb.get("owasp", "") if kb else "",
                kb_references=kb.get("references", []) if kb else [],
            )
            enriched.append(fd)

        # Severity bo'yicha saralash
        enriched.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), -f.cvss_score))
        return enriched

    # ── Executive Summary ──────────────────────────────────────────────────

    def generate_summary(self, findings: List[FindingData], target_url: str) -> Dict:
        """
        Deterministik mantiq asosida executive summary yaratadi — AI yo'q.
        """
        counts = Counter(f.severity for f in findings)
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        medium = counts.get("MEDIUM", 0)
        low = counts.get("LOW", 0)
        info = counts.get("INFO", 0)

        # Umumiy xavf darajasi
        if critical > 0:
            risk_level = "JUDA YUQORI"
            risk_color = "#dc3545"
            risk_summary = (
                f"{critical} ta KRITIK zaiflik aniqlandi. "
                "Darhol choralar ko'rish talab etiladi."
            )
        elif high > 3:
            risk_level = "YUQORI"
            risk_color = "#fd7e14"
            risk_summary = (
                f"{high} ta yuqori darajali zaiflik aniqlandi. "
                "Imkon qadar tezroq tuzatish tavsiya etiladi."
            )
        elif high > 0 or medium > 5:
            risk_level = "O'RTACHA"
            risk_color = "#ffc107"
            risk_summary = (
                f"{high} ta yuqori, {medium} ta o'rtacha zaiflik topildi. "
                "Rejalashtirilgan tuzatish ishlari olib borilishi kerak."
            )
        elif medium > 0 or low > 0:
            risk_level = "PAST"
            risk_color = "#28a745"
            risk_summary = (
                f"{medium} ta o'rtacha, {low} ta past darajali topilma. "
                "Muntazam xavfsizlik yangilashlari tavsiya etiladi."
            )
        else:
            risk_level = "MINIMAL"
            risk_color = "#17a2b8"
            risk_summary = "Jiddiy zaifliklar aniqlanmadi. Muntazam monitoring tavsiya etiladi."

        # Eng ko'p uchraydigan kategoriyalar
        cats = Counter()
        for f in findings:
            kb = self._match_kb(f.vulnerability_name)
            if kb:
                cats[kb.get("owasp", "Boshqa")] += 1
        top_categories = cats.most_common(3)

        # Tuzatish prioriteti
        priority_items = [f for f in findings if f.severity in ("CRITICAL", "HIGH")][:5]

        return {
            "target_url": target_url,
            "scan_date": datetime.now().strftime("%d.%m.%Y %H:%M"),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "risk_summary": risk_summary,
            "total": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "top_categories": top_categories,
            "priority_items": priority_items,
        }

    # ── HTML Hisobot ───────────────────────────────────────────────────────

    def build_html(
        self,
        findings: List[Dict],
        target_url: str,
        scan_duration: float = 0,
        modules_used: List[str] = None,
    ) -> str:
        """HTML hisobotini yaratadi va string qaytaradi."""
        enriched = self.enrich_findings(findings)
        summary = self.generate_summary(enriched, target_url)

        # Severity ranglarini template uchun tayyorlash
        severity_colors = SEVERITY_COLORS

        tmpl = self._env.get_template("report.html")
        return tmpl.render(
            summary=summary,
            findings=enriched,
            severity_colors=severity_colors,
            scan_duration=scan_duration,
            modules_used=modules_used or [],
            generated_at=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        )

    def save_html(self, html: str, output_path: Path) -> Path:
        """HTML faylni saqlaydi."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        logger.info(f"HTML hisobot saqlandi: {output_path}")
        return output_path

    def save_pdf(self, html: str, output_path: Path) -> Optional[Path]:
        """WeasyPrint orqali PDF yaratadi."""
        try:
            from weasyprint import HTML as WeasyprintHTML
            output_path.parent.mkdir(parents=True, exist_ok=True)
            WeasyprintHTML(string=html).write_pdf(str(output_path))
            logger.info(f"PDF hisobot saqlandi: {output_path}")
            return output_path
        except ImportError:
            logger.warning("WeasyPrint o'rnatilmagan. PDF yaratilmadi.")
            return None
        except Exception as e:
            logger.error(f"PDF yaratishda xato: {e}")
            return None
