"""
Database Models — SQLAlchemy ORM
=================================
ScanSession va Finding modellari.
Unified Finding JSON Schema (TZ 3.3 bo'yicha).
"""
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, Integer, String, Float, DateTime,
    ForeignKey, Text, JSON, Enum, Boolean
)
from sqlalchemy.orm import relationship

from agent.models.database import Base


class SeverityLevel(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ScanDepth(str, PyEnum):
    QUICK    = "quick"
    STANDARD = "standard"
    DEEP     = "deep"


class ScanStatus(str, PyEnum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


class ScanSession(Base):
    """
    Har bir skanerlash sessiyasi uchun asosiy model.
    Foydalanuvchi ruxsati va audit ma'lumotlarini saqlaydi.
    """
    __tablename__ = "scan_sessions"

    id              = Column(Integer, primary_key=True, index=True)
    target_url      = Column(String(2048), nullable=False, index=True)
    target_domain   = Column(String(255), nullable=False)
    scan_depth      = Column(Enum(ScanDepth), default=ScanDepth.STANDARD)
    status          = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    # Foydalanuvchi ruxsati (huquqiy talablar, TZ 9-bo'lim)
    user_consent    = Column(Boolean, default=False, nullable=False)
    user_ip         = Column(String(45))
    user_agent      = Column(String(512))

    # Vaqt belgilari
    created_at      = Column(DateTime, default=datetime.utcnow)
    started_at      = Column(DateTime, nullable=True)
    completed_at    = Column(DateTime, nullable=True)

    # Statistika
    total_checks    = Column(Integer, default=0)
    total_findings  = Column(Integer, default=0)
    error_message   = Column(Text, nullable=True)

    # Hisobot
    report_html_path = Column(String(512), nullable=True)
    report_pdf_path  = Column(String(512), nullable=True)

    # Munosabatlar
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanSession id={self.id} target={self.target_url} status={self.status}>"

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "target_domain": self.target_domain,
            "scan_depth": self.scan_depth,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_checks": self.total_checks,
            "total_findings": self.total_findings,
        }


class Finding(Base):
    """
    Topilgan har bir zaiflik uchun model.
    Unified Finding JSON Schema (TZ 3.3 bo'yicha).

    JSON Schema namunasi:
    {
        "tool_name": "Custom-XSS-Scanner",
        "target": "https://example.com/login",
        "cwe_id": "CWE-79",
        "vulnerability_name": "Reflected Cross-Site Scripting",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "proof_of_concept": {
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected in HTTP response body without encoding."
        }
    }
    """
    __tablename__ = "findings"

    id                 = Column(Integer, primary_key=True, index=True)
    session_id         = Column(Integer, ForeignKey("scan_sessions.id"), nullable=False, index=True)

    # Zaiflik identifikatsiyasi
    tool_name          = Column(String(100), nullable=False)
    target_url         = Column(String(2048), nullable=False)
    vulnerability_name = Column(String(255), nullable=False)
    cwe_id             = Column(String(20), nullable=True)   # masalan: CWE-79
    cve_id             = Column(String(20), nullable=True)   # masalan: CVE-2023-1234

    # Baholash
    severity           = Column(Enum(SeverityLevel), nullable=False)
    cvss_score         = Column(Float, nullable=True)
    cvss_vector        = Column(String(200), nullable=True)  # CVSS v3.1 vector string

    # Tafsilotlar
    description        = Column(Text, nullable=True)
    evidence           = Column(Text, nullable=True)        # Raw evidence (request/response)
    proof_of_concept   = Column(JSON, nullable=True)        # Structured PoC data
    remediation        = Column(Text, nullable=True)        # Tuzatish tavsiyasi

    # LLM tomonidan yozilgan tushuntirish
    llm_description    = Column(Text, nullable=True)
    llm_remediation    = Column(Text, nullable=True)

    # Tekshiruv holati
    verified           = Column(Boolean, default=False)     # Ikkilamchi tekshiruv o'tganmi
    false_positive     = Column(Boolean, default=False)     # False positive sifatida belgilangan
    confidence         = Column(String(10), default="MEDIUM")  # HIGH / MEDIUM / LOW

    # Vaqt belgisi
    found_at           = Column(DateTime, default=datetime.utcnow)

    # Munosabatlar
    session = relationship("ScanSession", back_populates="findings")

    def __repr__(self):
        return f"<Finding {self.severity} {self.vulnerability_name} @ {self.target_url}>"

    def to_dict(self) -> Dict[str, Any]:
        """Unified Finding JSON Schema formatida qaytaradi."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "target_url": self.target_url,
            "vulnerability_name": self.vulnerability_name,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "description": self.description,
            "evidence": self.evidence,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "llm_description": self.llm_description,
            "llm_remediation": self.llm_remediation,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "confidence": self.confidence,
            "found_at": self.found_at.isoformat() if self.found_at else None,
        }

    def to_llm_safe_dict(self) -> Dict[str, Any]:
        """
        LLM'ga yuborish uchun xavfsiz format.
        Raw HTTP response yoki payload'larni o'z ichiga olmaydi
        (prompt injection himoyasi, TZ 3.6 bo'yicha).
        """
        return {
            "vulnerability_name": self.vulnerability_name,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "target_url": self.target_url,
            "tool_name": self.tool_name,
            "description": self.description,
            "confidence": self.confidence,
        }
