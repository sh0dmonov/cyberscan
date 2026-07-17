"""
Orchestrator — Agentning "Miyasi"
====================================
Barcha skanerlash bosqichlarini ketma-ket boshqaradi.
Rate limiting, scope enforcer, audit logging integratsiyalari.
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import List, Optional, Callable
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from agent.config import settings
from agent.models.finding import (
    ScanSession, Finding, ScanStatus, ScanDepth, SeverityLevel
)
from agent.modules.base_scanner import ScanTarget, RawFinding
from agent.modules.analysis.cvss_scorer import CvssScorer, Verifier
from agent.utils.scope_enforcer import ScopeEnforcer
from agent.utils.audit_logger import AuditLogger

# --- Scanner modullari ---
from agent.modules.scanners.http_headers import (
    CspHeaderScanner, HstsHeaderScanner, XFrameHeaderScanner,
    XContentTypeHeaderScanner, ReferrerPolicyHeaderScanner,
    PermissionsPolicyHeaderScanner, ServerHeaderScanner, XPoweredByScanner
)
from agent.modules.scanners.xss_scanner import XssScanner
from agent.modules.scanners.sqli_scanner import SqliErrorScanner, SqliBooleanScanner
from agent.modules.scanners.csrf_checker import CsrfFormScanner, CookieSecurityScanner
from agent.modules.scanners.cors_scanner import CorsScanner
from agent.modules.scanners.info_disclosure import (
    EnvFileScanner, GitRepoScanner, BackupFileScanner,
    PhpInfoScanner, PhpMyAdminScanner, SwaggerApiScanner, SpringBootActuatorScanner
)
from agent.modules.scanners.port_scan import NmapScanner
from agent.modules.scanners.ssl_tls import SslCertificateScanner, SslProtocolScanner
from agent.modules.recon.tech_fingerprint import (
    TechFingerprintScanner, RobotsScanner, SitemapScanner,
    DnsSpfScanner, DnsDmarcScanner, DnsMxScanner, DnsZoneTransferScanner
)

logger = logging.getLogger(__name__)

# Scan chuqurligiga qarab modullar
SCANNERS_BY_DEPTH = {
    "quick": [
        CspHeaderScanner,
        HstsHeaderScanner,
        XFrameHeaderScanner,
        XContentTypeHeaderScanner,
        EnvFileScanner,
        GitRepoScanner,
        SslCertificateScanner,
    ],
    "standard": [
        TechFingerprintScanner,
        RobotsScanner,
        SitemapScanner,
        DnsSpfScanner,
        DnsDmarcScanner,
        DnsMxScanner,
        DnsZoneTransferScanner,
        CspHeaderScanner,
        HstsHeaderScanner,
        XFrameHeaderScanner,
        XContentTypeHeaderScanner,
        ReferrerPolicyHeaderScanner,
        PermissionsPolicyHeaderScanner,
        ServerHeaderScanner,
        XPoweredByScanner,
        SslCertificateScanner,
        SslProtocolScanner,
        EnvFileScanner,
        GitRepoScanner,
        BackupFileScanner,
        PhpInfoScanner,
        PhpMyAdminScanner,
        SwaggerApiScanner,
        SpringBootActuatorScanner,
        CorsScanner,
        XssScanner,
        SqliErrorScanner,
        SqliBooleanScanner,
        CsrfFormScanner,
        CookieSecurityScanner,
        NmapScanner,
    ],
    "deep": [
        TechFingerprintScanner,
        RobotsScanner,
        SitemapScanner,
        DnsSpfScanner,
        DnsDmarcScanner,
        DnsMxScanner,
        DnsZoneTransferScanner,
        CspHeaderScanner,
        HstsHeaderScanner,
        XFrameHeaderScanner,
        XContentTypeHeaderScanner,
        ReferrerPolicyHeaderScanner,
        PermissionsPolicyHeaderScanner,
        ServerHeaderScanner,
        XPoweredByScanner,
        SslCertificateScanner,
        SslProtocolScanner,
        EnvFileScanner,
        GitRepoScanner,
        BackupFileScanner,
        PhpInfoScanner,
        PhpMyAdminScanner,
        SwaggerApiScanner,
        SpringBootActuatorScanner,
        CorsScanner,
        XssScanner,
        SqliErrorScanner,
        SqliBooleanScanner,
        CsrfFormScanner,
        CookieSecurityScanner,
        NmapScanner,
    ],
}


class Orchestrator:
    """
    WebAuditAgent asosiy orchestrator.
    Barcha skanerlash bosqichlarini boshqaradi.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.cvss_scorer = CvssScorer()
        self.verifier = Verifier()

    async def run_scan(
        self,
        session_id: int,
        target_url: str,
        scan_depth: str = "standard",
        progress_callback: Optional[Callable] = None,
    ) -> ScanSession:
        """
        To'liq skanerlash jarayonini boshlaydi va boshqaradi.

        :param session_id: DB'dagi ScanSession ID
        :param target_url: Skanerlash manzili
        :param scan_depth: quick / standard / deep
        :param progress_callback: async callback(message, percent)
        :return: Tugallangan ScanSession
        """
        # Session'ni bazadan olish
        session = await self.db.get(ScanSession, session_id)
        if not session:
            raise ValueError(f"Session {session_id} topilmadi")

        # Audit logger yaratish
        audit_log = AuditLogger(session_id, target_url)

        # Session'ni "running" holatga o'tkazish
        session.status = ScanStatus.RUNNING
        session.started_at = datetime.utcnow()
        await self.db.commit()

        # Scope enforcer
        scope = ScopeEnforcer(target_url)

        # ScanTarget yaratish
        parsed = urlparse(target_url)
        target = ScanTarget.from_url(target_url, depth=scan_depth, session_id=session_id)

        all_findings: List[RawFinding] = []
        total_checks = 0

        try:
            # Scan uchun modullar ro'yxatini tanlash
            scanner_classes = SCANNERS_BY_DEPTH.get(scan_depth, SCANNERS_BY_DEPTH["standard"])

            for i, scanner_class in enumerate(scanner_classes):
                scanner = scanner_class()

                # Tool o'rnatilganligini tekshirish
                if not await scanner.is_available():
                    logger.warning(f"{scanner.name} mavjud emas, o'tkazib yuborildi")
                    continue

                percent = int((i / len(scanner_classes)) * 90)
                if progress_callback:
                    await progress_callback(f"🔍 {scanner.name} ishlamoqda...", percent)

                logger.info(f"▶ {scanner.name} boshlandi")
                audit_log.log_scan_start(scanner.name, target_url)
                start_time = time.time()

                try:
                    findings = await scanner.scan(target)
                    duration_ms = (time.time() - start_time) * 1000

                    # CVSS scoring
                    findings = self.cvss_scorer.score_findings(findings)

                    # Verification
                    findings = self.verifier.verify_findings(findings)

                    # Scope tekshiruvi
                    for f in findings:
                        if not scope.is_in_scope(f.target_url):
                            logger.warning(f"Scope'dan tashqari finding o'chirildi: {f.target_url}")
                            continue
                        all_findings.append(f)
                        audit_log.log_finding({
                            "vulnerability_name": f.vulnerability_name,
                            "severity": f.severity,
                            "target_url": f.target_url,
                        })

                    total_checks += 1
                    audit_log.log_scan_complete(scanner.name, len(findings), duration_ms)
                    logger.info(f"✓ {scanner.name}: {len(findings)} ta finding ({duration_ms:.0f}ms)")

                except Exception as e:
                    logger.error(f"✗ {scanner.name} xato: {e}", exc_info=True)
                    audit_log.log_error(scanner.name, str(e))
                finally:
                    await scanner.cleanup()

            # Barcha finding'larni DB'ga saqlash
            if progress_callback:
                await progress_callback("💾 Natijalar saqlanmoqda...", 92)

            await self._save_findings(session_id, all_findings)

            # Session'ni yakunlash
            session.status = ScanStatus.COMPLETED
            session.completed_at = datetime.utcnow()
            session.total_checks = total_checks
            session.total_findings = len([f for f in all_findings if not f.confidence == "LOW"])
            await self.db.commit()

            audit_log.log_session_end(len(all_findings))

            if progress_callback:
                await progress_callback("✅ Scan yakunlandi!", 100)

            logger.info(
                f"Scan yakunlandi: {target_url} | "
                f"{len(all_findings)} ta finding | "
                f"{session.duration_seconds:.0f}s"
            )

        except Exception as e:
            logger.error(f"Orchestrator xato: {e}", exc_info=True)
            session.status = ScanStatus.FAILED
            session.error_message = str(e)
            session.completed_at = datetime.utcnow()
            await self.db.commit()
            audit_log.log_error("Orchestrator", str(e))
            raise

        return session

    async def _save_findings(self, session_id: int, raw_findings: List[RawFinding]):
        """RawFinding ro'yxatini Finding DB modeliga o'tkazib saqlaydi."""
        for rf in raw_findings:
            finding = Finding(
                session_id=session_id,
                tool_name=rf.tool_name,
                target_url=rf.target_url,
                vulnerability_name=rf.vulnerability_name,
                cwe_id=rf.cwe_id,
                cve_id=rf.cve_id,
                severity=SeverityLevel(rf.severity),
                cvss_score=rf.cvss_score,
                cvss_vector=rf.cvss_vector,
                description=rf.description,
                evidence=rf.evidence,
                proof_of_concept=rf.proof_of_concept,
                remediation=rf.remediation,
                confidence=rf.confidence,
                verified=rf.confidence == "HIGH",
            )
            self.db.add(finding)

        await self.db.commit()
        logger.info(f"{len(raw_findings)} ta finding DB'ga saqlandi")
