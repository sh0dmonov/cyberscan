"""
CLI Orchestrator — DB'siz scan runner
=======================================
Findings'ni to'g'ridan-to'g'ri list sifatida qaytaradi.
"""
import asyncio
import logging
import time
from typing import List, Dict, Callable, Optional
from urllib.parse import urlparse

from agent.modules.base_scanner import ScanTarget, RawFinding
from agent.modules.analysis.cvss_scorer import CvssScorer, Verifier
from agent.utils.scope_enforcer import ScopeEnforcer
from agent.utils.audit_logger import AuditLogger

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


async def run_scan_cli(
    target_url: str,
    scan_depth: str = "standard",
    progress_cb: Optional[Callable] = None,
) -> tuple[List[Dict], float, List[str]]:
    """
    CLI uchun scan runner — DB'siz, findings list qaytaradi.
    Returns: (findings_dicts, duration_seconds, modules_used)
    """
    start = time.time()
    scope = ScopeEnforcer(target_url)
    cvss = CvssScorer()
    verifier = Verifier()
    audit = AuditLogger(0, target_url)

    target = ScanTarget.from_url(target_url, depth=scan_depth)
    scanner_classes = SCANNERS_BY_DEPTH.get(scan_depth, SCANNERS_BY_DEPTH["standard"])

    all_findings: List[RawFinding] = []
    modules_used: List[str] = []
    total = len(scanner_classes)

    for i, cls in enumerate(scanner_classes):
        scanner = cls()
        pct = int((i / total) * 95)

        if not await scanner.is_available():
            logger.warning(f"{scanner.name} mavjud emas, o'tkazib yuborildi")
            if progress_cb:
                await progress_cb(f"⏭  {scanner.name} — mavjud emas, o'tkazib yuborildi", pct)
            continue

        if progress_cb:
            await progress_cb(f"🔍 [{i+1}/{total}] {scanner.name}...", pct)

        t0 = time.time()
        try:
            raw = await scanner.scan(target)
            raw = cvss.score_findings(raw)
            raw = verifier.verify_findings(raw)

            for f in raw:
                if scope.is_in_scope(f.target_url):
                    all_findings.append(f)

            modules_used.append(scanner.name)
            elapsed = (time.time() - t0) * 1000
            logger.info(f"✓ {scanner.name}: {len(raw)} finding ({elapsed:.0f}ms)")

        except Exception as e:
            logger.error(f"✗ {scanner.name} xato: {e}")
            audit.log_error(scanner.name, str(e))
        finally:
            await scanner.cleanup()

    duration = time.time() - start

    # RawFinding → Dict
    findings_dicts = [
        {
            "tool_name": f.tool_name,
            "target_url": f.target_url,
            "vulnerability_name": f.vulnerability_name,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "evidence": f.evidence,
            "proof_of_concept": f.proof_of_concept,
            "remediation": f.remediation,
            "cwe_id": f.cwe_id,
            "cve_id": f.cve_id,
            "confidence": f.confidence,
        }
        for f in all_findings
    ]

    audit.log_session_end(len(findings_dicts))
    return findings_dicts, duration, modules_used
