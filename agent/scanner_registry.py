"""
Scanner Registry — Markazlashtirilgan Scanner Ro'yxati
=======================================================
SCANNERS_BY_DEPTH bir marta shu yerda aniqlanadi.
cli_runner.py va orchestrator.py shu moduldan import qiladi.
DRY (Don't Repeat Yourself) printsipi ta'minlanadi.

'deep' rejim 'standard' dan FARQLI:
  - To'liq port scan (-p-)
  - Qo'shimcha HTTP method tekshiruvi
  - Subdomain enumeration (agar mavjud bo'lsa)
"""
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
from agent.modules.scanners.http_methods import HttpMethodScanner
from agent.modules.scanners.open_redirect import OpenRedirectScanner

# ─── Scan chuqurligiga qarab modullar ───────────────────────────────────────
SCANNERS_BY_DEPTH: dict[str, list] = {
    # Quick: faqat eng muhim va tez tekshiruvlar
    "quick": [
        CspHeaderScanner,
        HstsHeaderScanner,
        XFrameHeaderScanner,
        XContentTypeHeaderScanner,
        EnvFileScanner,
        GitRepoScanner,
        SslCertificateScanner,
    ],

    # Standard: to'liq amaldagi xavfsizlik tekshiruvi
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

    # Deep: standartga qo'shimcha — HTTP method tekshiruvi,
    # open redirect, to'liq port scan (nmap -p-),
    # keng qamrovli ma'lumot yig'ish
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
        HttpMethodScanner,      # ← deep only: PUT/DELETE/TRACE tekshiruvi
        OpenRedirectScanner,    # ← deep only: Open Redirect tekshiruvi
        NmapScanner,            # deep rejimda -p- (barcha portlar) ishlatadi
    ],
}
