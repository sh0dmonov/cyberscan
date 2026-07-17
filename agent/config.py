"""
WebAuditAgent — Global Configuration
=====================================
Barcha sozlamalar shu yerda boshqariladi.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, ClassVar, Dict, List, Any


class Settings(BaseSettings):
    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./audit.db",
        env="DATABASE_URL"
    )

    # Anthropic
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")

    # Scanner rate limiting
    request_delay: float = Field(default=0.5, env="REQUEST_DELAY")
    max_concurrent_requests: int = Field(default=5, env="MAX_CONCURRENT_REQUESTS")
    request_timeout: int = Field(default=10, env="REQUEST_TIMEOUT")

    # Tool paths
    nmap_path: str = Field(default="nmap", env="NMAP_PATH")
    gobuster_path: str = Field(default="gobuster", env="GOBUSTER_PATH")
    ffuf_path: str = Field(default="ffuf", env="FFUF_PATH")
    whatweb_path: str = Field(default="whatweb", env="WHATWEB_PATH")
    amass_path: str = Field(default="amass", env="AMASS_PATH")
    sslyze_path: str = Field(default="sslyze", env="SSLYZE_PATH")
    wpscan_path: str = Field(default="wpscan", env="WPSCAN_PATH")
    nikto_path: str = Field(default="nikto", env="NIKTO_PATH")

    # App
    app_host: str = Field(default="0.0.0.0", env="APP_HOST")
    app_port: int = Field(default=8000, env="APP_PORT")
    app_debug: bool = Field(default=False, env="APP_DEBUG")
    secret_key: str = Field(default="change-this-secret", env="SECRET_KEY")

    # Scan depth multipliers
    SCAN_DEPTH_CONFIG: ClassVar[Dict[str, Any]] = {
        "quick":    {"timeout_multiplier": 0.5, "depth": 1},
        "standard": {"timeout_multiplier": 1.0, "depth": 2},
        "deep":     {"timeout_multiplier": 2.0, "depth": 3},
    }

    # Common sensitive file paths to check
    SENSITIVE_PATHS: ClassVar[List[str]] = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/db.sql", "/database.sql", "/dump.sql",
        "/phpinfo.php", "/info.php", "/test.php",
        "/admin/", "/administrator/", "/wp-admin/",
        "/phpmyadmin/", "/pma/", "/dbadmin/",
        "/config.php", "/config.bak", "/wp-config.php.bak",
        "/web.config", "/web.config.bak",
        "/.htaccess", "/.htpasswd",
        "/server-status", "/server-info",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/api/swagger.json", "/api/openapi.json",
        "/swagger-ui.html", "/swagger/index.html",
        "/actuator", "/actuator/env", "/actuator/health",
        "/debug/", "/console/", "/logs/",
        "/.DS_Store", "/Thumbs.db",
    ]

    # XSS payloads (basic reflected XSS detection)
    XSS_PAYLOADS: ClassVar[List[str]] = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "';alert(1)//",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '"><img src=x onerror=alert(1)>',
    ]

    # SQLi test payloads
    SQLI_PAYLOADS: ClassVar[List[str]] = [
        "'",
        '"',
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' AND SLEEP(0)--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' UNION SELECT NULL--",
        "admin'--",
        "1; SELECT 1",
    ]

    # SQLi error signatures
    SQLI_ERROR_SIGNATURES: ClassVar[List[str]] = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg_query(): query failed",
        "sqlstate",
        "ora-01756",
        "microsoft ole db provider for sql server",
        "sqlite_error",
        "[microsoft][odbc sql server driver]",
        "mysql_fetch_array() expects parameter 1 to be resource",
        "division by zero in",
        "pg::error",
        "syntax error in",
    ]

    # Security headers to check
    SECURITY_HEADERS: ClassVar[Dict[str, Any]] = {
        "Content-Security-Policy": {
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-693",
            "description": "Content Security Policy header yo'q — XSS hujumlaridan himoya yo'q",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "cvss": 5.9,
            "cwe": "CWE-319",
            "description": "HSTS header yo'q — MITM hujumiga zaif",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "cvss": 4.3,
            "cwe": "CWE-1021",
            "description": "X-Frame-Options yo'q — Clickjacking hujumiga zaif",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "cvss": 3.7,
            "cwe": "CWE-116",
            "description": "X-Content-Type-Options yo'q — MIME sniffing xavfi",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "cvss": 3.1,
            "cwe": "CWE-200",
            "description": "Referrer-Policy yo'q — ma'lumot sizib chiqishi mumkin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "cvss": 2.5,
            "cwe": "CWE-284",
            "description": "Permissions-Policy yo'q — brauzer funksiyalari cheklanmagan",
        },
    }

    # Common User-Agent for requests
    USER_AGENT: ClassVar[str] = (
        "WebAuditAgent/1.0 (Security Research; "
        "Authorized Testing Only; "
        "github.com/your-username/web-audit-agent)"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
