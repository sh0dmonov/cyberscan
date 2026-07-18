"""
BaseScanner — Plugin Arxitekturasi
=====================================
Barcha scanner modullari shu abstrakt klassdan meros oladi.
Har bir scanner bir xil interfeys orqali ishlaydi (TZ 3.3 bo'yicha).
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import httpx

from agent.config import settings

logger = logging.getLogger(__name__)

# Haqiqiy parallel so'rovlar cheklovi uchun global Semaphore
_REQUEST_SEMAPHORE = asyncio.Semaphore(settings.max_concurrent_requests)


@dataclass
class ScanTarget:
    """Skanerlash nishoni haqida barcha ma'lumotlar."""
    url: str
    domain: str
    scheme: str       # http yoki https
    host: str
    port: Optional[int]
    depth: str = "standard"  # quick / standard / deep
    session_id: Optional[int] = None

    @classmethod
    def from_url(cls, url: str, depth: str = "standard", session_id: Optional[int] = None):
        parsed = urlparse(url)
        return cls(
            url=url,
            domain=parsed.netloc,
            scheme=parsed.scheme,
            host=parsed.hostname or parsed.netloc,
            port=parsed.port,
            depth=depth,
            session_id=session_id,
        )


@dataclass
class RawFinding:
    """
    Scanner modulidan qaytadigan xom natija.
    DB ga yozishdan oldin CVSS scorer tomonidan boyitiladi.
    """
    tool_name: str
    target_url: str
    vulnerability_name: str
    severity: str                          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    description: str
    evidence: str = ""
    proof_of_concept: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: str = ""
    confidence: str = "MEDIUM"            # HIGH / MEDIUM / LOW


class BaseScanner(ABC):
    """
    Barcha scanner modullari uchun abstrakt asosiy klass.

    Har bir scanner quyidagilarni implement qilishi shart:
      - name: str          — scanner nomi
      - description: str   — nima tekshiradi
      - scan(target)       — asosiy skanerlash metodi

    Ixtiyoriy:
      - is_available()     — tool o'rnatilganmi (wrapper'lar uchun)
    """

    name: str = "BaseScanner"
    description: str = "Abstract base scanner"

    def __init__(self):
        self.logger = logging.getLogger(f"scanner.{self.name}")
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Shared async HTTP client.
        
        Eslatma: verify=False ishlatilmoqda — bu barcha SSL sertifikatlarni
        tekshirisiz qabul qiladi. Bu skanerlash vositasi uchun maqbul, lekin
        ishlab chiqarish kodida ishlatmang.
        """
        if self._http_client is None or self._http_client.is_closed:
            if not settings.verify_ssl:
                logger.debug(
                    f"[{self.name}] SSL tekshiruvi o'chirilgan (verify=False). "
                    "Bu skanerlash rejimi uchun maqbul."
                )
            self._http_client = httpx.AsyncClient(
                timeout=settings.request_timeout,
                headers={"User-Agent": settings.USER_AGENT},
                follow_redirects=True,
                verify=settings.verify_ssl,
            )
        return self._http_client

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[httpx.Response]:
        """
        Xavfsiz HTTP so'rov yuboruvchi helper.
        Rate limiting (asyncio.Semaphore) va xatolarni avtomatik boshqaradi.
        """
        await asyncio.sleep(settings.request_delay)
        client = await self._get_client()

        # Haqiqiy parallel so'rovlar cheklovi
        async with _REQUEST_SEMAPHORE:
            try:
                response = await client.request(method, url, **kwargs)
                return response
            except httpx.TimeoutException:
                self.logger.warning(f"Timeout: {url}")
                return None
            except httpx.ConnectError:
                self.logger.warning(f"Connection error: {url}")
                return None
            except Exception as e:
                self.logger.error(f"Request error {url}: {e}")
                return None

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("POST", url, **kwargs)

    @abstractmethod
    async def scan(self, target: ScanTarget) -> List[RawFinding]:
        """
        Asosiy skanerlash metodi.
        :param target: ScanTarget — nishon ma'lumotlari
        :return: List[RawFinding] — topilgan zaifliklar ro'yxati
        """
        ...

    async def is_available(self) -> bool:
        """
        Tool o'rnatilganligini tekshiradi (wrapper'lar uchun).
        Custom scanner'lar uchun har doim True qaytaradi.
        """
        return True

    async def cleanup(self):
        """HTTP client'ni yopish."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    def _make_finding(
        self,
        target_url: str,
        vulnerability_name: str,
        severity: str,
        description: str,
        evidence: str = "",
        proof_of_concept: Optional[Dict] = None,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        remediation: str = "",
        confidence: str = "MEDIUM",
    ) -> RawFinding:
        """Finding yaratish uchun qulay helper metod."""
        return RawFinding(
            tool_name=self.name,
            target_url=target_url,
            vulnerability_name=vulnerability_name,
            severity=severity,
            description=description,
            evidence=evidence,
            proof_of_concept=proof_of_concept or {},
            cwe_id=cwe_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            remediation=remediation,
            confidence=confidence,
        )

    def __repr__(self):
        return f"<Scanner: {self.name}>"
