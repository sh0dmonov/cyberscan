"""
Scope Enforcer — Out-of-Scope Blocker
=====================================
Agent faqat berilgan domen va uning subdomenlari doirasida so'rov yuboradi.
Tashqi domenlarga so'rov yuborishni oldini oladi (TZ 6-bo'lim).
"""
import ipaddress
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """
    Berilgan target domen asosida scope (doira) ni belgilaydi
    va har bir URL shu doiraga kirish-kirmasligini tekshiradi.
    """

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_domain = parsed.hostname or ""

        # Asosiy domenni ajratib olish (masalan, sub.example.com → example.com)
        parts = self.target_domain.split(".")
        if len(parts) >= 2:
            self.root_domain = ".".join(parts[-2:])
        else:
            self.root_domain = self.target_domain

        # IP manzilmi yoki domenmi?
        self._is_ip = self._check_is_ip(self.target_domain)

        self._blocked_count = 0
        logger.info(f"Scope belgilandi: {self.target_domain} (root: {self.root_domain}, ip: {self._is_ip})")

    def _check_is_ip(self, host: str) -> bool:
        """Host IP manzil ekanligini aniqlaydi (IPv4 va IPv6 uchun)."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def is_in_scope(self, url: str) -> bool:
        """
        URL scope doirasida ekanligini tekshiradi.
        True  → ruxsat berilgan
        False → scope'dan tashqari, so'rov yuborilmaydi
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""

            if not host:
                return False

            # IP manzil bilan skanerlayotgan bo'lsak — faqat exact match
            if self._is_ip:
                if host == self.target_domain:
                    return True
                self._blocked_count += 1
                logger.debug(f"Scope'dan tashqari IP (blok #{self._blocked_count}): {url}")
                return False

            # Domen bilan skanerlayotgan bo'lsak:
            # 1. To'liq mos (exact match)
            if host == self.target_domain:
                return True

            # 2. Subdomen tekshiruvi (sub.example.com → example.com scope)
            if host.endswith(f".{self.root_domain}"):
                return True

            # 3. Ildiz domen mos bo'lsa (www.example.com → example.com)
            if host == self.root_domain:
                return True

            self._blocked_count += 1
            logger.debug(f"Scope'dan tashqari (blok #{self._blocked_count}): {url}")
            return False

        except Exception as e:
            logger.error(f"Scope tekshiruvida xato: {e}")
            return False

    def filter_urls(self, urls: list) -> list:
        """URL ro'yxatidan faqat scope'dagi URL'larni qaytaradi."""
        in_scope = [u for u in urls if self.is_in_scope(u)]
        blocked = len(urls) - len(in_scope)
        if blocked > 0:
            logger.info(f"{blocked} ta URL scope'dan tashqari bo'lgani uchun o'tkazib yuborildi")
        return in_scope

    @property
    def blocked_count(self) -> int:
        return self._blocked_count
