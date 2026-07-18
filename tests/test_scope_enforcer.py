"""
ScopeEnforcer uchun unit testlar.
"""
import pytest
from agent.utils.scope_enforcer import ScopeEnforcer


class TestScopeEnforcer:
    """ScopeEnforcer klassini testlash."""

    def test_exact_match(self):
        """To'liq mos URL → scope ichida."""
        enforcer = ScopeEnforcer("https://example.com")
        assert enforcer.is_in_scope("https://example.com/page") is True

    def test_subdomain_in_scope(self):
        """Subdomen → scope ichida."""
        enforcer = ScopeEnforcer("https://example.com")
        assert enforcer.is_in_scope("https://api.example.com/endpoint") is True

    def test_different_domain_out_of_scope(self):
        """Boshqa domen → scope tashqarida."""
        enforcer = ScopeEnforcer("https://example.com")
        assert enforcer.is_in_scope("https://evil-attacker.com") is False

    def test_similar_domain_out_of_scope(self):
        """O'xshash domen lekin boshqa (example.com.evil.com) → scope tashqarida."""
        enforcer = ScopeEnforcer("https://example.com")
        assert enforcer.is_in_scope("https://example.com.evil.com") is False

    def test_ip_exact_match(self):
        """IP manzil — exact match → scope ichida."""
        enforcer = ScopeEnforcer("http://192.168.1.1")
        assert enforcer.is_in_scope("http://192.168.1.1/admin") is True

    def test_ip_different_address(self):
        """IP manzil — boshqa IP → scope tashqarida."""
        enforcer = ScopeEnforcer("http://192.168.1.1")
        assert enforcer.is_in_scope("http://10.0.0.1/admin") is False

    def test_root_domain_in_scope(self):
        """Ildiz domen (www olmagan) → scope ichida."""
        enforcer = ScopeEnforcer("https://www.example.com")
        assert enforcer.is_in_scope("https://example.com/page") is True

    def test_empty_url(self):
        """Bo'sh URL → scope tashqarida."""
        enforcer = ScopeEnforcer("https://example.com")
        assert enforcer.is_in_scope("") is False

    def test_filter_urls(self):
        """filter_urls — aralash ro'yxatdan faqat scope'dagilarni qaytarishi kerak."""
        enforcer = ScopeEnforcer("https://example.com")
        urls = [
            "https://example.com/page1",
            "https://api.example.com/v1",
            "https://evil.com/attack",
            "https://example.com/login",
        ]
        result = enforcer.filter_urls(urls)
        assert len(result) == 3
        assert "https://evil.com/attack" not in result

    def test_blocked_count(self):
        """Blok qilingan URL'lar soni to'g'ri hisoblanishi kerak."""
        enforcer = ScopeEnforcer("https://example.com")
        enforcer.is_in_scope("https://evil.com")
        enforcer.is_in_scope("https://another.com")
        assert enforcer.blocked_count == 2
