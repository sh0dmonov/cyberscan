"""
Scanner Registry uchun unit testlar.
"""
import pytest
from agent.scanner_registry import SCANNERS_BY_DEPTH
from agent.modules.base_scanner import BaseScanner


class TestScannerRegistry:
    """SCANNERS_BY_DEPTH ro'yxatini tekshirish."""

    def test_all_depths_present(self):
        """Barcha 3 ta depth mavjud bo'lishi kerak."""
        assert "quick" in SCANNERS_BY_DEPTH
        assert "standard" in SCANNERS_BY_DEPTH
        assert "deep" in SCANNERS_BY_DEPTH

    def test_quick_is_subset_of_standard(self):
        """Quick — standard'ning kichik to'plami bo'lishi kerak."""
        quick_names = {cls.__name__ for cls in SCANNERS_BY_DEPTH["quick"]}
        standard_names = {cls.__name__ for cls in SCANNERS_BY_DEPTH["standard"]}
        assert quick_names.issubset(standard_names), (
            f"Quick da bor lekin Standard da yo'q: {quick_names - standard_names}"
        )

    def test_deep_has_more_than_standard(self):
        """Deep — standard'dan ko'proq modul o'z ichiga olishi kerak."""
        deep_count = len(SCANNERS_BY_DEPTH["deep"])
        standard_count = len(SCANNERS_BY_DEPTH["standard"])
        assert deep_count > standard_count, (
            f"Deep ({deep_count}) standart ({standard_count}) dan ko'p bo'lishi kerak"
        )

    def test_all_scanners_are_base_scanner_subclasses(self):
        """Barcha scanner klasslar BaseScanner'dan meros olgan bo'lishi kerak."""
        for depth, scanners in SCANNERS_BY_DEPTH.items():
            for scanner_cls in scanners:
                assert issubclass(scanner_cls, BaseScanner), (
                    f"{depth}: {scanner_cls.__name__} BaseScanner dan meros olmagan"
                )

    def test_no_duplicates_in_list(self):
        """Har bir depth ro'yxatida takrorlanmagan klasslar bo'lishi kerak."""
        for depth, scanners in SCANNERS_BY_DEPTH.items():
            names = [cls.__name__ for cls in scanners]
            assert len(names) == len(set(names)), (
                f"{depth} ro'yxatida takrorlangan scanner topildi: {names}"
            )

    def test_quick_minimum_count(self):
        """Quick rejimda kamida 3 ta scanner bo'lishi kerak."""
        assert len(SCANNERS_BY_DEPTH["quick"]) >= 3

    def test_standard_minimum_count(self):
        """Standard rejimda kamida 10 ta scanner bo'lishi kerak."""
        assert len(SCANNERS_BY_DEPTH["standard"]) >= 10

    def test_all_scanner_classes_instantiable(self):
        """Barcha scanner klasslarni init qilish mumkin bo'lishi kerak."""
        for depth, scanners in SCANNERS_BY_DEPTH.items():
            for scanner_cls in scanners:
                try:
                    instance = scanner_cls()
                    assert instance.name != "BaseScanner", (
                        f"{scanner_cls.__name__} name atributini o'rnatmagan"
                    )
                except Exception as e:
                    pytest.fail(f"{depth}/{scanner_cls.__name__} init qilishda xato: {e}")
