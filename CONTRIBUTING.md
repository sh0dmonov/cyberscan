# Contributing to CyberScan

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs
Open an issue with:
- Python version
- OS
- Steps to reproduce
- Expected vs actual behavior

### Adding a New Scanner

1. Create `agent/modules/scanners/your_scanner.py`
2. Extend `BaseScanner`
3. Register in `agent/scanner_registry.py`
4. Add tests in `tests/`
5. Open a Pull Request

### Code Style
- Follow existing patterns
- Add docstrings to all classes and methods
- All tests must pass: `pytest tests/ -v`

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-scanner`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a Pull Request with a clear description

## Code of Conduct

Be respectful. This is a security tool — all contributions must be ethical and legal.
