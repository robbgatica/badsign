.PHONY: help install install-dev test lint format clean

help:
	@echo "Available commands:"
	@echo "  make install      - Install package"
	@echo "  make install-dev  - Install package with dev dependencies"
	@echo "  make test         - Run tests"
	@echo "  make lint         - Run linters"
	@echo "  make format       - Format code with black"
	@echo "  make clean        - Remove build artifacts"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest --cov=clamav_siggen --cov-report=html --cov-report=term tests/

lint:
	pylint clamav_siggen/
	mypy clamav_siggen/

format:
	black clamav_siggen/ tests/
	isort clamav_siggen/ tests/

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache htmlcov/ .coverage
