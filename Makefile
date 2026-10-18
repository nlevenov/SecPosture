.PHONY: install dev test lint security audit dashboard docker clean

install:
	pip install .

dev:
	pip install -e ".[dev,dashboard]"

test:
	pytest

lint:
	ruff check src tests

security:
	bandit -q -c pyproject.toml -r src
	pip-audit -r requirements.txt

audit:
	secposture audit --html --remediation

dashboard:
	secposture dashboard

docker:
	docker build -t secposture:latest .

clean:
	rm -rf var results reports baselines .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
