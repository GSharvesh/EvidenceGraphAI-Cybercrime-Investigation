.PHONY: install lint format typecheck test test-unit test-integration docker-up docker-down validate clean

PYTHON = .venv/Scripts/python
PIP = .venv/Scripts/pip
RUFF = .venv/Scripts/ruff
BLACK = .venv/Scripts/black
MYPY = .venv/Scripts/mypy
PYTEST = .venv/Scripts/pytest

install:
	$(PIP) install -e .[dev]

lint:
	$(RUFF) check .
	$(BLACK) --check .

format:
	$(BLACK) .
	$(RUFF) check --fix .

typecheck:
	$(MYPY) core api

test: test-unit test-integration

test-unit:
	$(PYTEST) tests/unit -v --cov=core --cov-report=term-missing

test-integration:
	$(PYTEST) tests/integration -v

docker-up:
	docker compose -f infra/docker/docker-compose.yml up -d

docker-down:
	docker compose -f infra/docker/docker-compose.yml down -v

validate:
	bash scripts/validate_phase0.sh

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
