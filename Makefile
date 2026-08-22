.PHONY: help install dev-install lint fmt type test test-cov run docker-build docker-up clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies
	pip install -r apps/platform/requirements.txt
	pip install -e packages/python-sdk

dev-install: ## Install dev + runtime dependencies and pre-commit hooks
	pip install -r requirements-dev.txt
	pip install -e packages/python-sdk
	pre-commit install || true

lint: ## Run ruff lint
	ruff check apps/platform/app packages/python-sdk/norinth_logger tests scripts demo-apps

fmt: ## Auto-format and fix lint
	ruff check --fix apps/platform/app packages/python-sdk/norinth_logger tests scripts demo-apps
	ruff format apps/platform/app packages/python-sdk/norinth_logger tests

type: ## Type-check the SDK
	mypy packages/python-sdk/norinth_logger

test: ## Run the test suite
	pytest

test-cov: ## Run tests with coverage
	pytest --cov=app --cov=norinth_logger --cov-report=term-missing

run: ## Run the platform locally on :8001
	NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3 \
	uvicorn app.main:app --app-dir apps/platform --reload --port 8001

docker-build: ## Build the platform Docker image
	docker compose build

docker-up: ## Run the platform via Docker Compose
	docker compose up --build

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache
