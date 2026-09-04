.PHONY: help install dev-install lint fmt type test test-cov build-frontend run docker-build docker-up clean lock lock-ci

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies (exact pinned versions)
	pip install --require-hashes -r apps/platform/requirements.lock.txt
	pip install -e packages/python-sdk

lock: ## Regenerate the dependency lock from requirements.txt (needs pip-tools, python 3.14 to match the image)
	pip-compile --generate-hashes --no-strip-extras \
		--output-file=apps/platform/requirements.lock.txt apps/platform/requirements.txt

lock-ci: ## Regenerate the CI locks for dev deps and CI tools (needs pip-tools, python 3.11 to match CI)
	pip-compile --generate-hashes --no-strip-extras \
		--output-file=requirements-dev.txt requirements-dev.in
	pip-compile --generate-hashes --no-strip-extras --allow-unsafe \
		--output-file=requirements-ci-tools.lock.txt requirements-ci-tools.txt

dev-install: ## Install dev + runtime dependencies and pre-commit hooks
	pip install -r requirements-dev.txt
	pip install -e packages/python-sdk
	pre-commit install || true

lint: ## Run ruff lint
	ruff check apps/platform/app packages/python-sdk/norinth_logger tests scripts

fmt: ## Auto-format and fix lint
	ruff check --fix apps/platform/app packages/python-sdk/norinth_logger tests scripts
	ruff format apps/platform/app packages/python-sdk/norinth_logger tests

type: ## Type-check the platform and SDK
	mypy apps/platform/app packages/python-sdk/norinth_logger

test: ## Run the test suite
	pytest

test-postgres: ## Run the test suite against PostgreSQL (needs NORINTH_TEST_DATABASE_URL)
	NORINTH_TEST_DATABASE_URL=$${NORINTH_TEST_DATABASE_URL:?set to a postgresql:// URL} pytest

test-frontend: ## Run frontend unit tests (vitest)
	cd apps/platform/frontend && npm test

test-cov: ## Run tests with coverage
	pytest --cov=app --cov=norinth_logger --cov-report=term-missing

migrate: ## Apply pending schema migrations and print schema status
	cd apps/platform && python -m app.storage.migrations

build-frontend: ## Build the dashboard bundle into apps/platform/app/dashboard/static (not committed)
	cd apps/platform/frontend && npm ci --no-audit --no-fund && npm run build

apps/platform/app/dashboard/static/index.html:
	$(MAKE) build-frontend

run: apps/platform/app/dashboard/static/index.html ## Run the platform locally on :8001 (builds the dashboard if missing)
	NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3 \
	uvicorn app.main:app --app-dir apps/platform --reload --port 8001

docker-build: ## Build the platform Docker image
	docker compose build

docker-up: ## Install/run the full stack (PostgreSQL + platform) from this checkout via the installer
	scripts/install.sh --source --dir . --yes

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache
