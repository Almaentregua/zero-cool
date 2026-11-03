.DEFAULT_GOAL := help

# Load backend/.env when it exists (secrets such as NVD_API_KEY live there).
BACKEND_ENV := $(if $(wildcard backend/.env),--env-file .env,)
.PHONY: help setup install install-backend install-frontend dev backend frontend \
        ingest ingest-kev ingest-osv ingest-nvd ingest-epss test test-backend test-frontend lint format typecheck check build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup: ## Create backend/.env from the example (never overwrites an existing one)
	@if [ -f backend/.env ]; then echo "backend/.env already exists; left untouched."; else cp backend/.env.example backend/.env && echo "Created backend/.env. Edit it to add your NVD_API_KEY (optional)."; fi

install: install-backend install-frontend ## Install all dependencies

install-backend: ## Install backend dependencies
	cd backend && uv sync

install-frontend: ## Install frontend dependencies
	cd frontend && npm install

dev: ## Run backend and frontend together (Ctrl+C stops both)
	$(MAKE) -j2 backend frontend

backend: ## Run the API with auto-reload on :8000
	cd backend && uv run $(BACKEND_ENV) uvicorn zero_cool_api.main:app --reload --port 8000

frontend: ## Run the Vite dev server on :5173
	cd frontend && npm run dev

ingest: ingest-kev ingest-osv ingest-epss ingest-nvd ## Run every ingestion in order: KEV, OSV, EPSS, then NVD (slow)

ingest-kev: ## Download the CISA KEV catalog into the local database
	cd backend && uv run $(BACKEND_ENV) python -m zero_cool_api.ingest kev

ingest-nvd: ## Enrich KEV CVEs with NVD data (LIMIT=n to try a few, FORCE=1 to refetch)
	cd backend && uv run $(BACKEND_ENV) python -m zero_cool_api.ingest nvd $(if $(LIMIT),--limit $(LIMIT),) $(if $(FORCE),--force,)

ingest-osv: ## Import GitHub advisories for the ecosystems in technologies.yaml (via OSV)
	cd backend && uv run $(BACKEND_ENV) python -m zero_cool_api.ingest osv

ingest-epss: ## Add EPSS scores to the KEV CVEs
	cd backend && uv run $(BACKEND_ENV) python -m zero_cool_api.ingest epss

test: test-backend test-frontend ## Run all tests

test-backend: ## Run backend tests
	cd backend && uv run pytest

test-frontend: ## Run frontend tests
	cd frontend && npm test

lint: ## Lint backend and frontend
	cd backend && uv run ruff check .
	cd frontend && npm run lint

format: ## Format backend code
	cd backend && uv run ruff format .

typecheck: ## Type check backend and frontend
	cd backend && uv run mypy
	cd frontend && npx tsc -b

check: ## Everything required before finishing a task
	cd backend && uv run ruff check . && uv run ruff format --check .
	$(MAKE) typecheck lint test

build: ## Build the frontend for production
	cd frontend && npm run build

clean: ## Remove build artifacts and caches
	rm -rf frontend/dist backend/.pytest_cache backend/.mypy_cache backend/.ruff_cache
