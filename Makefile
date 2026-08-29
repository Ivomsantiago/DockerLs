.PHONY: install dev check-dev-deps lint type-check test security audit build run clean \
	engine engine-test engine-lint engine-clean

install:
	pip install .

dev:
	pip install -e ".[dev,keyring]"

lint:
	ruff check dockerls/ tests/
	ruff format --check dockerls/ tests/

format:
	ruff format dockerls/ tests/
	ruff check --fix dockerls/ tests/

type-check:
	mypy dockerls/

check-dev-deps:
	python -c "import pytest_asyncio" || (echo "pytest-asyncio is required; run: make dev" && exit 1)

test: check-dev-deps
	pytest tests/ -v --cov=dockerls --cov-report=term-missing

security:
	bandit -r dockerls/ -c pyproject.toml
	pip-audit

# --- Engine Go -----------------------------------------------------------
#
# O binário é opcional: sem ele o pipeline Python roda inteiro, e é por
# isso que ele não entra no `pip install`. Quem quiser o caminho em lote
# roda `make engine` e a CLI o encontra em `engine/bin/`.

engine:
	cd engine && go build -trimpath -ldflags="-s -w" -o bin/dockerls-engine ./cmd/dockerls-engine

engine-test:
	cd engine && go test -race ./...

engine-lint:
	cd engine && gofmt -l . && go vet ./...

engine-clean:
	rm -rf engine/bin

audit: lint type-check test security

build:
	docker build -t dockerls:latest .

run:
	docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges dockerls:latest

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
