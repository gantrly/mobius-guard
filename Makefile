# One entry point for local checks. CI runs `make check`.
.PHONY: install fmt lint typecheck test check build

install:
	uv sync --locked
	uv run pre-commit install

fmt:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run pyright

test:
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck test

build:
	uv build --all-packages
