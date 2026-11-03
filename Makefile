# One entry point for local checks. CI runs `make check`.
.PHONY: install fmt lint typecheck test test-stress check build bench

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
	uv run pytest -n auto --cov --cov-report=term-missing

test-stress:
	HYPOTHESIS_PROFILE=stress uv run pytest -n auto -q

check: lint typecheck test

bench:
	uv run python benchmarks/redact_stream.py

build:
	uv build --all-packages
