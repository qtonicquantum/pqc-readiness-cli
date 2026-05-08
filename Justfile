# Justfile for pqc-readiness-cli

default:
    @just --list

install:
    pip install -e ".[dev]"

test:
    python -m pytest -q

lint:
    ruff check src tests
    mypy src

cbom:
    python -m pqc_readiness.cli inventory --directory tests/fixtures --output self-cbom.json

clean:
    rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
    find . -type d -name __pycache__ -exec rm -rf {} +
