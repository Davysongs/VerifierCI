PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
PYTEST = $(PYTHON) -m pytest

.PHONY: help install install-dev lint lint-all test test-unit test-integration test-e2e test-property test-security test-all slice clean

help:
	@echo "Available targets:"
	@echo "  make install          - install runtime+dev dependencies"
	@echo "  make lint             - run compile checks"
	@echo "  make lint-all         - run compile, ruff format/lint, and mypy checks"
	@echo "  make test             - run unit tests"
	@echo "  make test-unit        - run unit tests"
	@echo "  make test-integration - run integration tests"
	@echo "  make test-e2e         - run end-to-end tests"
	@echo "  make slice            - run canonical retry-contract 30-job Phase 1 vertical slice"
	@echo "  make test-property    - run property tests"
	@echo "  make test-security    - run security tests"
	@echo "  make test-all         - run unit, integration, and e2e tests"
	@echo "  make clean            - remove build/test artifacts"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e .[dev]

install-dev: install

lint:
	$(PYTHON) -m compileall -q src tests


lint-all: lint
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .
	PYTHONPATH=src $(PYTHON) -m mypy src tests


test-unit:
	PYTHONPATH=src $(PYTEST) tests/unit


test-integration:
	PYTHONPATH=src $(PYTEST) tests/integration


test-e2e:
	PYTHONPATH=src $(PYTEST) tests/e2e


SLICE_TMP ?= /tmp/verifierci-slice

slice:
	@mkdir -p "$(SLICE_TMP)"
	@SLICE_RUN_DIR="$$(mktemp -d "$(SLICE_TMP)/run-XXXXXX")" && \
		echo "Slice run directory: $$SLICE_RUN_DIR" >&2 && \
		PYTHONPATH=src $(PYTHON) -m verifierci.cli \
			--db "$$SLICE_RUN_DIR/state.sqlite" \
			--artifact-dir "$$SLICE_RUN_DIR/artifacts" \
			--json \
			audit \
			--task examples/retry-contract/task.yaml \
			--panel examples/retry-contract/panel.jsonl \
			--baseline examples/retry-contract/v1.yaml \
			--candidate examples/retry-contract/v2.yaml \
			--backend fixture \
			--trusted-fixture \
			--diagnostic \
			--collect-only \
			--repetitions 3 \
			--output-dir "$$SLICE_RUN_DIR/out"


test-property:
	PYTHONPATH=src $(PYTEST) tests/property


test-security:
	PYTHONPATH=src $(PYTEST) tests/security


test-all:
	PYTHONPATH=src $(PYTEST) tests/unit tests/integration tests/e2e


test:
	$(MAKE) test-unit

clean:
	$(RM) -r .pytest_cache .coverage htmlcov dist build .eggs *.egg-info
