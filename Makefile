PYTHON = python3
PYTEST = $(PYTHON) -m pytest

.PHONY: help install install-dev lint test test-unit test-integration test-e2e test-property test-security test-all slice clean

help:
	@echo "Available targets:"
	@echo "  make install          - install runtime+dev dependencies"
	@echo "  make lint             - run compile checks"
	@echo "  make test             - run all test groups"
	@echo "  make test-unit        - run unit tests"
	@echo "  make test-integration - run integration tests"
	@echo "  make test-e2e         - run end-to-end tests"
	@echo "  make slice            - run canonical retry-contract 30-job Phase 1 vertical slice"
	@echo "  make test-property    - run property tests"
	@echo "  make test-security    - run security tests"
	@echo "  make clean            - remove build/test artifacts"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e .[dev]

install-dev: install

lint:
	$(PYTHON) -m compileall -q src tests


test-unit:
	PYTHONPATH=src $(PYTEST) tests/unit


test-integration:
	PYTHONPATH=src $(PYTEST) tests/integration


test-e2e:
	PYTHONPATH=src $(PYTEST) tests/e2e


slice:
	PYTHONPATH=src $(PYTHON) -m verifierci.cli --db /tmp/verifierci-slice/state.sqlite --artifact-dir /tmp/verifierci-slice/artifacts --json audit --task examples/retry-contract/task.yaml --panel examples/retry-contract/panel.jsonl --baseline examples/retry-contract/v1.yaml --candidate examples/retry-contract/v2.yaml --backend fixture --trusted-fixture --diagnostic --collect-only --repetitions 3 --output-dir /tmp/verifierci-slice/out


test-property:
	PYTHONPATH=src $(PYTEST) tests/property


test-security:
	PYTHONPATH=src $(PYTEST) tests/security


test:
	$(MAKE) test-unit

clean:
	$(RM) -r .pytest_cache .coverage htmlcov dist build .eggs *.egg-info
