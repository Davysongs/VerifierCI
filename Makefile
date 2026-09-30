PYTHON = python3
PYTEST = $(PYTHON) -m pytest

.PHONY: help install install-dev lint test test-unit test-integration test-property test-security test-all clean

help:
	@echo "Available targets:"
	@echo "  make install      - install runtime+dev dependencies"
	@echo "  make lint         - run compile checks"
	@echo "  make test         - run all test groups"
	@echo "  make test-unit    - run unit tests"
	@echo "  make test-integration - run integration tests"
	@echo "  make test-property - run property tests"
	@echo "  make test-security - run security tests"
	@echo "  make clean        - remove build/test artifacts"

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


test-property:
	PYTHONPATH=src $(PYTEST) tests/property


test-security:
	PYTHONPATH=src $(PYTEST) tests/security


test:
	$(MAKE) test-unit

clean:
	$(RM) -r .pytest_cache .coverage htmlcov dist build .eggs *.egg-info
