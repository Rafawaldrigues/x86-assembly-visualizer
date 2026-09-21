# ---------------------------------------------------------------------------
# ASM X — developer tasks
#
#   make            (default target: help)
#   make test       run the unittest suite
#   make quality    lint + typecheck + coverage (what CI runs)
#
# ASM X itself has no runtime dependencies; the targets that need extra
# tooling (flake8, mypy, coverage, black, docker) are the only ones that
# require `make install-dev` first.
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: help install-dev test test-gui coverage lint format typecheck quality gates \
        run check docker-build docker-test clean

PYTHON  ?= python3
IMAGE   ?= asmx:dev

# `xvfb-run` gives the Tkinter tests a virtual display when it is installed.
XVFB     := $(shell command -v xvfb-run 2>/dev/null)
XVFB_RUN := $(if $(XVFB),$(XVFB) -a ,)

TESTS      := $(PYTHON) -m unittest discover -s tests -v
COVERAGE   := $(XVFB_RUN)$(PYTHON) -m coverage run --source=asmx -m unittest discover -s tests

help: ## List the available targets (default)
	@echo "ASM X — available make targets:"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
	@echo
	@echo "  python:   $(PYTHON)"
	@echo "  xvfb-run: $(if $(XVFB),$(XVFB),not found — GUI tests will skip)"

install-dev: ## Install the development tooling (asmx stays dependency-free)
	$(PYTHON) -m pip install -r requirements-dev.txt

test: ## Run the full unittest suite (GUI tests skip without a display)
	$(TESTS)

test-gui: ## Run the suite under xvfb-run so the GUI tests really execute
	@if [ -n "$(XVFB)" ]; then \
		echo "using $(XVFB)"; \
		$(TESTS); \
	else \
		echo "xvfb-run not found — running without a virtual display"; \
		echo "(install it with: sudo apt install xvfb)"; \
		$(TESTS); \
	fi

coverage: ## Measure coverage and fail below 94%
	$(COVERAGE)
	$(PYTHON) -m coverage report --fail-under=94 --show-missing

lint: ## Static style check with flake8
	$(PYTHON) -m flake8 asmx/ tests/ tools/ asmx.py --max-line-length=100 --extend-ignore=E203,W503

format: ## Auto-format the source with black
	$(PYTHON) -m black asmx/ tests/ --line-length=100

typecheck: ## Static type check with mypy
	$(PYTHON) -m mypy asmx/

quality: lint typecheck gates coverage ## lint + typecheck + portões + cobertura

gates: ## Check 100% type hints/docstrings and that examples/ matches the package
	$(PYTHON) tools/quality_gates.py
	$(PYTHON) tools/export_examples.py --check

run: ## Open the Tkinter GUI
	$(PYTHON) -m asmx

check: ## Validate examples/linux-hello.asm with the CLI (falls back to CLI help)
	@if [ ! -f asmx/cli.py ]; then \
		echo "asmx/cli.py is missing: the CLI is not available in this checkout."; \
		exit 1; \
	elif [ -f examples/linux-hello.asm ]; then \
		$(PYTHON) -m asmx check examples/linux-hello.asm; \
	else \
		echo "examples/linux-hello.asm not found — showing the CLI help instead:"; \
		$(PYTHON) -m asmx check --help; \
	fi

docker-build: ## Build the container image
	docker build -t $(IMAGE) .

docker-test: docker-build ## Build the image and run the quality gate inside it
	docker run --rm $(IMAGE) quality

clean: ## Remove caches, coverage data and build artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage coverage.xml htmlcov \
		build dist .eggs *.egg-info
