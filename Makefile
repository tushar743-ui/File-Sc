PY ?= python3
ENVDIR := .venv
DEPS := .deps
TARGET ?= ./corpus
RULES ?= rules.yaml
STAMP := $(DEPS)/.stamp

PYBIN = $(shell [ -x $(ENVDIR)/bin/python ] && echo $(ENVDIR)/bin/python || echo $(PY))
RUNNER = $(shell [ -d $(DEPS) ] && echo PYTHONPATH=$(DEPS) || echo) $(PYBIN)

.PHONY: all start install test scan sarif bench baseline clean

all: start

start: install test scan

install: $(STAMP)

$(STAMP):
	@if $(PY) -m venv $(ENVDIR) >/dev/null 2>&1 \
	   && $(ENVDIR)/bin/pip install -q -e ".[dev]" >/dev/null 2>&1; then \
	  echo "installed into $(ENVDIR)"; \
	else \
	  rm -rf $(ENVDIR); \
	  $(PY) -m pip install -q --target $(DEPS) PyYAML pytest || exit 1; \
	  echo "installed into $(DEPS) (python venv unavailable)"; \
	fi
	@mkdir -p $(DEPS) && touch $(STAMP)

test: install
	@$(RUNNER) -m pytest -q

scan: install
	@$(RUNNER) -m scanner.cli scan $(TARGET) --rules $(RULES) --format table

sarif: install
	@$(RUNNER) -m scanner.cli scan $(TARGET) --rules $(RULES) --format sarif -o results.sarif
	@echo "wrote results.sarif"

bench: install
	@$(RUNNER) -m scanner.cli bench ./corpus --rules $(RULES) --labels corpus/labels.json

baseline: install
	@$(RUNNER) -m scanner.cli baseline $(TARGET) --rules $(RULES) -o .scanner-baseline.json
	@echo "wrote .scanner-baseline.json"

clean:
	@rm -rf $(ENVDIR) $(DEPS) .pytest_cache results.sarif
	@find . -name __pycache__ -type d -prune -exec rm -rf {} +
