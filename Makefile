# PromptWall developer tasks.
#
#   make help     list targets
#   make check    what CI runs
#   make demo     see an injection get stopped

.DEFAULT_GOAL := help
SHELL := /bin/bash
PY ?= python
BASELINE ?= bench/results/2026-08-26/results.json

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- setup ------------------------------------------------------------------

.PHONY: install
install: ## Install with dev extras
	$(PY) -m pip install -e ".[dev]"

.PHONY: install-all
install-all: ## Install with dev, ml and training extras
	$(PY) -m pip install -e ".[all]"

# --- quality ----------------------------------------------------------------

.PHONY: test
test: ## Run the test suite
	$(PY) -m pytest -q

.PHONY: cov
cov: ## Run tests with a coverage report
	$(PY) -m pytest --cov=promptwall --cov-report=term-missing -q

.PHONY: lint
lint: ## Lint and type-check
	$(PY) -m ruff check .
	$(PY) -m mypy promptwall

.PHONY: fmt
fmt: ## Auto-fix formatting and lint issues
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

.PHONY: validate
validate: ## Validate configuration and policy
	PW_AUTH_REQUIRED=false $(PY) -m promptwall.main check

.PHONY: check
check: lint test validate bench-check ## Everything CI runs

# --- benchmark --------------------------------------------------------------

.PHONY: datasets
datasets: ## Regenerate the benchmark corpora
	$(PY) scripts/seed_datasets.py

.PHONY: bench
bench: datasets ## Run the benchmark and write a report
	$(PY) bench/harness/runner.py --out /tmp/pw-bench.json
	$(PY) bench/harness/report.py /tmp/pw-bench.json --format console

.PHONY: bench-check
bench-check: ## Fail if the benchmark regressed against the committed baseline
	@$(PY) scripts/seed_datasets.py >/dev/null
	@$(PY) bench/harness/runner.py --quiet --out /tmp/pw-bench.json
	@$(PY) scripts/bench_delta.py $(BASELINE) /tmp/pw-bench.json --only promptwall

.PHONY: bench-baseline
bench-baseline: ## Record the current results as the new baseline
	$(PY) bench/harness/runner.py --quiet --out $(BASELINE)
	$(PY) bench/harness/report.py $(BASELINE) --out $(dir $(BASELINE))report.md
	@echo "baseline updated. Commit it with the reason it moved."

.PHONY: adaptive
adaptive: ## Measure evasion under an adaptive attacker
	$(PY) bench/adaptive_attacker.py --budget 12

.PHONY: ablate
ablate: ## Measure what each layer contributes
	$(PY) bench/harness/runner.py --defences promptwall --ablations

# --- models -----------------------------------------------------------------

.PHONY: train
train: ## Train and export the L2 classifier
	$(PY) models/train_classifier.py
	$(PY) models/export_onnx.py

.PHONY: eval-model
eval-model: ## Check the trained model actually beats the built-in scorer
	$(PY) models/eval_classifier.py

.PHONY: calibrate
calibrate: ## Suggest thresholds for a target false-positive rate
	$(PY) models/calibrate.py --target-fpr 0.01

# --- running ----------------------------------------------------------------

.PHONY: serve
serve: ## Run locally with the echo provider (no credentials needed)
	PW_UPSTREAM_PROVIDER=echo PW_AUTH_REQUIRED=false PW_MODE=enforce \
	  $(PY) -m uvicorn promptwall.main:app --reload --port 8080

.PHONY: demo
demo: ## Watch an injection succeed, then fail
	$(PY) demo/vulnerable_app/app.py

.PHONY: smoke
smoke: ## Smoke-test a running instance
	bash scripts/smoke_test.sh

# --- containers -------------------------------------------------------------

.PHONY: docker-build
docker-build: ## Build the image
	docker build -t promptwall:local .

.PHONY: up
up: ## Start the local stack
	docker compose up --build

.PHONY: down
down: ## Stop the local stack
	docker compose down -v

# --- housekeeping -----------------------------------------------------------

.PHONY: clean
clean: ## Remove build and cache artefacts
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
