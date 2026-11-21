PY_PROJECTS := 03-llm-security-gateway 04-mlops-pipeline 05-data-pipeline 07-vuln-management-automation

.PHONY: install test lint evals train clean

install:
	@for p in $(PY_PROJECTS); do \
	  if [ -f $$p/requirements-dev.txt ]; then pip install -r $$p/requirements-dev.txt; else pip install -r $$p/requirements.txt; fi; \
	done
	pip install ruff==0.17.6

test: evals train
	@for p in $(PY_PROJECTS); do echo "== $$p"; (cd $$p && python -m pytest -q) || exit 1; done

evals:
	cd 03-llm-security-gateway && python evals/run_evals.py --min-precision 0.9 --min-recall 0.9

train:
	cd 04-mlops-pipeline && python -m src.train --out artifacts --min-pr-auc 0.5

lint:
	@for p in $(PY_PROJECTS); do (cd $$p && ruff check .) || exit 1; done
	terraform -chdir=01-terraform-aws-eks fmt -recursive -check
	promtool check rules 06-observability-sre/prometheus/*.yaml

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf 04-mlops-pipeline/artifacts .pytest_cache */.pytest_cache
