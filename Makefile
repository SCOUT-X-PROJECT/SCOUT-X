.PHONY: install test lint run-receiver run-dashboard run-demo evaluate

install:
	python -m pip install -r requirements-dev.txt

test:
	python -m pytest --cov=simulation --cov=dashboard --cov-fail-under=80

lint:
	ruff check .
	ruff format --check .
	mypy --follow-imports=silent

run-receiver:
	python -m simulation.ground_control.receiver

run-dashboard:
	python -m dashboard.server

run-demo:
	python -m simulation.demo.run_scenarios --headless

evaluate:
	python scripts/evaluate_ml.py
