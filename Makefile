lint:
	pre-commit run --all

test:
	poetry run pytest --cov=src --cov-branch --cov-fail-under=95 --cov-report html:coverage_report
