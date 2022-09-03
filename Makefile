MODULE_NAME := purus

.PHONY: help
help: ## show commands ## make
	@printf "\033[36m%-30s\033[0m %-50s %s\n" "[Sub command]" "[Description]" "[Example]"
	@grep -E '^[/a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | perl -pe 's%^([/a-zA-Z_-]+):.*?(##)%$$1 $$2%' | awk -F " *?## *?" '{printf "\033[36m%-30s\033[0m %-50s %s\n", $$1, $$2, $$3}'

.PHONY: format
format: ## format with black ## make format
	isort $(MODULE_NAME)
	isort test
	black .

.PHONY: lint
lint: ## lint python (flake8 and mypy) ## make lint
	mypy $(MODULE_NAME)

.PHONY: pytest
pytest: ## execute test with pytest ## make test-python
	pytest ./test -vv --cov=./$(MODULE_NAME) --cov-report=html
