# Builds the stateless Go sp-ssh helper.
.DEFAULT_GOAL := help
GO      ?= go
BIN     := bin
PKGS    := ./...

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build sp-ssh into ./bin
	$(GO) build -o $(BIN)/sp-ssh ./cmd/sp-ssh

.PHONY: vet
vet: ## go vet
	$(GO) vet $(PKGS)

.PHONY: test
test: ## Run all tests
	$(GO) test $(PKGS)

.PHONY: test-v
test-v: ## Run all tests (verbose)
	$(GO) test -v $(PKGS)

.PHONY: check
check: vet test ## vet + test

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN)
