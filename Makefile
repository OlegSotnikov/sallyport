# Builds the Swift Mac app and Go sp-ssh helper.

CORE := core
MAC  := mac
SP_SSH := $(CORE)/bin/sp-ssh

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: build-core build-mac ## Build both components

.PHONY: build-core
build-core: ## Build the sp-ssh helper into core/bin/
	cd $(CORE) && go build -o bin/sp-ssh ./cmd/sp-ssh
	@echo "built $(SP_SSH)"

.PHONY: build-mac
build-mac: ## Build the Swift menu-bar app
	cd $(MAC) && swift build

.PHONY: test
test: test-core test-mac ## Run all tests (Go + Swift)

.PHONY: test-core
test-core: ## go vet + go test ./...
	cd $(CORE) && go vet ./... && go test ./...

.PHONY: test-mac
test-mac: ## swift test
	cd $(MAC) && swift test

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(CORE)/bin $(MAC)/.build
