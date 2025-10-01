# SecureSBOM Go SDK Makefile

# Go configuration
GO ?= go
GOFMT ?= gofmt "-s"
GOLANGCI_LINT ?= golangci-lint
DOCKER ?= docker

# Version and build info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Directories
PKG_DIR := ./pkg/securesbom
EXAMPLES_DIR := ./cmd/examples
BIN_DIR := ./bin
COVERAGE_DIR := ./coverage

# Go packages and files
PACKAGES ?= $(shell $(GO) list ./...)
VETPACKAGES ?= $(shell $(GO) list ./... | grep -v /examples/)
GOFILES := $(shell find . -name "*.go" -not -path "./vendor/*")
TEST_FILES := $(shell find . -name '*_test.go' -not -path "./vendor/*")

# Build flags
LDFLAGS := -X $(shell $(GO) list .)/pkg/securesbom.Version=$(VERSION) \
           -X $(shell $(GO) list .)/pkg/securesbom.Commit=$(COMMIT) \
           -X $(shell $(GO) list .)/pkg/securesbom.BuildTime=$(BUILD_TIME)

# Default target
.DEFAULT_GOAL := help

## Build targets

.PHONY: build
build: build-examples ## Build all examples

.PHONY: build-examples
build-examples: build-sign build-keymgmt ## TODO: Add this back in when the example is ready: build-verify

.PHONY: build-sign
build-sign: ## Build sign example
	@echo "Building sign example..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/sign $(EXAMPLES_DIR)/sign/

.PHONY: build-verify  
build-verify: ## Build verify example
	@echo "Building verify example..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/verify $(EXAMPLES_DIR)/verify/

.PHONY: build-keymgmt
build-keymgmt: ## Build keymgmt example
	@echo "Building keymgmt example..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/keymgmt $(EXAMPLES_DIR)/keymgmt/

.PHONY: install-examples
install-examples: ## Install examples to $GOPATH/bin
	$(GO) install -ldflags "$(LDFLAGS)" $(EXAMPLES_DIR)/sign/
	$(GO) install -ldflags "$(LDFLAGS)" $(EXAMPLES_DIR)/verify/
	$(GO) install -ldflags "$(LDFLAGS)" $(EXAMPLES_DIR)/keymgmt/

## Test targets

.PHONY: test
test: ## Run all tests with coverage
	@echo "Running tests..."
	@mkdir -p $(COVERAGE_DIR)
	@for pkg in $(PACKAGES); do \
		echo "Testing $$pkg"; \
		$(GO) test -v -race -covermode=atomic -coverprofile="$(COVERAGE_DIR)/$$(basename $$pkg).out" "$$pkg" || exit 1; \
	done
	@echo "Combining coverage profiles..."
	@if command -v gocovmerge >/dev/null 2>&1; then \
		gocovmerge $(COVERAGE_DIR)/*.out > $(COVERAGE_DIR)/merged.out; \
	else \
		echo "Warning: gocovmerge not found. Install with: go install github.com/wadey/gocovmerge@latest"; \
	fi

.PHONY: test-short
test-short: ## Run tests without coverage
	$(GO) test -short -race $(PACKAGES)

.PHONY: test-sdk
test-sdk: ## Run only SDK tests (not examples)
	$(GO) test -v -race -covermode=atomic $(PKG_DIR)

.PHONY: coverage
coverage: test ## Generate and display coverage report
	@if [ -f $(COVERAGE_DIR)/merged.out ]; then \
		$(GO) tool cover -html=$(COVERAGE_DIR)/merged.out -o $(COVERAGE_DIR)/coverage.html; \
		echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"; \
		$(GO) tool cover -func=$(COVERAGE_DIR)/merged.out | tail -1; \
	else \
		echo "No coverage data found. Run 'make test' first."; \
	fi

## Code quality targets

.PHONY: fmt
fmt: ## Format Go code
	$(GOFMT) -w $(GOFILES)

.PHONY: fmt-check
fmt-check: ## Check if code is formatted
	@diff=$$($(GOFMT) -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Code is not formatted. Please run 'make fmt':"; \
		echo "$$diff"; \
		exit 1; \
	fi

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(VETPACKAGES)

.PHONY: check
check: fmt-check vet lint test-short ## Run all checks (formatting, vetting, linting, tests)

## Documentation targets

.PHONY: docs
docs: ## Generate documentation
	@echo "Generating Go documentation..."
	$(GO) doc -all $(PKG_DIR) > docs/api-reference.txt
	@echo "Documentation generated in docs/api-reference.txt"

.PHONY: serve-docs
serve-docs: ## Serve documentation locally
	@echo "Starting documentation server at http://localhost:6060"
	@echo "Visit http://localhost:6060/pkg/$(shell $(GO) list .)/ to view SDK docs"
	godoc -http=:6060

.PHONY: markdown-lint
markdown-lint: ## Lint markdown files
	$(DOCKER) run --rm -v "$(shell pwd)":/build --workdir /build \
		markdownlint/markdownlint:0.13.0 *.md docs/*.md

## Development targets

.PHONY: run-sign-example
run-sign-example: build-sign ## Run sign example with sample data
	@echo "Running sign example..."
	@echo '{"name":"example-sbom","version":"1.0"}' | $(BIN_DIR)/sign -key-id example-key

.PHONY: dev-setup
dev-setup: ## Set up development environment
	@echo "Installing development tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install github.com/wadey/gocovmerge@latest
	$(GO) install golang.org/x/tools/cmd/godoc@latest
	@echo "Development tools installed"

.PHONY: deps
deps: ## Download and verify dependencies
	$(GO) mod download
	$(GO) mod verify

.PHONY: deps-update
deps-update: ## Update dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

.PHONY: tidy
tidy: ## Clean up go.mod and go.sum
	$(GO) mod tidy

## Release targets

.PHONY: release-check
release-check: check ## Pre-release checks
	@echo "Running pre-release checks..."
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then \
		echo "Error: VERSION must be set for release"; \
		exit 1; \
	fi
	@echo "Ready for release $(VERSION)"

.PHONY: tag
tag: ## Create and push a new tag (requires VERSION=x.y.z)
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make tag VERSION=v1.0.0"; \
		exit 1; \
	fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "Tagged and pushed $(VERSION)"

## Cleanup targets

.PHONY: clean
clean: ## Clean build artifacts and coverage data
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -f profile.out
	$(GO) clean -cache -testcache -modcache

.PHONY: clean-examples
clean-examples: ## Clean only example binaries
	rm -rf $(BIN_DIR)

## Utility targets

.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

.PHONY: help
help: ## Show this help message
	@echo "SecureSBOM Go SDK - Available targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}' | \
		sort
	@echo
	@echo "Examples:"
	@echo "  make build                    # Build all examples"
	@echo "  make test                     # Run tests with coverage"
	@echo "  make check                    # Run all quality checks"
	@echo "  make tag VERSION=v1.0.0       # Create and push a release tag"