## APIScan Makefile
## Development and build automation
##
## Usage:
##   make build      — Build the binary
##   make test       — Run all tests
##   make lint       — Run linter
##   make run        — Build and run with help flag
##   make clean      — Remove build artifacts
##   make install    — Install binary to $GOPATH/bin

# Project metadata
PROJECT_NAME := apiscan
MODULE       := github.com/M-Mercy/ApiVulnScanner
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE   := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION   := $(shell go version | cut -d' ' -f3)

# Build settings
BINARY       := bin/$(PROJECT_NAME)
MAIN_PKG     := ./cmd/apiscan
LDFLAGS      := -ldflags "-X $(MODULE)/cmd/apiscan.Version=$(VERSION) \
                          -X $(MODULE)/cmd/apiscan.CommitHash=$(COMMIT) \
                          -X $(MODULE)/cmd/apiscan.BuildDate=$(BUILD_DATE) \
                          -s -w"

# Colour output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
CYAN   := \033[0;36m
RESET  := \033[0m

.PHONY: all build test lint clean install deps fmt vet help run scan-example

all: deps fmt vet lint test build ## Run full pipeline (CI equivalent)

## —— Build ————————————————————————————————————————————————————

build: ## Build the apiscan binary
	@echo "$(CYAN)▶ Building $(PROJECT_NAME) $(VERSION)...$(RESET)"
	@mkdir -p bin
	@go build $(LDFLAGS) -o $(BINARY) $(MAIN_PKG)
	@echo "$(GREEN)✓ Built: $(BINARY)$(RESET)"

build-all: ## Cross-compile for Linux, macOS, and Windows
	@echo "$(CYAN)▶ Cross-compiling...$(RESET)"
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(PROJECT_NAME)-linux-amd64   $(MAIN_PKG)
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(PROJECT_NAME)-linux-arm64   $(MAIN_PKG)
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(PROJECT_NAME)-darwin-amd64  $(MAIN_PKG)
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(PROJECT_NAME)-darwin-arm64  $(MAIN_PKG)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(PROJECT_NAME)-windows-amd64.exe $(MAIN_PKG)
	@echo "$(GREEN)✓ Cross-compiled to dist/$(RESET)"

install: build ## Install binary to GOPATH/bin
	@echo "$(CYAN)▶ Installing $(PROJECT_NAME)...$(RESET)"
	@cp $(BINARY) $(GOPATH)/bin/$(PROJECT_NAME)
	@echo "$(GREEN)✓ Installed to $(GOPATH)/bin/$(PROJECT_NAME)$(RESET)"

## —— Development ——————————————————————————————————————————————

deps: ## Download and tidy Go module dependencies
	@echo "$(CYAN)▶ Downloading dependencies...$(RESET)"
	@go mod download
	@go mod tidy
	@echo "$(GREEN)✓ Dependencies ready$(RESET)"

fmt: ## Format Go source files
	@echo "$(CYAN)▶ Formatting code...$(RESET)"
	@gofmt -s -w .
	@echo "$(GREEN)✓ Formatted$(RESET)"

vet: ## Run go vet static analysis
	@echo "$(CYAN)▶ Running go vet...$(RESET)"
	@go vet ./...
	@echo "$(GREEN)✓ Vet passed$(RESET)"

lint: ## Run golangci-lint (install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@echo "$(CYAN)▶ Running linter...$(RESET)"
	@which golangci-lint > /dev/null 2>&1 || (echo "$(YELLOW)⚠ golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(RESET)"; exit 0)
	@golangci-lint run ./...
	@echo "$(GREEN)✓ Lint passed$(RESET)"

## —— Testing ——————————————————————————————————————————————————

test: ## Run all unit tests
	@echo "$(CYAN)▶ Running tests...$(RESET)"
	@go test ./... -v -race -count=1 -timeout 60s
	@echo "$(GREEN)✓ All tests passed$(RESET)"

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)▶ Running tests with coverage...$(RESET)"
	@go test ./... -race -coverprofile=coverage.out -covermode=atomic
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: coverage.html$(RESET)"

test-short: ## Run only fast tests (skip integration tests)
	@go test ./... -short -timeout 30s

bench: ## Run benchmarks
	@go test ./... -bench=. -benchmem -run=^$

## —— Running ——————————————————————————————————————————————————

run: build ## Build and run apiscan --help
	@./$(BINARY) --help

scan-httpbin: build ## Scan httpbin.org as a safe demo target
	@echo "$(YELLOW)⚠ Scanning httpbin.org — this is a public test service$(RESET)"
	@./$(BINARY) scan https://httpbin.org \
		--i-have-authorization \
		--concurrency 3 \
		--rate-limit 5 \
		--output json,markdown,html \
		--verbose

## —— Maintenance ——————————————————————————————————————————————

clean: ## Remove build artifacts and reports
	@echo "$(CYAN)▶ Cleaning...$(RESET)"
	@rm -rf bin/ dist/ coverage.out coverage.html
	@find reports/ -name "*.json" -o -name "*.md" -o -name "*.html" | grep -v ".gitkeep" | xargs rm -f 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned$(RESET)"

check-security: ## Run gosec security scanner on the tool itself
	@echo "$(CYAN)▶ Running gosec...$(RESET)"
	@which gosec > /dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@gosec -fmt=text ./...

help: ## Show this help message
	@echo ""
	@echo "  $(CYAN)APIScan Makefile$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

.DEFAULT_GOAL := help
