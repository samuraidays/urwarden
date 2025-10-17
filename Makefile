# ---- Project ----
APP := urwarden
CMD := ./cmd/urwarden
PKG := ./...

# ---- Auto versioning (from Git) ----
GIT_DESCRIBE := $(shell git describe --tags --always --dirty --abbrev=7 2>/dev/null || echo dev)
GIT_COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE   := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
BUILD_NUM    := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)

LDFLAGS := -X 'github.com/samuraidays/urwarden/internal/version.Version=$(GIT_DESCRIBE)' \
           -X 'github.com/samuraidays/urwarden/internal/version.Commit=$(GIT_COMMIT)' \
           -X 'github.com/samuraidays/urwarden/internal/version.BuildDate=$(BUILD_DATE)' \
           -X 'github.com/samuraidays/urwarden/internal/version.BuildNumber=$(BUILD_NUM)'

# ---- Defaults ----
URL ?= 'https://bad.example.com/login?next=%2Fhome'
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)

# ---- Help ----
.PHONY: help
help:
	@echo "Targets:"
	@echo "  make build     - build binary with auto version"
	@echo "  make install   - go install with ldflags (to \$$GOBIN or \$$GOPATH/bin)"
	@echo "  make test      - run unit tests"
	@echo "  make lint      - run golangci-lint"
	@echo "  make fmt       - gofmt/goimports via golangci-lint --fix"
	@echo "  make version   - print resolved version strings"
	@echo "  make clean     - remove build artifacts"

# ---- Meta ----
.PHONY: version
version:
	@echo "GIT_DESCRIBE = $(GIT_DESCRIBE)"
	@echo "GIT_COMMIT   = $(GIT_COMMIT)"
	@echo "BUILD_DATE   = $(BUILD_DATE)"
	@echo "BUILD_NUM    = $(BUILD_NUM)"

# ---- Build / Run / Install ----
.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

# Go公式の install （GOBIN へ配置）。再現性のため ldflags を注入。
.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

# ---- Quality ----
.PHONY: test
test:
	go test $(PKG)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: fmt
fmt:
	golangci-lint run --fix || true
	go fmt $(PKG)

# ---- Clean ----
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html
