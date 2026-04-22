# BackupSwarm Makefile — all development operations go through here.
# Never run go/docker commands directly; use `make <target>`.

BINARY       := backupswarm
CMD_PATH     := ./cmd/backupswarm
BUILD_DIR    := bin
COVERAGE_OUT := coverage.out
COVERAGE_MIN := 90

DOCKER_IMAGE := backupswarm:dev

GO           ?= go
GOFLAGS      ?=

.PHONY: all build test coverage lint fmt vet check clean \
        docker-build docker-run docker-compose-up docker-compose-down help

all: check build

## build: compile the backupswarm binary into bin/
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)

## test: run the full test suite with race detector
test:
	$(GO) test -race -count=1 ./...

# Packages measured for coverage: library code only. cmd/ is a thin wrapper
# around internal/cli and is exercised via `make build` / end-to-end tests.
# Expand this list as pkg/ subpackages are introduced (e.g. ./pkg/... from M2.1).
COVERAGE_PKGS := ./internal/...

## coverage: run tests with coverage and enforce $(COVERAGE_MIN)% minimum
coverage:
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=$(COVERAGE_OUT) $(COVERAGE_PKGS)
	@total=$$($(GO) tool cover -func=$(COVERAGE_OUT) | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo "Total coverage: $${total}%"; \
	awk -v t="$${total}" -v min="$(COVERAGE_MIN)" 'BEGIN { if (t+0 < min+0) { printf "FAIL: coverage %.1f%% is below required %s%%\n", t, min; exit 1 } else { printf "OK: coverage %.1f%% meets %s%% target\n", t, min } }'

## fmt: check formatting (fails if any file needs gofmt)
fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

## vet: run go vet across all packages
vet:
	$(GO) vet ./...

## lint: static analysis (gofmt + go vet)
lint: fmt vet

## check: lint + test (stories are only complete when this passes cleanly)
check: lint test

## clean: remove build artifacts and coverage output
clean:
	rm -rf $(BUILD_DIR) $(COVERAGE_OUT)

## docker-build: build the multi-stage Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE) .

## docker-run: run a single node in Docker (foreground)
docker-run: docker-build
	docker run --rm -it $(DOCKER_IMAGE)

## docker-compose-up: spin up multi-node local swarm
docker-compose-up:
	docker compose up --build

## docker-compose-down: tear down the local swarm
docker-compose-down:
	docker compose down -v

## help: list documented targets
help:
	@awk '/^## / { sub(/^## /, "", $$0); print "  " $$0 }' $(MAKEFILE_LIST)
