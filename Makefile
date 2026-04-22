# BackupSwarm Makefile — all development operations go through here.
# Never run go/docker commands directly; use `make <target>`.

BINARY       := backupswarm
CMD_PATH     := ./cmd/backupswarm
BUILD_DIR    := bin
COVERAGE_OUT := coverage.out
COVERAGE_MIN := 90

DOCKER_IMAGE := backupswarm:dev

# Trivy — pinned version for reproducible security scans.
# Named docker volume keeps the vulnerability DB cached across runs.
TRIVY_IMAGE    := aquasec/trivy:0.70.0
TRIVY_CACHE    := backupswarm-trivy-cache
TRIVY_SEVERITY := HIGH,CRITICAL

GO           ?= go
GOFLAGS      ?=

.PHONY: all build test coverage coverage-report lint fmt fmt-fix vet check clean \
        docker-build docker-run docker-compose-up docker-compose-down \
        trivy-deps trivy-image security-scan story-done help \
        mod-get mod-tidy

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

## coverage-report: print per-function coverage (requires coverage.out from `make coverage`)
coverage-report:
	@test -s $(COVERAGE_OUT) || { echo "no $(COVERAGE_OUT); run 'make coverage' first"; exit 1; }
	$(GO) tool cover -func=$(COVERAGE_OUT)

## fmt: check formatting (fails if any file needs gofmt)
fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

## fmt-fix: rewrite any files that need gofmt in place
fmt-fix:
	gofmt -w .

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

## mod-get: add/update a module dependency — make mod-get PKG=<path>[@version]
mod-get:
	@test -n "$(PKG)" || { echo "usage: make mod-get PKG=<module-path>[@version]"; exit 1; }
	$(GO) get $(PKG)
	$(GO) mod tidy

## mod-tidy: reconcile go.mod/go.sum with current imports
mod-tidy:
	$(GO) mod tidy

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

## trivy-deps: scan source tree for vulnerable deps, secrets, and misconfigs (HIGH+CRITICAL)
# Misconfig scanners restricted to dockerfile — cloud/terraform checks don't apply here
# and Trivy's embedded AWS rego currently spams parse errors.
trivy-deps:
	docker volume inspect $(TRIVY_CACHE) >/dev/null 2>&1 || docker volume create $(TRIVY_CACHE) >/dev/null
	docker run --rm \
		-v "$(CURDIR):/src:ro" \
		-v $(TRIVY_CACHE):/root/.cache/trivy \
		$(TRIVY_IMAGE) \
		fs \
		--scanners vuln,secret,misconfig \
		--misconfig-scanners dockerfile \
		--severity $(TRIVY_SEVERITY) \
		--exit-code 1 \
		--no-progress \
		/src

## trivy-image: scan the built Docker image for vulnerable OS/app packages
trivy-image: docker-build
	docker volume inspect $(TRIVY_CACHE) >/dev/null 2>&1 || docker volume create $(TRIVY_CACHE) >/dev/null
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(TRIVY_CACHE):/root/.cache/trivy \
		$(TRIVY_IMAGE) \
		image \
		--severity $(TRIVY_SEVERITY) \
		--exit-code 1 \
		--no-progress \
		$(DOCKER_IMAGE)

## security-scan: run all security scans (deps + built image)
security-scan: trivy-deps trivy-image

## story-done: full story-completion gate — check + coverage + security-scan
# Must pass cleanly before a story can be marked ✅ in plan.md.
story-done: check coverage security-scan
	@echo ""
	@echo "story-done: all gates passed (lint, tests, coverage ≥ $(COVERAGE_MIN)%, security scan clean)"

## help: list documented targets
help:
	@awk '/^## / { sub(/^## /, "", $$0); print "  " $$0 }' $(MAKEFILE_LIST)
