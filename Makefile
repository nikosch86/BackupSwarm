# BackupSwarm Makefile — all development operations go through here.
# Never run go/docker commands directly; use `make <target>`.

BINARY       := backupswarm
CMD_PATH     := ./cmd/backupswarm
BUILD_DIR    := bin
COVERAGE_OUT := coverage.out
COVERAGE_MIN := 90

DOCKER_IMAGE := backupswarm:dev

# Multi-arch publish settings — kept in sync with .github/workflows/release.yml
PUBLISH_PLATFORMS := linux/amd64,linux/arm64
PUBLISH_DRYRUN_TAG := backupswarm:publish-dryrun

# Trivy — pinned version for reproducible security scans.
# Named docker volume keeps the vulnerability DB cached across runs.
TRIVY_IMAGE    := aquasec/trivy:0.70.0
TRIVY_CACHE    := backupswarm-trivy-cache
TRIVY_SEVERITY := HIGH,CRITICAL

GO           ?= go
GOFLAGS      ?=

.PHONY: all build test coverage coverage-report coverage-gaps lint fmt fmt-fix vet check clean \
        docker-build docker-run docker-compose-up docker-compose-down docker-compose-test \
        publish-dryrun \
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
COVERAGE_PKGS := ./internal/... ./pkg/...

## coverage: run tests with coverage and enforce $(COVERAGE_MIN)% minimum
coverage:
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=$(COVERAGE_OUT) $(COVERAGE_PKGS)
	@total=$$($(GO) tool cover -func=$(COVERAGE_OUT) | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo "Total coverage: $${total}%"; \
	awk -v t="$${total}" -v min="$(COVERAGE_MIN)" 'BEGIN { if (t+0 < min+0) { printf "FAIL: coverage %.1f%% is below required %s%%\n", t, min; exit 1 } else { printf "OK: coverage %.1f%% meets %s%% target\n", t, min } }' \
		|| { $(MAKE) -s coverage-gaps; exit 1; }

## coverage-report: print per-function coverage (requires coverage.out from `make coverage`)
coverage-report:
	@test -s $(COVERAGE_OUT) || { echo "no $(COVERAGE_OUT); run 'make coverage' first"; exit 1; }
	$(GO) tool cover -func=$(COVERAGE_OUT)

## coverage-gaps: list files below COVERAGE_MIN% (requires coverage.out from `make coverage`)
coverage-gaps:
	@test -s $(COVERAGE_OUT) || { echo "no $(COVERAGE_OUT); run 'make coverage' first"; exit 1; }
	@gaps=$$(awk -v min=$(COVERAGE_MIN) ' \
		NR > 1 && NF == 3 { \
			p = index($$1, ":"); \
			if (p == 0) next; \
			f = substr($$1, 1, p - 1); \
			s[f] += $$2; \
			if ($$3 + 0 > 0) c[f] += $$2 \
		} \
		END { \
			for (f in s) if (s[f] > 0) { \
				pct = (c[f] / s[f]) * 100; \
				if (pct < min + 0) printf "%6.2f%% %s\n", pct, f \
			} \
		}' $(COVERAGE_OUT) | sort -n); \
	if [ -z "$$gaps" ]; then \
		echo "all files meet the $(COVERAGE_MIN)% coverage gate"; \
	else \
		echo "files below $(COVERAGE_MIN)% coverage gate:"; \
		echo "$$gaps"; \
	fi

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

## publish-dryrun: multi-arch buildx build (no push) — mirrors release.yml's build step
# Builds the Dockerfile for both publish platforms via buildx.
# Output stays in the buildkit cache; no image is loaded or pushed.
publish-dryrun:
	docker buildx build \
		--platform $(PUBLISH_PLATFORMS) \
		--tag $(PUBLISH_DRYRUN_TAG) \
		--file Dockerfile \
		.

## docker-compose-test: end-to-end smoke test of the containerised 4-node swarm
# Brings the swarm up detached and asserts: node-b accepted all three
# joiners ("peer joined" >= 3), node-a backed up the seeded tree,
# node-b shipped its own backup payload (founder-as-source), node-a
# observed both forwarded announcements ("applied announcement" >= 2),
# and node-a dialed every announced peer ("dialed peer" >= 3).
docker-compose-test:
	docker compose up -d --build
	@echo "verifying image's BACKUPSWARM_LISTEN default feeds --listen..."
	@for i in $$(seq 1 30); do \
		if docker compose logs env-default-check 2>/dev/null | grep -q '"listen":"0.0.0.0:7777"'; then break; fi; \
		sleep 1; \
	done
	@docker compose logs env-default-check 2>/dev/null | grep -q '"listen":"0.0.0.0:7777"' || \
		{ echo "env-default-check did not bind to 0.0.0.0:7777 (image's BACKUPSWARM_LISTEN default broke)"; docker compose logs env-default-check; docker compose down -v; exit 1; }
	@echo "waiting for node-b to accept all three joiners..."
	@for i in $$(seq 1 90); do \
		count=$$(docker compose logs node-b 2>/dev/null | grep -c '"msg":"peer joined"'); \
		if [ "$$count" -ge 3 ]; then break; fi; \
		sleep 1; \
	done
	@count=$$(docker compose logs node-b 2>/dev/null | grep -c '"msg":"peer joined"'); \
	if [ "$$count" -lt 3 ]; then \
		echo "node-b only logged $$count 'peer joined' events; want >=3"; \
		docker compose logs node-b; docker compose down -v; exit 1; \
	fi
	@echo "waiting for node-a to complete at least one scan pass..."
	@for i in $$(seq 1 60); do \
		if docker compose logs node-a 2>/dev/null | grep -q 'backed up '; then break; fi; \
		sleep 1; \
	done
	@docker compose logs node-a 2>/dev/null | grep -q 'backed up ' || \
		{ echo "node-a never logged 'backed up'"; docker compose logs node-a; docker compose down -v; exit 1; }
	@echo "waiting for node-b to ship its own payload (founder-as-source)..."
	@for i in $$(seq 1 60); do \
		if docker compose logs node-b 2>/dev/null | grep -q 'backed up '; then break; fi; \
		sleep 1; \
	done
	@docker compose logs node-b 2>/dev/null | grep -q 'backed up ' || \
		{ echo "node-b never logged 'backed up' — founder-as-source flow regressed"; docker compose logs node-b; docker compose down -v; exit 1; }
	@echo "waiting for node-a to observe both forwarded PeerJoined announcements..."
	@for i in $$(seq 1 90); do \
		count=$$(docker compose logs node-a 2>/dev/null | grep -c '"msg":"applied announcement"'); \
		if [ "$$count" -ge 2 ]; then break; fi; \
		sleep 1; \
	done
	@count=$$(docker compose logs node-a 2>/dev/null | grep -c '"msg":"applied announcement"'); \
	if [ "$$count" -lt 2 ]; then \
		echo "node-a only logged $$count 'applied announcement' events; want >=2 (node-c + node-d)"; \
		docker compose logs node-a; docker compose logs node-b; docker compose down -v; exit 1; \
	fi
	@echo "waiting for node-a to dial every announced peer..."
	@for i in $$(seq 1 90); do \
		count=$$(docker compose logs node-a 2>/dev/null | grep -c '"msg":"dialed peer"'); \
		if [ "$$count" -ge 3 ]; then break; fi; \
		sleep 1; \
	done
	@count=$$(docker compose logs node-a 2>/dev/null | grep -c '"msg":"dialed peer"'); \
	if [ "$$count" -lt 3 ]; then \
		echo "node-a only logged $$count 'dialed peer' events; want >=3 (node-b at startup + node-c + node-d post-startup)"; \
		docker compose logs node-a; docker compose down -v; exit 1; \
	fi
	@echo "docker-compose-test: 4-node swarm formed; node-a backed up the seeded tree, node-b shipped its own payload, both saw forwarded announcements, node-a dialed each announced peer, and env-default-check bound via the image's BACKUPSWARM_LISTEN default"
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
