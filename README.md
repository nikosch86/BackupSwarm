# BackupSwarm

A peer-to-peer encrypted backup tool. Share encrypted chunks of your data with a group of trusted nodes — like torrents, but for the kind of data that should live safely off-site.

- **Zero plaintext leaves your node.** All chunks are encrypted locally before they touch the wire.
- **Configurable redundancy** (1–N copies per chunk) and per-volume storage limits.
- **Explicit membership** via single-use join tokens — no open discovery, no auto-trust.

Status: **early development**.

---

## Design Highlights

| Area | Choice |
|---|---|
| Language | Go |
| Transport | QUIC (`quic-go`), TLS 1.3 built-in |
| Identity | Ed25519 per-node keypair (public key = node ID) |
| Encryption | Chunk-then-encrypt, X25519 + XChaCha20-Poly1305 (hybrid) |
| Discovery | Explicit single-use join tokens, no auto-discovery |
| Metadata | Local `bbolt` index, encrypted backup of the index to the swarm |
| Placement | Weighted random by reported free capacity, lazy re-replication on churn |
| Deployment | Docker image (primary), multi-platform binaries (secondary) |

---

## Requirements

- **Go 1.24+** (for local development)
- **Docker** (for container builds, multi-node testing, and security scanning)
- **Make** (everything is driven through the Makefile)

## Getting Started

```bash
# Build the binary
make build

# Identity is auto-generated on first use by invite/join/run.
# Default data dir: $XDG_DATA_HOME/backupswarm or ~/.local/share/backupswarm.
# Override with --data-dir or $BACKUPSWARM_DATA_DIR.

# Run the full test suite
make test

# Lint + test (the pre-PR gate)
make check
```

## Two-node swarm (local smoke test)

```bash
# Node A (founder): start the daemon and print an initial invite token.
./bin/backupswarm --data-dir /tmp/bs-a run \
    --listen 127.0.0.1:7777 --invite

# Copy the printed token. In a second terminal:

# Node B (joiner): verify the token over TLS, persist A, transition to daemon.
mkdir -p /tmp/bs-b-src && echo hello > /tmp/bs-b-src/test
./bin/backupswarm --data-dir /tmp/bs-b join <token> \
    --then-run --backup-dir /tmp/bs-b-src --listen 127.0.0.1:7778

# To issue further invites against the running daemon at /tmp/bs-a:
./bin/backupswarm --data-dir /tmp/bs-a invite
```

The daemon reads the storage peer from `<data-dir>/peers.db` (populated by
`join`). Omitting `--backup-dir` runs the daemon in pure storage-peer mode.
`run --invite` accepts `--token-out FILE` to write the token atomically and
`--no-ca` to opt the founder into pubkey-pin trust.

## Restore

Two ways to restore, assuming the storage peer (`node A` above) is up:

```bash
# Standalone one-shot: reassemble every indexed file under <dest>.
# Paths are rewritten as Dest + original-absolute-path.
./bin/backupswarm --data-dir /tmp/bs-b restore /tmp/rescue

# Or via the daemon: empty backup dir + --restore restores to the
# original locations before the scan loop starts.
rm -rf /tmp/bs-b-src/*
./bin/backupswarm --data-dir /tmp/bs-b run \
    --backup-dir /tmp/bs-b-src \
    --listen 127.0.0.1:7778 \
    --restore
```

Each chunk's post-decrypt plaintext hash is verified against the
index's `PlaintextHash`; a mismatch aborts the restore. Restored
files keep their original mtime so the daemon's incremental scan
does not re-upload them.

## Makefile Targets

All development operations go through the Makefile — never invoke `go` or `docker` directly.

### Build & Test

| Target | Purpose |
|---|---|
| `make build` | Compile the `backupswarm` binary into `bin/` |
| `make test` | Run the full test suite with the race detector |
| `make coverage` | Run tests with coverage and enforce the 90% minimum |
| `make coverage-report` | Print per-function coverage from the last `make coverage` run |
| `make lint` | Static analysis (`gofmt -l` + `go vet`) |
| `make fmt-fix` | Rewrite files in place to satisfy `gofmt` |
| `make check` | Lint + test — **stories are only complete when this is clean** |
| `make clean` | Remove `bin/` and coverage artifacts |
| `make mod-get PKG=<module>[@version]` | Add or update a Go module dependency (runs `go get` + `go mod tidy`) |
| `make mod-tidy` | Reconcile `go.mod`/`go.sum` with current imports |

### Docker

| Target | Purpose |
|---|---|
| `make docker-build` | Build the multi-stage Docker image (`backupswarm:dev`) |
| `make docker-run` | Run a single node in Docker (foreground) |
| `make docker-compose-up` | Spin up a local 3-node swarm for testing |
| `make docker-compose-down` | Tear down the local swarm |
| `make docker-compose-test` | Containerised end-to-end test: assert two joiners reach the founder, the joiner backs up the seeded tree, and the announcement reaches the third node |

### Security

| Target | Purpose |
|---|---|
| `make trivy-deps` | Scan source tree for vulnerable deps, leaked secrets, and misconfigs |
| `make trivy-image` | Scan the built Docker image for vulnerable OS/app packages |
| `make security-scan` | Run both — fails on any HIGH or CRITICAL finding |

Trivy runs inside Docker (pinned version, see Makefile). The vulnerability DB is cached in a named Docker volume (`backupswarm-trivy-cache`) so subsequent runs are fast. See the [Security](#security) section below for when to run these.

### Story-completion gate

| Target | Purpose |
|---|---|
| `make story-done` | Runs `check` + `coverage` + `security-scan`. **Must pass cleanly before a story is marked complete.** |

Run `make help` to list all targets with descriptions.

---

## Project Layout

```
cmd/backupswarm/           CLI entrypoint (thin wrapper around internal/cli)
internal/
  chunk/                   Chunking logic
  crypto/                  Encryption, key generation, key wrapping
  index/                   Local bbolt index
  node/                    Node identity, lifecycle
  protocol/                Wire protocol messages and handlers
  quic/                    QUIC transport and connection management
  nat/                     STUN / TURN / hole-punching (M4)
  store/                   On-disk chunk storage
  swarm/                   Membership, announcements, placement
  replication/             Redundancy tracking, re-replication
  cli/                     Cobra command wiring
pkg/token/                 Join token generation and parsing (public)
configs/                   Default config templates
Dockerfile                 Multi-stage build (distroless runtime)
docker-compose.yml         Local multi-node test setup
Makefile                   All development operations
```

---

## Security

BackupSwarm holds itself to a few hard rules:

- **No plaintext on the wire or at rest on remote nodes.** Chunks are encrypted with per-chunk symmetric keys; those keys are wrapped per-recipient.
- **Every protocol message is signed** with the sender's Ed25519 key and verified before it is acted on; replay protection via timestamp + monotonic sequence number.
- **Private key material is protected by 0600 permissions.**
- **No dependency with a known HIGH or CRITICAL vulnerability ships in the repo.** The `make security-scan` target (Trivy in Docker) enforces this — run it before opening a PR and in CI.

The scan covers three layers:

1. **Filesystem scan** (`trivy fs`) — Go modules (`go.mod` / `go.sum`), secrets accidentally committed, and Dockerfile/compose misconfigurations.
2. **Image scan** (`trivy image`) — OS packages and Go binaries in the built `backupswarm:dev` runtime image.
3. **(Planned, M5+)** SBOM generation and supply-chain provenance.

A full threat model lands in M7.7 (`THREAT_MODEL.md`).

---

## Contributing

Contributions follow conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`.

---

## License

TBD.
