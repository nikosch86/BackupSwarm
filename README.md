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
| Chunk lifecycle | Owner-signed delete on file removal; storage-side TTL safety net (30d default, owner renews periodically); periodic integrity scrub |
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

### Get the prebuilt image

Multi-arch images (`linux/amd64` + `linux/arm64`) ship to GitHub Container Registry:

```bash
# Stable: every git tag v* publishes :vX.Y.Z, :vX.Y, and :latest
docker pull ghcr.io/nikosch86/backupswarm:latest

# Rolling/unstable: every push to main publishes :main-dev (overwritten)
# plus :main-dev-<short-sha> (immutable, for traceability)
docker pull ghcr.io/nikosch86/backupswarm:main-dev
```

Ready-to-run compose templates for the three node roles
(storage-peer, backup-source, dual-role) live under [`examples/`](examples/).

### Container defaults

The image bakes in `BACKUPSWARM_LISTEN=0.0.0.0:7777`, so `docker run … backupswarm run` binds to that port without a `--listen` flag. Override by setting the env var (`-e BACKUPSWARM_LISTEN=0.0.0.0:9000`) or by passing `--listen` on the CLI; the flag wins over the env.

### Auto-join from an env var

For containerised joiners, `run` reads `BACKUPSWARM_INVITE_TOKEN` at startup
and joins the swarm before the daemon serves traffic. Subsequent restarts of
the same data dir skip the join (idempotent on a populated `peers.db`).

```bash
docker run --rm \
    -v bsw-data:/data \
    -v bsw-src:/backup \
    -e BACKUPSWARM_INVITE_TOKEN="$(cat /tmp/founder.token)" \
    -p 7777:7777/udp \
    ghcr.io/nikosch86/backupswarm:latest \
    run --backup-dir /backup
```

### NAT / advertised address

When the introducer is behind NAT, the address embedded in invite tokens
must be the externally-routable one, not the bound listener. Pass
`--advertise-addr <host:port>` to `run --invite` (founder bootstrap) or
`invite` (steady-state). When `--listen` is omitted (and
`BACKUPSWARM_LISTEN` is unset), it defaults to
`0.0.0.0:<port-of-advertise-addr>` — convenient for Docker setups where
the bound address is irrelevant. `BACKUPSWARM_ADVERTISE_ADDR` is read as
a fallback when the flag is empty.

The same flag also controls the address a joiner reports to the founder
during the auto-join handshake — set it on the joiner side too when the
joiner is reachable at a different address than its bound listener, so
the founder's peers.db records a routable peer address.

```bash
# Founder behind NAT, port-forwarded as 203.0.113.7:7777 → container:7777
docker run --rm \
    -v bsw-data:/data \
    -e BACKUPSWARM_ADVERTISE_ADDR=203.0.113.7:7777 \
    -p 7777:7777/udp \
    ghcr.io/nikosch86/backupswarm:latest \
    run --invite
```

#### Auto-discovered public IP via STUN

Pass `--advertise-addr auto` (or `BACKUPSWARM_ADVERTISE_ADDR=auto`) to
`run` or `invite` to resolve the externally-routable host via a STUN
binding request and combine it with the bound listener port.
`--stun-server <host:port>` selects the server (default
`stun.l.google.com:19302`). When `auto` is in effect on `run`, the daemon
also re-queries STUN periodically (default 5 minutes) and broadcasts an
`AddressChanged` announcement to live peers when the public IP changes.

```bash
# Founder discovers its public IP via STUN at startup and on every refresh.
docker run --rm \
    -v bsw-data:/data \
    -p 7777:7777/udp \
    ghcr.io/nikosch86/backupswarm:latest \
    run --invite --advertise-addr auto
```

#### UDP buffer warning (optional)

quic-go logs `failed to sufficiently increase receive buffer size` on
startup when the kernel's UDP buffer ceilings are below ~7 MB. The runtime
is unaffected; the warning is benign for small swarms. To silence it, set
both keys on the host:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
# or persist via /etc/sysctl.d/99-quic.conf
```

`docker run --sysctl` is supported on Linux 5.10+ but blocked by the
apparmor/seccomp profiles on many distros, so the host-level fix is the
reliable path.

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
# Standalone one-shot: reassemble every indexed file under <dest>,
# preserving the relative tree under the original backup root.
./bin/backupswarm --data-dir /tmp/bs-b restore /tmp/rescue

# Or via the daemon: empty backup dir + --restore restores each
# file under the configured --backup-dir before the scan loop starts.
rm -rf /tmp/bs-b-src/*
./bin/backupswarm --data-dir /tmp/bs-b run \
    --backup-dir /tmp/bs-b-src \
    --listen 127.0.0.1:7778 \
    --restore
```

Index entries are stored as paths relative to the configured backup
root, and every restore filesystem operation runs through an
`*os.Root` rooted at the destination — a tampered index can never
direct writes outside the destination tree. Each chunk's post-decrypt
plaintext hash is verified against the index's `PlaintextHash`; a
mismatch aborts the restore. Restored files keep their original
mtime so the daemon's incremental scan does not re-upload them.

## Disaster recovery

If the backup-source node is wiped — disk failure, lost laptop, ransomware
— recovery hinges entirely on whether its **identity keys** survived.
Storage peers hold ciphertext wrapped to the source node's public
recipient key; only the matching private key can unwrap it. Everything
else in the data dir is rebuildable from the surviving swarm.

### What to back up out-of-band

These files in `<data-dir>` are irreplaceable. Copy them somewhere
offline (encrypted USB, password manager, paper) when you first stand
up the node:

| File | Role | If lost |
|---|---|---|
| `node.key` | Ed25519 private key — the node ID | Cannot re-attach as the same node; chunks become orphaned on storage peers |
| `node.xkey` | X25519 private key — unwraps per-chunk symmetric keys | **All backed-up data is permanently unreadable** |
| `node.pub` / `node.xpub` | Public halves of the above | Derivable from the private keys, but easier to copy alongside |

Founder nodes additionally hold `ca.key` / `ca.crt` — back these up if
you want to keep issuing new invites after a founder rebuild. Without
them, existing peers keep working but no new joiners can be admitted.

The rest is regenerable: `peers.db` (rebuilt by re-joining the swarm),
`node.crt` (re-issued by the founder during re-join), and `index.db`
(rebuilt by `restore-index`).

### Recovery procedure

Assuming `node.key` + `node.xkey` (and ideally their `.pub` siblings)
were preserved out-of-band:

1. **Restore the keys** into a fresh data dir with locked-down permissions:
   ```bash
   mkdir -p /new/data-dir && chmod 700 /new/data-dir
   cp /offline-backup/node.key  /new/data-dir/
   cp /offline-backup/node.xkey /new/data-dir/
   cp /offline-backup/node.pub  /new/data-dir/   # optional; regenerable
   cp /offline-backup/node.xpub /new/data-dir/   # optional; regenerable
   chmod 600 /new/data-dir/node.key /new/data-dir/node.xkey
   ```

2. **Re-join the swarm** to rebuild `peers.db`. Issue a fresh invite from
   any surviving storage peer:
   ```bash
   ./bin/backupswarm --data-dir /surviving/peer invite
   ```
   then redeem it on the recovering node:
   ```bash
   ./bin/backupswarm --data-dir /new/data-dir join <token>
   ```
   The identity public key is unchanged, so storage peers recognize the
   recovering node as the original owner and continue serving its chunks.

3. **Rebuild the index** from the encrypted snapshot a storage peer
   already holds (the running daemon ships one every
   `--index-backup-interval`, default 5 min):
   ```bash
   ./bin/backupswarm --data-dir /new/data-dir restore-index
   ```
   `restore-index` dials each storage peer, fetches the encrypted
   snapshot, decrypts it with the local recipient key, and writes
   `index.db`.

4. **Reassemble the files** the same way as a normal restore:
   ```bash
   ./bin/backupswarm --data-dir /new/data-dir restore /restored/tree
   ```

### If the keys are gone

There is no recovery path. Chunks on storage peers are wrapped to a
public key whose private half no longer exists. This is the same
property that prevents a compromised storage peer from reading any of
the data it holds — the asymmetry cuts both ways.

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
| `make publish-dryrun` | Multi-arch buildx build (`linux/amd64` + `linux/arm64`) without pushing — sanity-checks the release workflow's build command locally |

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
compose.yaml               Local multi-node test setup
Makefile                   All development operations
```

---

## Security

BackupSwarm holds itself to a few hard rules:

- **No plaintext on the wire or at rest on remote nodes.** Each chunk is encrypted with a fresh per-chunk XChaCha20-Poly1305 key (random 24-byte nonce); the symmetric key is wrapped per-recipient via X25519 + `nacl/box.SealAnonymous`.
- **Every connection is mutually authenticated.** QUIC uses TLS 1.3 with one of two per-swarm trust modes — a swarm-specific Ed25519 CA (default) or pinned-pubkey trust (`--no-ca` swarms). The peer's Ed25519 public key is verified inside the TLS callback in both modes, and the listener's `VerifyPeer` predicate then gates membership against `peers.db`. Application-layer per-message Ed25519 signatures and timestamp/sequence replay protection are not currently implemented (planned, M7.x).
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
