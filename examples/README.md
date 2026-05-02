# Examples

Compose-based templates for the three roles a `backupswarm` node can
play. Each variant is self-contained — pick the one matching your role,
set the env vars described in its `README.md`, and `docker compose up`.

| Variant | Backs up its own files? | Stores chunks for others? | Key flags |
|---|---|---|---|
| [`storage-peer/`](storage-peer/) | no | yes | `--max-storage 100g`, no `--backup-dir` |
| [`backup-source/`](backup-source/) | yes | no | `--backup-dir`, `--max-storage 0` |
| [`dual-role/`](dual-role/) | yes | yes | `--backup-dir`, `--max-storage 100g` |

All variants pull the prebuilt image from GitHub Container Registry. See
[Get the prebuilt image](../README.md#get-the-prebuilt-image) in the
top-level README for tag conventions and the rolling/stable channels.

All three compose files bind to `0.0.0.0:7777` via the `--port` flag's
default — no `--listen` flag needed. To run several of these on one
host, change the `ports:` host-side mapping or set `BACKUPSWARM_PORT`
(or `--port`) per service. When the host-side port differs from the
container-side port, set `BACKUPSWARM_PORT` to the container-side value
and `BACKUPSWARM_ADVERTISE_ADDR` to the host:port pair the swarm
should dial.

## The three roles

- **storage-peer**: donates disk + bandwidth to the swarm; has no local
  data it cares about. Set `--max-storage` to your donation size.
- **backup-source**: pushes a local directory to the swarm but refuses to
  store other peers' chunks. The `--max-storage 0` knob disables storage
  entirely (incoming `PutChunk` rejected; capacity probe reports
  saturated so peers exclude this node from placement).
- **dual-role**: both backs up its own data and stores chunks for
  others. The standard operator setup.

## Joining a swarm

Every variant expects an invite token in `BACKUPSWARM_INVITE_TOKEN`. To
issue one against an already-running daemon container:

```bash
docker exec <existing-container> backupswarm --data-dir /data invite
```

To bootstrap a brand-new swarm, run `run --invite` once on a founder
node (see the [Two-node swarm](../README.md#two-node-swarm-local-smoke-test)
section in the top-level README), then feed the printed token into a
joiner's `BACKUPSWARM_INVITE_TOKEN`.

## NAT / advertised address

When the node will issue invites and is behind NAT, set
`BACKUPSWARM_ADVERTISE_ADDR=<public-ip>:<host-port>` in the environment.
The daemon embeds that address in invite tokens instead of its bound
listener. See the top-level README's [NAT section](../README.md#nat--advertised-address)
for the details.
