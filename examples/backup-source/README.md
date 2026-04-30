# backup-source

A node that ships its own directory to the swarm but stores nothing for
other peers. Use this when you need backup off-site but cannot or do not
want to donate storage in return — e.g., a low-disk laptop, a cheap
ingress VM, or a node behind a metered link.

## Role-specific flags

- `--backup-dir /backup` — directory tree the daemon keeps synced to the
  swarm. Mount your data here.
- `--max-storage 0` — switches the daemon to **no-storage mode**. Every
  incoming `PutChunk` is rejected; the capacity probe reports a saturated
  state so other peers exclude this node from chunk placement entirely.
  This is the explicit "I will not donate storage" knob.

If you want a finite cap rather than zero storage, use a positive value
like `--max-storage 10g`. Omit the flag (or pass `unlimited`) to place
no cap. See `storage-peer/` and `dual-role/` for those modes.

## Bring up

```bash
mkdir -p ./backup
echo "your data here" > ./backup/notes.txt

export BACKUPSWARM_INVITE_TOKEN="<token issued by a storage-capable swarm member>"
# Optional: NAT-routable advertise address if you'll issue invites later.
# export BACKUPSWARM_ADVERTISE_ADDR=203.0.113.7:7778

docker compose up -d
docker compose logs -f backup-source
```

The daemon scans `/backup` on the configured `--scan-interval` (default
60s), encrypts new/changed files, and ships them to live storage peers
in `peers.db`. With `--redundancy 1` (default) each chunk lands on one
peer; bump it for more copies.

## Restore

To restore the contents of `/backup` from the swarm onto a fresh node:

```bash
docker compose down
rm -rf ./backup/*    # or run on a new host with an empty mount
docker compose run --rm backup-source run --backup-dir /backup --restore --listen 0.0.0.0:7778
```

See the top-level README "Restore" section for the disaster-recovery
flow that also rebuilds a lost index from the swarm.
