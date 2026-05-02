# storage-peer

A node that serves chunks for swarm peers and backs up nothing of its
own. Use this on hardware you want to donate to a swarm: storage and
bandwidth, no local data of its own to protect.

## Role-specific flags

- `--max-storage 100g` — cap on bytes stored for others. Tune to your
  disk. `unlimited` (the flag default) places no cap. `0` would refuse
  every chunk and is the wrong setting here — see `backup-source/` for
  that role.
- No `--backup-dir` — the daemon runs in pure storage-peer mode.

## Bring up

```bash
export BACKUPSWARM_INVITE_TOKEN="<token issued by an existing swarm member>"
# Optional: NAT-routable advertise address (host:port) if you'll issue
# invites from this node later. Otherwise omit.
# export BACKUPSWARM_ADVERTISE_ADDR=203.0.113.7:7777

docker compose up -d
docker compose logs -f storage-peer
```

After the first start, the env var is no longer needed; the daemon
remembers the swarm via `peers.db` in the named `data` volume.

## Issue an invite token

To get a token from an existing swarm member's running daemon:

```bash
docker exec <existing-container> backupswarm invite
```

The image presets `BACKUPSWARM_DATA_DIR=/data`, so `--data-dir` is
already wired to the named volume.

Or bootstrap a brand-new swarm with `run --invite` once on a founder
node, then copy that token here.
