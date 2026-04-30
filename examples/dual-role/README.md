# dual-role

A node that both backs up its own directory **and** stores chunks for
other swarm peers. The standard operator setup: every node contributes
storage and consumes redundancy.

## Role-specific flags

- `--backup-dir /backup` — directory tree the daemon keeps synced to the
  swarm.
- `--max-storage 100g` — cap on bytes stored for others. Tune to your
  disk. `unlimited` (the flag default) places no cap; `0` would disable
  storage and is wrong here — see `backup-source/` for that role.

## Bring up

```bash
mkdir -p ./backup
echo "your data here" > ./backup/notes.txt

export BACKUPSWARM_INVITE_TOKEN="<token issued by an existing swarm member>"
# Optional: NAT-routable advertise address if you'll issue invites later.
# export BACKUPSWARM_ADVERTISE_ADDR=203.0.113.7:7779

docker compose up -d
docker compose logs -f dual-role
```

## Build a swarm out of dual-role nodes

To stand up a brand-new swarm of N dual-role nodes:

1. Pick one node to be the founder. Run it once with `run --invite` to
   issue the bootstrap token (replace this compose's `BACKUPSWARM_INVITE_TOKEN`
   env var with `--invite` and `--token-out /data/token.txt` for the founder
   only).
2. Read the printed token (or `cat ./data/token.txt`).
3. On every other node, set `BACKUPSWARM_INVITE_TOKEN` to that token and
   `docker compose up -d`.
4. To add more nodes later, issue fresh tokens from any running daemon:
   `docker exec <container> backupswarm --data-dir /data invite`.
