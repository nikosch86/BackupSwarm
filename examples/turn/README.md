# turn

A `dual-role` daemon paired with a coturn sidecar so peers behind
symmetric NAT can still bootstrap. The daemon allocates a relay at
startup, embeds the TURN credentials in every issued invite token, and
joiners that find their direct + relay-direct rungs blocked fall through
to a joiner-side allocation against the same TURN server. Cross-
allocation forwarding then carries the QUIC handshake.

## When to use this

Pick this template when the host issuing invites is behind a
non-full-cone NAT (no port-forward, no UPnP). For full-cone or
port-forwarded inviters, the simpler `dual-role/` template is enough —
the bootstrap chain's `direct` rung wins and TURN never fires.

## Hard requirements

- A **publicly-routable IP** on the host running coturn. Carrier-grade
  NAT defeats this — coturn behind CGNAT only relays for peers that
  already share its private subnet, which is not the failure mode we're
  trying to fix. If `curl ifconfig.me` returns an address you cannot
  reach from the public internet, this template won't help you.
- The host's firewall must allow inbound UDP on port `3478` (TURN
  control) and the ephemeral relay range `49152-49200`. Adjust both
  ranges if the defaults clash; the `--min-port` / `--max-port` flags on
  coturn and the `ports:` mapping must agree.
- Outbound UDP on `:7777` for the daemon's own QUIC listener. The
  compose file maps it to the host with `0.0.0.0:7777/udp`.

`coturn` runs in `network_mode: host` so the relay-port range and the
control port are all visible to the public network without per-port
docker mappings (the relay range is large and dynamic).

## Bring up

```bash
mkdir -p ./backup
echo "your data here" > ./backup/notes.txt

export BACKUPSWARM_PUBLIC_IP=203.0.113.7
export BACKUPSWARM_TURN_USER=swarm
export BACKUPSWARM_TURN_PASS=$(openssl rand -base64 24)
export BACKUPSWARM_TURN_REALM=backupswarm.example.org
# When joining an existing swarm, set this to the issued token.
export BACKUPSWARM_INVITE_TOKEN="<token>"

docker compose up -d
docker compose logs -f dual-role
```

The daemon logs `nat: turn relay allocated relay_addr=<host:port>` on
startup; that's the relay address embedded in every token it issues.

## Bootstrap a brand-new swarm

Replace `BACKUPSWARM_INVITE_TOKEN` with `--invite` + `--token-out` on
the `dual-role` command for the founder run:

```yaml
command:
  - run
  - --invite
  - --token-out
  - /data/token.txt
  # ... rest unchanged ...
```

Bring up, read `./data/token.txt` (or the printed log line), feed that
token into joiners' `BACKUPSWARM_INVITE_TOKEN`, and switch the founder's
compose back to the standard form.

## What gets shared in the token

By default the daemon embeds `BACKUPSWARM_TURN_SERVER` /
`BACKUPSWARM_TURN_USER` / `BACKUPSWARM_TURN_PASS` /
`BACKUPSWARM_TURN_REALM` in every invite token it issues, so a NATted
joiner can allocate against the same coturn server without manual
configuration. Pass `--turn-cred-share=off` on the daemon `command:`
when minting per-joiner credentials out-of-band; joiners then override
via the four `BACKUPSWARM_TURN_*` env vars on the join side.

## Production hardening

The compose file uses long-term credentials over plain UDP for clarity.
For real deployments:

- Add `--use-auth-secret` and rotate the shared secret periodically;
  long-term creds in tokens grant indefinite TURN access until the
  secret rotates.
- Enable TLS / DTLS by removing `--no-tls` / `--no-dtls` and pointing at
  certificate files (mount them into the coturn container).
- Restrict the relay port range to only what the swarm's redundancy
  actually requires; `49152-49200` is fine for a handful of nodes but
  hundreds of peers need wider ranges and matching firewall rules.
- Run coturn on a dedicated host or in a separate failure domain — a
  single TURN outage takes out the cross-allocation path for every
  joiner that needs it.

## When this template is not enough

Cross-allocation forwarding requires both peers to allocate against the
**same** TURN server. If your swarm spans multiple TURN deployments
(per-region servers, mixed providers, etc.), this template doesn't
bridge them. A signaling sidecar that surfaces joiner IPs to inviters
ahead of time would be needed; that's not part of the daemon today.
