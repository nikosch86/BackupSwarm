package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	"backupswarm/internal/backup"
	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	"backupswarm/internal/swarm"
)

// loadSwarmCAIfPresent returns the per-swarm CA when one exists at
// dir, or (nil, nil) when the swarm is in pubkey-pin mode.
func loadSwarmCAIfPresent(dir string) (*ca.CA, error) {
	has, err := ca.Has(dir)
	if err != nil {
		return nil, fmt.Errorf("check ca: %w", err)
	}
	if !has {
		return nil, nil
	}
	swarmCA, err := ca.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load ca: %w", err)
	}
	return swarmCA, nil
}

// makeJoinHandler returns the dispatcher's MsgJoinRequest handler.
// It opens invites.db, runs HandleJoinStream, then broadcasts
// PeerJoined to every conn in conns except the joiner.
func makeJoinHandler(dataDir string, peerStore *peers.Store, swarmCA *ca.CA, conns *swarm.ConnSet) backup.JoinHandler {
	return func(ctx context.Context, rw io.ReadWriter, joinerPub []byte) error {
		invStore, err := invites.Open(filepath.Join(dataDir, invites.DefaultFilename))
		if err != nil {
			return fmt.Errorf("open invites.db: %w", err)
		}
		defer func() { _ = invStore.Close() }()

		validator := bootstrap.SecretValidator(invStore.Consume)
		peer, joinErr := bootstrap.HandleJoinStream(ctx, rw, joinerPub, peerStore, validator, swarmCA)
		if joinErr != nil {
			return fmt.Errorf("handle join stream: %w", joinErr)
		}
		slog.InfoContext(ctx, "peer joined",
			"peer_pub", hex.EncodeToString(peer.PubKey),
			"peer_addr", peer.Addr,
		)
		if conns != nil {
			targets := conns.SnapshotExcept(peer.PubKey)
			if err := swarm.BroadcastPeerJoined(ctx, targets, peer); err != nil && !errors.Is(err, context.Canceled) {
				slog.WarnContext(ctx, "broadcast peer joined", "err", err)
			}
		}
		return nil
	}
}
