package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
	"backupswarm/internal/invites"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

func newInviteCmd(dataDir *string) *cobra.Command {
	var (
		listenAddr string
		timeout    time.Duration
		tokenOut   string
		thenRun    bool
		noCA       bool
	)
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Print an invite token and wait for one peer to join",
		Long: "Generate an invite token, open a QUIC listener, and block for " +
			"one incoming join handshake. The first invite on a fresh data dir " +
			"auto-generates the per-swarm Ed25519 CA and embeds its cert in the " +
			"token; --no-ca opts in to pubkey-pin trust and locks the swarm into " +
			"pin mode for life. With --then-run, transition into " +
			"the sync daemon (storage-peer role) after the handshake completes " +
			"so the same command can stand up a node end-to-end. --token-out " +
			"also writes the printed token to a file (atomic rename) for " +
			"orchestrated setups like docker-compose that share the token via " +
			"a volume.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if listenAddr == "" {
				return fmt.Errorf("--listen is required (the address peers will dial)")
			}
			sess, err := openPeerSession(*dataDir)
			if err != nil {
				return err
			}
			// Ownership of sess and listener is handed off to daemon.Run
			// when --then-run fires; these flags guard against double-close.
			sessHandedOff := false
			defer func() {
				if !sessHandedOff {
					_ = sess.Close()
				}
			}()

			// Bootstrap mode (nil VerifyPeer): AcceptJoin must admit a
			// joiner whose pubkey is not yet in peers.db. Once the
			// handshake completes and --then-run hands off to the
			// daemon, daemon.Run flips the listener to a membership
			// check against peers.db before starting Serve.
			listener, err := bsquic.Listen(listenAddr, sess.id.PrivateKey, nil, nil)
			if err != nil {
				return fmt.Errorf("listen on %q: %w", listenAddr, err)
			}
			listenerHandedOff := false
			defer func() {
				if !listenerHandedOff {
					_ = listener.Close()
				}
			}()

			invitesStore, err := invites.Open(filepath.Join(sess.dir, invites.DefaultFilename))
			if err != nil {
				return fmt.Errorf("open invites store: %w", err)
			}
			defer func() { _ = invitesStore.Close() }()

			swarmID, secret, err := newSessionIDs()
			if err != nil {
				return fmt.Errorf("generate session secret: %w", err)
			}
			if err := invitesStore.Issue(secret, swarmID); err != nil {
				return fmt.Errorf("issue invite: %w", err)
			}
			swarmCA, err := resolveInviteCA(cmd.Context(), sess.dir, noCA)
			if err != nil {
				return err
			}
			var caCertDER []byte
			if swarmCA != nil {
				caCertDER = swarmCA.CertDER
			}
			// Use the listener's actual bound addr so ":0" (ephemeral
			// port) still produces a usable token.
			tokStr, err := token.Encode(token.Token{
				Addr:    listener.Addr().String(),
				Pub:     sess.id.PublicKey,
				SwarmID: swarmID,
				Secret:  secret,
				CACert:  caCertDER,
			})
			if err != nil {
				return fmt.Errorf("encode token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tokStr)
			if tokenOut != "" {
				if err := writeTokenFile(tokenOut, tokStr); err != nil {
					return fmt.Errorf("write token file: %w", err)
				}
			}

			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			peer, err := bootstrap.AcceptJoin(ctx, listener, sess.peerStore, invitesStore.Consume, swarmCA)
			if err != nil {
				return fmt.Errorf("accept join: %w", err)
			}
			slog.InfoContext(ctx, "peer joined",
				"peer_pub", hex.EncodeToString(peer.PubKey),
				"peer_addr", peer.Addr,
			)

			if !thenRun {
				return nil
			}
			// Hand off listener + peer store to the daemon, which runs
			// in storage-peer-only mode (no BackupDir). daemon.Run owns
			// closing both on exit.
			listenerHandedOff = true
			sessHandedOff = true
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:   sess.dir,
				Listener:  listener,
				PeerStore: sess.peerStore,
				Progress:  cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Address to listen on (host:port)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum time to wait for a joiner (0 = no timeout)")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the printed token to this file (atomic)")
	cmd.Flags().BoolVar(&thenRun, "then-run", false, "After the handshake, transition into the sync daemon (storage-peer role)")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip swarm CA generation; use pubkey-pin trust. Locks the swarm into pin mode for life.")
	return cmd
}

// resolveInviteCA returns the swarm CA used to sign joiner CSRs and embed
// in invite tokens. First invite generates+saves a CA, or writes a pin
// marker with --no-ca; subsequent invites honor the locked-in mode.
func resolveInviteCA(ctx context.Context, dir string, noCA bool) (*ca.CA, error) {
	hasCA, err := ca.Has(dir)
	if err != nil {
		return nil, fmt.Errorf("check ca: %w", err)
	}
	pinMode, err := ca.IsPinMode(dir)
	if err != nil {
		return nil, fmt.Errorf("check pin mode: %w", err)
	}
	if noCA {
		if hasCA {
			return nil, fmt.Errorf("invite: swarm at %s is in CA mode; --no-ca is incompatible", dir)
		}
		if !pinMode {
			if err := ca.MarkPinMode(dir); err != nil {
				return nil, fmt.Errorf("mark pin mode: %w", err)
			}
		}
		return nil, nil
	}
	if hasCA {
		swarmCA, err := ca.Load(dir)
		if err != nil {
			return nil, fmt.Errorf("load ca: %w", err)
		}
		return swarmCA, nil
	}
	if pinMode {
		return nil, nil
	}
	swarmCA, err := ca.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate ca: %w", err)
	}
	if err := ca.Save(dir, swarmCA); err != nil {
		return nil, fmt.Errorf("save ca: %w", err)
	}
	slog.InfoContext(ctx, "generated swarm ca", "data_dir", dir)
	return swarmCA, nil
}

// newSessionIDs generates the per-invite swarm ID and single-use secret.
func newSessionIDs() (swarmID, secret [32]byte, err error) {
	if _, err = rand.Read(swarmID[:]); err != nil {
		return swarmID, secret, fmt.Errorf("read swarm id: %w", err)
	}
	if _, err = rand.Read(secret[:]); err != nil {
		return swarmID, secret, fmt.Errorf("read secret: %w", err)
	}
	return swarmID, secret, nil
}

// tokenTempFile narrows the surface writeTokenFile needs from a
// temp-file handle, so the white-box test can swap in a fake whose
// Write/Close leg fails — following the same seam pattern internal/store
// uses for its atomic Put.
type tokenTempFile interface {
	WriteString(string) (int, error)
	Close() error
	Name() string
}

// createTokenTempFunc is the seam that lets tests inject a tokenTempFile
// whose methods fail. Production never reassigns it.
var createTokenTempFunc = func(dir, pattern string) (tokenTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// writeTokenFile writes tok+newline to path via a same-directory temp
// file + rename, so concurrent readers never observe a partially-written
// token. Used by --token-out.
func writeTokenFile(path, tok string) error {
	dir := filepath.Dir(path)
	tmp, err := createTokenTempFunc(dir, ".token-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	committed = true
	return nil
}
