package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/config"

	"github.com/spf13/cobra"
)

func newTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	defaults := config.Default()
	cmd.Flags().String("max-storage", defaults.Storage.MaxStorage, "")
	cmd.Flags().Int("redundancy", defaults.Storage.Redundancy, "")
	cmd.Flags().Duration("scan-interval", defaults.Storage.ScanInterval, "")
	cmd.Flags().Duration("scrub-interval", defaults.Storage.ScrubInterval, "")
	cmd.Flags().Duration("index-backup-interval", defaults.Storage.IndexBackupInterval, "")
	cmd.Flags().Duration("chunk-ttl", defaults.Storage.ChunkTTL, "")
	cmd.Flags().Duration("chunk-renew-interval", defaults.Storage.ChunkRenewInterval, "")
	cmd.Flags().Duration("chunk-expire-interval", defaults.Storage.ChunkExpireInterval, "")
	cmd.Flags().String("stun-server", defaults.NAT.STUNServer, "")
	cmd.Flags().String("port-mapping", defaults.NAT.PortMapping, "")
	cmd.Flags().Duration("dial-timeout", defaults.NAT.DialTimeout, "")
	cmd.Flags().Duration("punch-timeout", defaults.NAT.PunchTimeout, "")
	cmd.Flags().Duration("turn-dial-timeout", defaults.NAT.TURNDialTimeout, "")
	cmd.Flags().Duration("relay-dial-timeout", defaults.NAT.RelayDialTimeout, "")
	cmd.Flags().Duration("heartbeat-interval", defaults.NAT.HeartbeatInterval, "")
	cmd.Flags().Int("heartbeat-misses", defaults.NAT.HeartbeatMisses, "")
	cmd.Flags().Duration("grace-period", defaults.NAT.GracePeriod, "")
	cmd.Flags().Duration("backoff-base", defaults.NAT.BackoffBase, "")
	cmd.Flags().Duration("backoff-max", defaults.NAT.BackoffMax, "")
	cmd.Flags().Bool("backoff-jitter", defaults.NAT.BackoffJitter, "")
	cmd.Flags().String("upload-rate", defaults.NAT.UploadRate, "")
	cmd.Flags().String("download-rate", defaults.NAT.DownloadRate, "")
	cmd.Flags().String("turn-server", defaults.TURN.Server, "")
	cmd.Flags().String("turn-user", defaults.TURN.User, "")
	cmd.Flags().String("turn-pass", defaults.TURN.Pass, "")
	cmd.Flags().String("turn-realm", defaults.TURN.Realm, "")
	cmd.Flags().String("turn-cred-share", defaults.TURN.CredShare, "")
	cmd.Flags().String("metrics-addr", defaults.Metrics.Addr, "")
	cmd.Flags().Duration("stats-interval", defaults.Metrics.StatsInterval, "")
	cmd.Flags().Int("chunk-size", defaults.Backup.ChunkSize, "")
	cmd.Flags().StringSlice("include", defaults.Backup.Include, "")
	cmd.Flags().StringSlice("exclude", defaults.Backup.Exclude, "")
	cmd.Flags().Bool("no-progress", defaults.Backup.NoProgress, "")
	cmd.Flags().Duration("progress-interval", defaults.Backup.ProgressInterval, "")
	cmd.Flags().String("log-level", defaults.Log.Level, "")
	return cmd
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefault_HasExpectedValues(t *testing.T) {
	t.Parallel()
	def := config.Default()
	if def.Storage.MaxStorage != "unlimited" {
		t.Errorf("MaxStorage default = %q, want unlimited", def.Storage.MaxStorage)
	}
	if def.Storage.Redundancy != 1 {
		t.Errorf("Redundancy default = %d, want 1", def.Storage.Redundancy)
	}
	if def.NAT.PortMapping != "auto" {
		t.Errorf("PortMapping default = %q, want auto", def.NAT.PortMapping)
	}
	if def.TURN.CredShare != "on" {
		t.Errorf("CredShare default = %q, want on", def.TURN.CredShare)
	}
	if def.Log.Level != "info" {
		t.Errorf("Log.Level default = %q, want info", def.Log.Level)
	}
	if def.Metrics.StatsInterval != 2*time.Minute {
		t.Errorf("StatsInterval default = %v, want 2m", def.Metrics.StatsInterval)
	}
}

func TestResolve_NoFile_NoFlags_ReturnsDefaults(t *testing.T) {
	t.Parallel()
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(cfg, config.Default()) {
		t.Fatalf("cfg = %+v\nwant %+v", cfg, config.Default())
	}
}

func TestResolve_MissingFile_NotFatal(t *testing.T) {
	t.Parallel()
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil {
		t.Fatalf("Resolve missing: %v", err)
	}
	if cfg.Storage.Redundancy != 1 {
		t.Fatalf("expected default redundancy, got %d", cfg.Storage.Redundancy)
	}
}

func TestResolve_FileOverridesDefault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `
[storage]
redundancy = 5
max_storage = "10g"
scrub_interval = "1h"

[nat]
upload_rate = "5m"

[turn]
server = "turn.example:3478"
user = "alice"
pass = "secret"
realm = "swarm"

[metrics]
addr = ":9091"
stats_interval = "30s"

[backup]
exclude = ["*.tmp", "**/cache"]

[log]
level = "debug"
`
	path := writeFile(t, dir, "config.toml", body)
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Storage.Redundancy != 5 {
		t.Errorf("Redundancy = %d, want 5", cfg.Storage.Redundancy)
	}
	if cfg.Storage.MaxStorage != "10g" {
		t.Errorf("MaxStorage = %q, want 10g", cfg.Storage.MaxStorage)
	}
	if cfg.Storage.ScrubInterval != time.Hour {
		t.Errorf("ScrubInterval = %v, want 1h", cfg.Storage.ScrubInterval)
	}
	if cfg.NAT.UploadRate != "5m" {
		t.Errorf("UploadRate = %q, want 5m", cfg.NAT.UploadRate)
	}
	if cfg.TURN.Server != "turn.example:3478" {
		t.Errorf("TURN.Server = %q", cfg.TURN.Server)
	}
	if cfg.TURN.User != "alice" || cfg.TURN.Pass != "secret" || cfg.TURN.Realm != "swarm" {
		t.Errorf("TURN creds = %+v", cfg.TURN)
	}
	if cfg.Metrics.Addr != ":9091" {
		t.Errorf("Metrics.Addr = %q", cfg.Metrics.Addr)
	}
	if cfg.Metrics.StatsInterval != 30*time.Second {
		t.Errorf("StatsInterval = %v", cfg.Metrics.StatsInterval)
	}
	wantExclude := []string{"*.tmp", "**/cache"}
	if len(cfg.Backup.Exclude) != 2 || cfg.Backup.Exclude[0] != wantExclude[0] || cfg.Backup.Exclude[1] != wantExclude[1] {
		t.Errorf("Backup.Exclude = %v, want %v", cfg.Backup.Exclude, wantExclude)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
}

func TestResolve_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	body := `
[storage]
redundancy = 3
[log]
level = "warn"
`
	path := writeFile(t, dir, "config.toml", body)
	t.Setenv("BACKUPSWARM_STORAGE_REDUNDANCY", "7")
	t.Setenv("BACKUPSWARM_LOG_LEVEL", "error")
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Storage.Redundancy != 7 {
		t.Errorf("Redundancy = %d, want 7 (env)", cfg.Storage.Redundancy)
	}
	if cfg.Log.Level != "error" {
		t.Errorf("Log.Level = %q, want error (env)", cfg.Log.Level)
	}
}

func TestResolve_LegacyPortMappingAlias(t *testing.T) {
	t.Setenv("BACKUPSWARM_PORT_MAPPING", "off")
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.NAT.PortMapping != "off" {
		t.Fatalf("PortMapping = %q, want off (legacy env alias)", cfg.NAT.PortMapping)
	}
}

func TestResolve_FlagOverridesEnv(t *testing.T) {
	dir := t.TempDir()
	body := `
[storage]
redundancy = 3
`
	path := writeFile(t, dir, "config.toml", body)
	t.Setenv("BACKUPSWARM_STORAGE_REDUNDANCY", "7")
	cmd := newTestCmd(t)
	if err := cmd.Flags().Set("redundancy", "9"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	cfg, err := config.Resolve(cmd, path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Storage.Redundancy != 9 {
		t.Errorf("Redundancy = %d, want 9 (flag)", cfg.Storage.Redundancy)
	}
}

func TestResolve_FlagOverlay_TypedValues(t *testing.T) {
	t.Parallel()
	cmd := newTestCmd(t)
	if err := cmd.Flags().Set("scan-interval", "5s"); err != nil {
		t.Fatalf("set duration: %v", err)
	}
	if err := cmd.Flags().Set("backoff-jitter", "false"); err != nil {
		t.Fatalf("set bool: %v", err)
	}
	if err := cmd.Flags().Set("exclude", "*.tmp"); err != nil {
		t.Fatalf("set stringSlice: %v", err)
	}
	if err := cmd.Flags().Set("exclude", "foo.bin"); err != nil {
		t.Fatalf("set stringSlice 2: %v", err)
	}
	if err := cmd.Flags().Set("max-storage", "8g"); err != nil {
		t.Fatalf("set string: %v", err)
	}
	cfg, err := config.Resolve(cmd, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Storage.ScanInterval != 5*time.Second {
		t.Errorf("ScanInterval = %v, want 5s", cfg.Storage.ScanInterval)
	}
	if cfg.NAT.BackoffJitter {
		t.Errorf("BackoffJitter = true, want false")
	}
	if len(cfg.Backup.Exclude) != 2 || cfg.Backup.Exclude[0] != "*.tmp" || cfg.Backup.Exclude[1] != "foo.bin" {
		t.Errorf("Backup.Exclude = %v, want [*.tmp foo.bin]", cfg.Backup.Exclude)
	}
	if cfg.Storage.MaxStorage != "8g" {
		t.Errorf("MaxStorage = %q, want 8g", cfg.Storage.MaxStorage)
	}
}

func TestUnknownKeyError_Format(t *testing.T) {
	t.Parallel()
	got := config.UnknownKeyError{Key: "storage.bogus"}.Error()
	if !strings.Contains(got, "storage.bogus") {
		t.Errorf("Error() = %q, want substring storage.bogus", got)
	}
}

func TestResolve_FlagDefault_DoesNotOverrideEnv(t *testing.T) {
	t.Setenv("BACKUPSWARM_STORAGE_REDUNDANCY", "11")
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Storage.Redundancy != 11 {
		t.Errorf("Redundancy = %d, want 11 (env, since flag wasn't changed)", cfg.Storage.Redundancy)
	}
}

func TestResolve_UnknownKey_ErrorNamesKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `
[storage]
bogus = 5
`
	path := writeFile(t, dir, "config.toml", body)
	cmd := newTestCmd(t)
	_, err := config.Resolve(cmd, path)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	var unk config.UnknownKeyError
	if !errors.As(err, &unk) {
		t.Fatalf("err type = %T, want UnknownKeyError; err=%v", err, err)
	}
	if !strings.Contains(unk.Key, "storage.bogus") {
		t.Errorf("error names key %q, want substring storage.bogus", unk.Key)
	}
}

func TestResolve_UnknownTopLevelSection_ErrorNamesKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `
[bogus_section]
foo = "bar"
`
	path := writeFile(t, dir, "config.toml", body)
	cmd := newTestCmd(t)
	_, err := config.Resolve(cmd, path)
	if err == nil {
		t.Fatal("expected error for unknown section")
	}
	var unk config.UnknownKeyError
	if !errors.As(err, &unk) {
		t.Fatalf("err type = %T, want UnknownKeyError", err)
	}
	if !strings.Contains(unk.Key, "bogus_section") {
		t.Errorf("error names key %q, want substring bogus_section", unk.Key)
	}
}

func TestResolve_MalformedTOML_ErrorIncludesLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "[storage]\nredundancy = \"unterminated\nthis is broken"
	path := writeFile(t, dir, "config.toml", body)
	cmd := newTestCmd(t)
	_, err := config.Resolve(cmd, path)
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
	if !strings.Contains(err.Error(), "row") && !strings.Contains(err.Error(), "line") && !strings.Contains(err.Error(), "(2,") && !strings.Contains(err.Error(), "2:") {
		t.Errorf("error %q does not include a line/row reference", err.Error())
	}
}

func TestBindings_MatchSchema(t *testing.T) {
	t.Parallel()
	schema := config.SchemaKeys()
	for _, key := range config.BindingKeys() {
		if _, ok := schema[key]; !ok {
			t.Errorf("binding key %q not in schema", key)
		}
	}
}

func TestResolve_AllSchemaKeysCovered(t *testing.T) {
	t.Parallel()
	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	keys := config.SchemaKeys()
	if len(keys) < 20 {
		t.Errorf("SchemaKeys returned %d keys, want at least 20 to cover daemon-config surface", len(keys))
	}
	for _, key := range []string{
		"storage.redundancy",
		"storage.max_storage",
		"storage.scrub_interval",
		"storage.index_backup_interval",
		"nat.stun_server",
		"nat.upload_rate",
		"nat.port_mapping",
		"turn.server",
		"turn.cred_share",
		"metrics.addr",
		"metrics.stats_interval",
		"backup.exclude",
		"backup.chunk_size",
		"log.level",
	} {
		if _, ok := keys[key]; !ok {
			t.Errorf("schema missing key %q", key)
		}
	}
	_ = cfg
}
