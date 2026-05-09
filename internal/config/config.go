// Package config layers a TOML config file, env vars, CLI flags, and built-in
// defaults into a single resolved daemon configuration. Precedence: CLI flag >
// env var > config file > default. Mode flags (--invite, --restore, --purge,
// --seed-file, --token-out) are not covered here; only daemon-config concerns.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Config carries every daemon-config setting that can be specified in a
// config file.
type Config struct {
	Storage Storage `mapstructure:"storage"`
	NAT     NAT     `mapstructure:"nat"`
	TURN    TURN    `mapstructure:"turn"`
	Metrics Metrics `mapstructure:"metrics"`
	Backup  Backup  `mapstructure:"backup"`
	Log     Log     `mapstructure:"log"`
}

type Storage struct {
	MaxStorage          string        `mapstructure:"max_storage"`
	Redundancy          int           `mapstructure:"redundancy"`
	ScanInterval        time.Duration `mapstructure:"scan_interval"`
	ScrubInterval       time.Duration `mapstructure:"scrub_interval"`
	IndexBackupInterval time.Duration `mapstructure:"index_backup_interval"`
	ChunkTTL            time.Duration `mapstructure:"chunk_ttl"`
	ChunkRenewInterval  time.Duration `mapstructure:"chunk_renew_interval"`
	ChunkExpireInterval time.Duration `mapstructure:"chunk_expire_interval"`
}

type NAT struct {
	STUNServer        string        `mapstructure:"stun_server"`
	PortMapping       string        `mapstructure:"port_mapping"`
	DialTimeout       time.Duration `mapstructure:"dial_timeout"`
	PunchTimeout      time.Duration `mapstructure:"punch_timeout"`
	TURNDialTimeout   time.Duration `mapstructure:"turn_dial_timeout"`
	RelayDialTimeout  time.Duration `mapstructure:"relay_dial_timeout"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
	HeartbeatMisses   int           `mapstructure:"heartbeat_misses"`
	GracePeriod       time.Duration `mapstructure:"grace_period"`
	BackoffBase       time.Duration `mapstructure:"backoff_base"`
	BackoffMax        time.Duration `mapstructure:"backoff_max"`
	BackoffJitter     bool          `mapstructure:"backoff_jitter"`
	UploadRate        string        `mapstructure:"upload_rate"`
	DownloadRate      string        `mapstructure:"download_rate"`
}

type TURN struct {
	Server    string `mapstructure:"server"`
	User      string `mapstructure:"user"`
	Pass      string `mapstructure:"pass"`
	Realm     string `mapstructure:"realm"`
	CredShare string `mapstructure:"cred_share"`
}

type Metrics struct {
	Addr          string        `mapstructure:"addr"`
	StatsInterval time.Duration `mapstructure:"stats_interval"`
}

type Backup struct {
	ChunkSize        int           `mapstructure:"chunk_size"`
	Include          []string      `mapstructure:"include"`
	Exclude          []string      `mapstructure:"exclude"`
	NoProgress       bool          `mapstructure:"no_progress"`
	ProgressInterval time.Duration `mapstructure:"progress_interval"`
}

type Log struct {
	Level string `mapstructure:"level"`
}

// Default returns the canonical default config. Cobra flag defaults must
// stay in sync with these values.
func Default() Config {
	return Config{
		Storage: Storage{
			MaxStorage:          "unlimited",
			Redundancy:          1,
			ScanInterval:        60 * time.Second,
			ScrubInterval:       6 * time.Hour,
			IndexBackupInterval: 5 * time.Minute,
			ChunkTTL:            30 * 24 * time.Hour,
			ChunkRenewInterval:  6 * 24 * time.Hour,
			ChunkExpireInterval: 1 * time.Hour,
		},
		NAT: NAT{
			STUNServer:        "stun.l.google.com:19302",
			PortMapping:       "auto",
			DialTimeout:       30 * time.Second,
			PunchTimeout:      5 * time.Second,
			TURNDialTimeout:   15 * time.Second,
			RelayDialTimeout:  15 * time.Second,
			HeartbeatInterval: 30 * time.Second,
			HeartbeatMisses:   3,
			GracePeriod:       24 * time.Hour,
			BackoffBase:       1 * time.Second,
			BackoffMax:        30 * time.Minute,
			BackoffJitter:     true,
			UploadRate:        "unlimited",
			DownloadRate:      "unlimited",
		},
		TURN: TURN{
			CredShare: "on",
		},
		Metrics: Metrics{
			StatsInterval: 2 * time.Minute,
		},
		Backup: Backup{
			ChunkSize:        1 << 20,
			Include:          []string{},
			Exclude:          []string{},
			ProgressInterval: 10 * time.Second,
		},
		Log: Log{
			Level: "info",
		},
	}
}

// flagBinding pairs a cobra flag name with its dotted config key.
type flagBinding struct {
	Key  string
	Flag string
}

// bindings is the canonical mapping from cobra flag names to dotted config
// keys. Listing both sides explicitly catches drift between schema and CLI.
var bindings = []flagBinding{
	{"storage.max_storage", "max-storage"},
	{"storage.redundancy", "redundancy"},
	{"storage.scan_interval", "scan-interval"},
	{"storage.scrub_interval", "scrub-interval"},
	{"storage.index_backup_interval", "index-backup-interval"},
	{"storage.chunk_ttl", "chunk-ttl"},
	{"storage.chunk_renew_interval", "chunk-renew-interval"},
	{"storage.chunk_expire_interval", "chunk-expire-interval"},
	{"nat.stun_server", "stun-server"},
	{"nat.port_mapping", "port-mapping"},
	{"nat.dial_timeout", "dial-timeout"},
	{"nat.punch_timeout", "punch-timeout"},
	{"nat.turn_dial_timeout", "turn-dial-timeout"},
	{"nat.relay_dial_timeout", "relay-dial-timeout"},
	{"nat.heartbeat_interval", "heartbeat-interval"},
	{"nat.heartbeat_misses", "heartbeat-misses"},
	{"nat.grace_period", "grace-period"},
	{"nat.backoff_base", "backoff-base"},
	{"nat.backoff_max", "backoff-max"},
	{"nat.backoff_jitter", "backoff-jitter"},
	{"nat.upload_rate", "upload-rate"},
	{"nat.download_rate", "download-rate"},
	{"turn.server", "turn-server"},
	{"turn.user", "turn-user"},
	{"turn.pass", "turn-pass"},
	{"turn.realm", "turn-realm"},
	{"turn.cred_share", "turn-cred-share"},
	{"metrics.addr", "metrics-addr"},
	{"metrics.stats_interval", "stats-interval"},
	{"backup.chunk_size", "chunk-size"},
	{"backup.include", "include"},
	{"backup.exclude", "exclude"},
	{"backup.no_progress", "no-progress"},
	{"backup.progress_interval", "progress-interval"},
	{"log.level", "log-level"},
}

// envAliases maps a dotted config key to a legacy env-var name kept alive
// for back-compat. The viper-derived name (BACKUPSWARM_<KEY>) is always
// honoured; aliases are fallbacks that take precedence over config + default
// but not over the canonical env name.
var envAliases = map[string]string{
	"nat.port_mapping": "BACKUPSWARM_PORT_MAPPING",
}

// UnknownKeyError reports a key in the config file that the schema does
// not recognise.
type UnknownKeyError struct {
	Key string
}

func (e UnknownKeyError) Error() string {
	return fmt.Sprintf("unknown config key %q", e.Key)
}

// BindingKeys returns the dotted config keys for every flag binding, in
// declaration order. Used by tests to assert binding-to-schema parity.
func BindingKeys() []string {
	out := make([]string, len(bindings))
	for i, b := range bindings {
		out[i] = b.Key
	}
	return out
}

// SchemaKeys returns the set of dotted keys defined by the Config struct's
// mapstructure tags.
func SchemaKeys() map[string]struct{} {
	out := map[string]struct{}{}
	collectKeys(reflect.TypeOf(Config{}), "", out)
	return out
}

func collectKeys(t reflect.Type, prefix string, out map[string]struct{}) {
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("mapstructure")
		if tag == "" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() != "time" {
			collectKeys(f.Type, key, out)
			continue
		}
		out[key] = struct{}{}
	}
}

// Resolve produces a Config respecting CLI > env > config > default
// precedence. configPath may be empty (no file layer) or point to a missing
// file (treated as no file layer).
func Resolve(cmd *cobra.Command, configPath string) (Config, error) {
	v := viper.New()
	v.SetEnvPrefix("BACKUPSWARM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v, Default())

	for _, b := range bindings {
		names := []string{strings.ToUpper("BACKUPSWARM_" + strings.ReplaceAll(b.Key, ".", "_"))}
		if alias, ok := envAliases[b.Key]; ok {
			names = append(names, alias)
		}
		if err := v.BindEnv(append([]string{b.Key}, names...)...); err != nil {
			return Config{}, fmt.Errorf("bind env %q: %w", b.Key, err)
		}
	}

	if err := readFile(v, configPath); err != nil {
		return Config{}, err
	}

	for _, b := range bindings {
		if !cmd.Flags().Changed(b.Flag) {
			continue
		}
		val, err := flagValue(cmd, b.Flag)
		if err != nil {
			return Config{}, err
		}
		v.Set(b.Key, val)
	}

	var cfg Config
	decodeOpt := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	))
	if err := v.Unmarshal(&cfg, decodeOpt); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}

func readFile(v *viper.Viper, configPath string) error {
	if configPath == "" {
		return nil
	}
	switch _, err := os.Stat(configPath); {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("stat config %s: %w", configPath, err)
	}
	v.SetConfigFile(configPath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config %s: %w", configPath, err)
	}
	return validateKeys(v)
}

// validateKeys errors if AllKeys contains any key not in SchemaKeys().
// AllKeys returns the union of defaults, env-bound, and config-file keys;
// since defaults and env-bound are always schema keys, any extra entry must
// have come from the config file.
func validateKeys(v *viper.Viper) error {
	schema := SchemaKeys()
	for _, key := range v.AllKeys() {
		if _, ok := schema[key]; ok {
			continue
		}
		head := strings.SplitN(key, ".", 2)[0]
		if _, ok := topLevelSections()[head]; !ok {
			return UnknownKeyError{Key: head}
		}
		return UnknownKeyError{Key: key}
	}
	return nil
}

func topLevelSections() map[string]struct{} {
	out := map[string]struct{}{}
	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("mapstructure"); tag != "" {
			out[tag] = struct{}{}
		}
	}
	return out
}

// setDefaults walks Default() and seeds each schema key with a typed value.
func setDefaults(v *viper.Viper, def Config) {
	var visit func(prefix string, val reflect.Value)
	visit = func(prefix string, val reflect.Value) {
		t := val.Type()
		for i := 0; i < val.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("mapstructure")
			if tag == "" {
				continue
			}
			key := tag
			if prefix != "" {
				key = prefix + "." + tag
			}
			fv := val.Field(i)
			if fv.Kind() == reflect.Struct && fv.Type().PkgPath() != "time" {
				visit(key, fv)
				continue
			}
			v.SetDefault(key, fv.Interface())
		}
	}
	visit("", reflect.ValueOf(def))
}

// flagValue extracts a typed Go value from a cobra flag. Going through the
// typed Get* helpers (rather than Value.String) preserves duration, int,
// bool, and []string semantics for v.Set.
func flagValue(cmd *cobra.Command, flag string) (any, error) {
	f := cmd.Flags().Lookup(flag)
	if f == nil {
		return nil, fmt.Errorf("flag %q not registered", flag)
	}
	switch f.Value.Type() {
	case "string":
		return cmd.Flags().GetString(flag)
	case "int":
		return cmd.Flags().GetInt(flag)
	case "int64":
		return cmd.Flags().GetInt64(flag)
	case "bool":
		return cmd.Flags().GetBool(flag)
	case "duration":
		return cmd.Flags().GetDuration(flag)
	case "stringSlice":
		return cmd.Flags().GetStringSlice(flag)
	default:
		return f.Value.String(), nil
	}
}
