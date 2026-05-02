package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRunCmd_TURNServerRequiresCredentials asserts --turn-server demands the
// matching --turn-user / --turn-pass / --turn-realm triple.
func TestRunCmd_TURNServerRequiresCredentials(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing user", []string{"--turn-server", "turn.example:3478", "--turn-pass", "p", "--turn-realm", "r"}},
		{"missing pass", []string{"--turn-server", "turn.example:3478", "--turn-user", "u", "--turn-realm", "r"}},
		{"missing realm", []string{"--turn-server", "turn.example:3478", "--turn-user", "u", "--turn-pass", "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := NewRootCmd()
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			args := append([]string{"--data-dir", t.TempDir(), "run", "--listen", "127.0.0.1:0"}, tc.args...)
			root.SetArgs(args)
			err := root.ExecuteContext(context.Background())
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), "--turn-server requires") {
				t.Errorf("err = %v, want mention of --turn-server requires", err)
			}
		})
	}
}
