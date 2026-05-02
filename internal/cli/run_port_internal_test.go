package cli

import "testing"

// TestResolveListenAdvertise covers the full listen/advertise resolution
// matrix: bare host, host:port back-compat, the auto sentinel, and the
// listen-empty advertise-port-derives-listen fallback.
func TestResolveListenAdvertise(t *testing.T) {
	cases := []struct {
		name            string
		listenIn        string
		advertiseIn     string
		port            int
		wantListen      string
		wantAdvertise   string
		wantErrContains string
	}{
		{
			name:          "defaults to 0.0.0.0:7777",
			port:          7777,
			wantListen:    "0.0.0.0:7777",
			wantAdvertise: "",
		},
		{
			name:          "port flag selects listen port",
			port:          7779,
			wantListen:    "0.0.0.0:7779",
			wantAdvertise: "",
		},
		{
			name:          "listen host-only combined with port",
			listenIn:      "127.0.0.1",
			port:          7777,
			wantListen:    "127.0.0.1:7777",
			wantAdvertise: "",
		},
		{
			name:          "listen host:port accepted as-is",
			listenIn:      "127.0.0.1:0",
			port:          7777,
			wantListen:    "127.0.0.1:0",
			wantAdvertise: "",
		},
		{
			name:          "advertise host-only combined with port",
			advertiseIn:   "example.com",
			port:          7779,
			wantListen:    "0.0.0.0:7779",
			wantAdvertise: "example.com:7779",
		},
		{
			name:          "advertise host:port accepted as-is",
			advertiseIn:   "example.com:9999",
			port:          7777,
			wantListen:    "0.0.0.0:9999",
			wantAdvertise: "example.com:9999",
		},
		{
			name:          "advertise port wins when listen empty",
			advertiseIn:   "example.com:9999",
			port:          7777,
			wantListen:    "0.0.0.0:9999",
			wantAdvertise: "example.com:9999",
		},
		{
			name:          "explicit listen overrides advertise port",
			listenIn:      "127.0.0.1:5555",
			advertiseIn:   "example.com:9999",
			port:          7777,
			wantListen:    "127.0.0.1:5555",
			wantAdvertise: "example.com:9999",
		},
		{
			name:          "auto passes through unchanged",
			advertiseIn:   advertiseAddrAuto,
			port:          7777,
			wantListen:    "0.0.0.0:7777",
			wantAdvertise: advertiseAddrAuto,
		},
		{
			name:          "ipv6 host-only combined with port",
			listenIn:      "::1",
			port:          7777,
			wantListen:    "[::1]:7777",
			wantAdvertise: "",
		},
		{
			name:          "ipv6 bracketed host:port accepted as-is",
			listenIn:      "[::1]:7778",
			port:          7777,
			wantListen:    "[::1]:7778",
			wantAdvertise: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotListen, gotAdv, err := resolveListenAdvertise(tc.listenIn, tc.advertiseIn, tc.port)
			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (listen=%q adv=%q)", tc.wantErrContains, gotListen, gotAdv)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if gotListen != tc.wantListen {
				t.Errorf("listen = %q, want %q", gotListen, tc.wantListen)
			}
			if gotAdv != tc.wantAdvertise {
				t.Errorf("advertise = %q, want %q", gotAdv, tc.wantAdvertise)
			}
		})
	}
}
