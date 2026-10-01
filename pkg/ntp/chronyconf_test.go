// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ntp

import (
	"errors"
	"strings"
	"testing"
)

// requireLines asserts every wanted line appears in the rendered config.
func requireLines(t *testing.T, rendered string, want ...string) {
	t.Helper()
	for _, line := range want {
		if !strings.Contains(rendered, line) {
			t.Fatalf("rendered config missing %q:\n%s", line, rendered)
		}
	}
}

// requireNoLines asserts none of the forbidden lines appear.
func requireNoLines(t *testing.T, rendered string, forbidden ...string) {
	t.Helper()
	for _, line := range forbidden {
		if strings.Contains(rendered, line) {
			t.Fatalf("rendered config unexpectedly contains %q:\n%s", line, rendered)
		}
	}
}

func TestRenderControlPlaneEmitsServerAndClientDirectives(t *testing.T) {
	rendered, err := Render(controlPlaneConfig(), DefaultPaths())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	requireLines(t, rendered,
		ManagedHeader,
		"# mode: both",
		"server 10.4.200.1 iburst prefer",
		"pool pool.ntp.org iburst",
		"driftfile /var/lib/chrony/chrony.drift",
		"makestep 1.0 3",
		"rtcsync",
		"allow 10.4.200.0/24",
		"allow 192.0.2.0/24",
		"local stratum 10",
		"ntsservercert /etc/chrony/nts.d/current/nts-server.crt",
		"ntsserverkey /etc/chrony/nts.d/current/nts-server.key",
		"ntsdumpdir /var/lib/chrony",
		"bindcmdaddress /run/chrony/chronyd.sock",
		"cmdport 0",
	)
	// A serving node must not disable the NTP port, and must never open
	// the allow-list.
	requireNoLines(t, rendered, "\nport 0", "allow 0.0.0.0/0", "allow ::/0")
}

func TestRenderConsumerDisablesTheServerPort(t *testing.T) {
	rendered, err := Render(consumerConfig(), DefaultPaths())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	requireLines(t, rendered,
		"# mode: consume",
		"server 10.4.200.10 iburst prefer nts",
		"port 0",
		"cmdport 0",
	)
	requireNoLines(t, rendered, "allow ", "local stratum", "ntsservercert")
}

func TestRenderOmitsRTCSyncAndOrphanWhenDisabled(t *testing.T) {
	cfg := controlPlaneConfig()
	cfg.RTC = &RTCConfig{WriteBack: false}
	cfg.Consume.OrphanFallback = false
	cfg.Serve.NTS.Enabled = false

	rendered, err := Render(cfg, DefaultPaths())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	requireNoLines(t, rendered, "rtcsync", "local stratum", "ntsservercert")
	requireLines(t, rendered, "allow 10.4.200.0/24")
}

func TestRenderHonorsCustomPaths(t *testing.T) {
	paths := Paths{
		ConfigFile:     "/tmp/chrony.conf",
		DriftFile:      "/tmp/drift",
		NTSMaterialDir: "/tmp/nts.d",
		NTSDumpDir:     "/tmp/nts",
		CommandSocket:  "/tmp/chronyd.sock",
	}

	rendered, err := Render(controlPlaneConfig(), paths)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	requireLines(t, rendered,
		"driftfile /tmp/drift",
		"ntsservercert /tmp/nts.d/current/nts-server.crt",
		"ntsserverkey /tmp/nts.d/current/nts-server.key",
		"ntsdumpdir /tmp/nts",
		"bindcmdaddress /tmp/chronyd.sock",
	)
}

func TestRenderRejectsInvalidConfigurations(t *testing.T) {
	cases := map[string]struct {
		config *Config
		want   error
	}{
		"nil config":       {config: nil, want: ErrNilConfig{}},
		"disabled section": {config: &Config{Enabled: false}, want: ErrDisabled{}},
		"open allow-list": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"0.0.0.0/0"},
			}},
			want: ErrUnrestrictedListenNetwork{Network: "0.0.0.0/0"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rendered, err := Render(tc.config, DefaultPaths())
			if err == nil {
				t.Fatalf("Render() = %q, want error", rendered)
			}
			var renderErr ErrRenderFailed
			if !errors.As(err, &renderErr) {
				t.Fatalf("Render() error = %v, want ErrRenderFailed", err)
			}
			if renderErr.Unwrap().Error() != tc.want.Error() {
				t.Fatalf("cause = %q, want %q", renderErr.Unwrap().Error(), tc.want.Error())
			}
		})
	}
}
