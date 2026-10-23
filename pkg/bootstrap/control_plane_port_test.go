// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package bootstrap

import (
	"errors"
	"slices"
	"testing"
)

func TestEffectiveControlPlanePort(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		cfg  *BootstrapConfig
		want int
	}{
		"nil config uses the default": {cfg: nil, want: DefaultControlPlanePort},
		"unset uses the default":      {cfg: &BootstrapConfig{}, want: DefaultControlPlanePort},
		"configured port wins": {
			cfg:  &BootstrapConfig{Platform: PlatformGlobalConfig{ControlPlanePort: 9000}},
			want: 9000,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tc.cfg.EffectiveControlPlanePort(); got != tc.want {
				t.Errorf("EffectiveControlPlanePort = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHealthProbePorts(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		port int
		want []int
	}{
		"default":                      {port: 0, want: []int{8443, 9443, 443}},
		"custom port leads":            {port: 9000, want: []int{9000, 9443, 443}},
		"node port is not repeated":    {port: 9443, want: []int{9443, 443}},
		"gateway port is not repeated": {port: 443, want: []int{443, 9443}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := &BootstrapConfig{Platform: PlatformGlobalConfig{ControlPlanePort: tc.port}}
			if got := cfg.HealthProbePorts(); !slices.Equal(got, tc.want) {
				t.Errorf("HealthProbePorts = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBootstrapConfig_Validate_ControlPlanePort(t *testing.T) {
	t.Parallel()

	invalidPorts := map[string]int{
		"negative":     -1,
		"out of range": maxPort + 1,
	}
	for name, port := range invalidPorts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := minimalConfig()
			cfg.Platform.ControlPlanePort = port

			var invalid ErrInvalidPort
			if err := cfg.Validate(); !errors.As(err, &invalid) {
				t.Fatalf("port %d: Validate = %v, want ErrInvalidPort", port, err)
			}
			if invalid.Field != "platform.control_plane_port" || invalid.Port != port {
				t.Errorf("port %d: error must name the field and value, got %+v", port, invalid)
			}
		})
	}

	t.Run("valid port is accepted", func(t *testing.T) {
		t.Parallel()
		cfg := minimalConfig()
		cfg.Platform.ControlPlanePort = 9000
		if err := cfg.Validate(); err != nil {
			t.Fatalf("a valid control-plane port must be accepted: %v", err)
		}
	})
}

func TestOrchestrator_ControlPlanePort(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		configure func(o *Orchestrator)
		want      string
	}{
		"unset uses the default": {configure: func(*Orchestrator) {}, want: "8443"},
		"configured port wins": {
			configure: func(o *Orchestrator) { o.config.Platform.ControlPlanePort = 9000 },
			want:      "9000",
		},
		"no config uses the default": {configure: func(o *Orchestrator) { o.config = nil }, want: "8443"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := newTrustTestOrchestrator()
			tc.configure(o)
			if got := o.controlPlanePort(); got != tc.want {
				t.Errorf("controlPlanePort = %q, want %q", got, tc.want)
			}
		})
	}
}
