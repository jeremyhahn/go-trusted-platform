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

package bootstrap

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// observedFirstbootCycle is the measured install-exit -> healthy interval from
// #134 run 9 on lab-node-1 (12:19:29Z installer exit, ~12:35:00Z /api/v1/status
// answering 200). The post-install health window must exceed it with margin,
// because a node that is merely SLOW must not fail the run — in run 9 that
// failure also cancelled the remaining-nodes phase and stranded lab-node-5.
const observedFirstbootCycle = 15*time.Minute + 30*time.Second

func TestPostInstallHealthTimeoutCoversObservedFirstbootCycle(t *testing.T) {
	if defaultPostInstallHealthTimeout <= observedFirstbootCycle {
		t.Fatalf("defaultPostInstallHealthTimeout = %v, which does not exceed the measured firstboot cycle %v (#134). "+
			"The window must cover install-reboot -> firstboot seal -> auto-provision -> ACME -> restart, not just boot time.",
			defaultPostInstallHealthTimeout, observedFirstbootCycle)
	}
	// Demand real margin, not a value tuned to sit just above the one
	// observation we have. Hardware slower than lab-node-1 must still pass.
	const wantMargin = 5 * time.Minute
	if got := defaultPostInstallHealthTimeout - observedFirstbootCycle; got < wantMargin {
		t.Errorf("margin over the observed cycle is %v, want at least %v: one measurement is not the worst case", got, wantMargin)
	}
}

func TestEffectivePostInstallHealthTimeout(t *testing.T) {
	tests := []struct {
		name string
		cfg  *BootstrapConfig
		want time.Duration
	}{
		{"nil config falls back", nil, defaultPostInstallHealthTimeout},
		{"unset falls back", &BootstrapConfig{}, defaultPostInstallHealthTimeout},
		// A zero or negative value means the key was omitted or mistyped.
		// Honouring it literally would give every node a zero-length window
		// and fail the run instantly, which is the opposite of the intent.
		{"negative is treated as unset", &BootstrapConfig{
			Platform: PlatformGlobalConfig{HealthTimeout: -1 * time.Minute}}, defaultPostInstallHealthTimeout},
		{"configured value wins", &BootstrapConfig{
			Platform: PlatformGlobalConfig{HealthTimeout: 40 * time.Minute}}, 40 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EffectivePostInstallHealthTimeout(); got != tt.want {
				t.Errorf("EffectivePostInstallHealthTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHealthTimeoutYAMLParseRule pins what the documentation promises about
// this key, because the doc and the decoder can drift apart silently.
//
// yaml.v3 decodes time.Duration from a unit-suffixed STRING. A bare number is
// a parse error, and the error surfaces during LoadBootstrapConfig — before
// EffectivePostInstallHealthTimeout can apply any default. So documenting
// "zero is treated as unset" without saying "with a unit" would promise a
// fallback the operator can never reach: `health_timeout: 0` fails the load.
//
// Same constraint as the sibling read-timeout/write-timeout fields, which is
// why this is documented rather than papered over with a custom unmarshaler
// for one field.
func TestHealthTimeoutYAMLParseRule(t *testing.T) {
	type platformOnly struct {
		HealthTimeout time.Duration `yaml:"health_timeout,omitempty"`
	}
	tests := []struct {
		yaml      string
		wantErr   bool
		wantValue time.Duration
	}{
		{"health_timeout: 25m", false, 25 * time.Minute},
		{"health_timeout: 0s", false, 0},
		{"health_timeout: -5m", false, -5 * time.Minute},
		{"health_timeout: 0", true, 0}, // bare number: parse error, not a default
		{"health_timeout: 600", true, 0},
		{"{}", false, 0}, // omitted, which IS the supported way to take the default
	}
	for _, tt := range tests {
		var got platformOnly
		err := yaml.Unmarshal([]byte(tt.yaml), &got)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%q: parsed without error; docs say a bare number is a parse error", tt.yaml)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", tt.yaml, err)
			continue
		}
		if got.HealthTimeout != tt.wantValue {
			t.Errorf("%q: got %v, want %v", tt.yaml, got.HealthTimeout, tt.wantValue)
		}
	}
}

// deadlineObservingChecker records the deadline of the context it is probed
// with, then CANCELS the wait so the test ends on the next select.
//
// The cancel is load-bearing: a refused probe RETRIES on the health cadence, so
// a checker that only returned an error would make this test poll for the very
// 25-40 minutes it is asserting about. Same shape as the existing
// cancellingHealthChecker in orchestrator_test.go.
type deadlineObservingChecker struct {
	cancel   context.CancelFunc
	deadline time.Time
	seen     bool
	calls    atomic.Int64
}

func (c *deadlineObservingChecker) Check(ctx context.Context, _ string) error {
	if d, ok := ctx.Deadline(); ok && !c.seen {
		c.deadline, c.seen = d, true
	}
	if c.calls.Add(1) == 1 && c.cancel != nil {
		c.cancel()
	}
	return errProbeRefused
}

var errProbeRefused = errors.New("probe refused")

// TestAwaitPostInstallHealthUsesConfiguredTimeout exercises the PRODUCTION
// path — awaitPostInstallHealth — not EffectivePostInstallHealthTimeout in
// isolation. Testing the helper alone proves only the helper: if
// orchestrator.go's health context reverted to the bare constant, or read a
// different config field, every other test here would still pass while the
// operator-facing knob silently did nothing. Asserting on the deadline the
// checker actually receives is what ties the config to the wait.
func TestAwaitPostInstallHealthUsesConfiguredTimeout(t *testing.T) {
	tests := []struct {
		name      string
		configure time.Duration
		want      time.Duration
	}{
		{"unset uses the default", 0, defaultPostInstallHealthTimeout},
		{"configured value governs", 40 * time.Minute, 40 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalConfig()
			cfg.Platform.HealthTimeout = tt.configure
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			chk := &deadlineObservingChecker{cancel: cancel}
			o, err := NewOrchestrator(OrchestratorParams{
				Config:        cfg,
				BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
				Logger:        orchTestLogger(),
				Deployer:      &mockDeployer{},
				HealthChecker: chk,
			})
			if err != nil {
				t.Fatalf("NewOrchestrator: %v", err)
			}

			node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "probe-node", Role: RoleWorker}}
			start := time.Now()
			_ = o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1:1"}, "")

			if !chk.seen {
				t.Fatal("health checker was never probed with a deadline; the wait did not run")
			}
			got := chk.deadline.Sub(start)
			// Generous tolerance: distinguishing 25m from 40m, not timing.
			if got < tt.want-time.Minute || got > tt.want+time.Minute {
				t.Errorf("health context deadline ~%v, want ~%v (config=%v)", got.Round(time.Second), tt.want, tt.configure)
			}
		})
	}
}
