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

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// newOVSTestApp builds the minimal App needed for OVS other_config tests.
func newOVSTestApp(t *testing.T) *App {
	t.Helper()
	return &App{
		Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
	}
}

// fakeOtherConfigClient implements ovsOtherConfigClient for unit tests.
type fakeOtherConfigClient struct {
	current map[string]string
	getErr  error
	setErr  error

	getCalls int
	setCalls []map[string]string
}

func (f *fakeOtherConfigClient) GetOVSOtherConfig(_ context.Context) (map[string]string, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.current, nil
}

func (f *fakeOtherConfigClient) SetOVSOtherConfig(_ context.Context, config map[string]string) error {
	f.setCalls = append(f.setCalls, config)
	if f.setErr != nil {
		return f.setErr
	}
	return nil
}

// fakeDatapathClient implements ovsBridgeDatapathClient for unit tests.
type fakeDatapathClient struct {
	err   error
	calls []string
}

func (f *fakeDatapathClient) SetBridgeDatapath(_ context.Context, name, datapathType string) error {
	f.calls = append(f.calls, name+"="+datapathType)
	return f.err
}

func TestDesiredOVSOtherConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *sdn.OVSConfig
		want map[string]string
	}{
		{
			name: "nil config",
			cfg:  nil,
			want: map[string]string{},
		},
		{
			name: "empty config",
			cfg:  &sdn.OVSConfig{},
			want: map[string]string{},
		},
		{
			name: "hw-offload only",
			cfg:  &sdn.OVSConfig{HWOffload: true},
			want: map[string]string{"hw-offload": "true"},
		},
		{
			name: "hw-offload with tc-policy",
			cfg:  &sdn.OVSConfig{HWOffload: true, TCPolicy: "skip_sw"},
			want: map[string]string{"hw-offload": "true", "tc-policy": "skip_sw"},
		},
		{
			name: "dpdk not initialized produces no keys",
			cfg: &sdn.OVSConfig{
				Datapath: "netdev",
				DPDK:     &sdn.DPDKConfig{Init: false, SocketMem: "1024"},
			},
			want: map[string]string{},
		},
		{
			name: "dpdk full",
			cfg: &sdn.OVSConfig{
				Datapath: "netdev",
				DPDK: &sdn.DPDKConfig{
					Init:       true,
					SocketMem:  "1024,1024",
					LCoreMask:  "0x1",
					PMDCPUMask: "0x6",
				},
			},
			want: map[string]string{
				"dpdk-init":       "true",
				"dpdk-socket-mem": "1024,1024",
				"dpdk-lcore-mask": "0x1",
				"pmd-cpu-mask":    "0x6",
			},
		},
		{
			name: "dpdk partial omits empty keys",
			cfg: &sdn.OVSConfig{
				Datapath: "netdev",
				DPDK:     &sdn.DPDKConfig{Init: true, SocketMem: "2048"},
			},
			want: map[string]string{
				"dpdk-init":       "true",
				"dpdk-socket-mem": "2048",
			},
		},
		{
			name: "dpdk extra merged last and wins",
			cfg: &sdn.OVSConfig{
				Datapath: "netdev",
				DPDK: &sdn.DPDKConfig{
					Init:      true,
					LCoreMask: "0x1",
					Extra: map[string]string{
						"dpdk-lcore-mask":   "0xff",
						"dpdk-hugepage-dir": "/dev/hugepages",
					},
				},
			},
			want: map[string]string{
				"dpdk-init":         "true",
				"dpdk-lcore-mask":   "0xff",
				"dpdk-hugepage-dir": "/dev/hugepages",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := desiredOVSOtherConfig(tt.cfg)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("desiredOVSOtherConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiffOtherConfig(t *testing.T) {
	tests := []struct {
		name    string
		current map[string]string
		desired map[string]string
		want    map[string]string
	}{
		{
			name:    "all missing",
			current: map[string]string{},
			desired: map[string]string{"hw-offload": "true"},
			want:    map[string]string{"hw-offload": "true"},
		},
		{
			name:    "value changed",
			current: map[string]string{"tc-policy": "none"},
			desired: map[string]string{"tc-policy": "skip_sw"},
			want:    map[string]string{"tc-policy": "skip_sw"},
		},
		{
			name:    "in sync",
			current: map[string]string{"hw-offload": "true"},
			desired: map[string]string{"hw-offload": "true"},
			want:    map[string]string{},
		},
		{
			name:    "unmanaged current keys ignored",
			current: map[string]string{"max-idle": "10000"},
			desired: map[string]string{"hw-offload": "true"},
			want:    map[string]string{"hw-offload": "true"},
		},
		{
			name:    "empty desired",
			current: map[string]string{"hw-offload": "true"},
			desired: map[string]string{},
			want:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffOtherConfig(tt.current, tt.desired)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("diffOtherConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDatapathEquivalent(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"", "system", true},
		{"system", "", true},
		{"system", "system", true},
		{"netdev", "netdev", true},
		{"", "netdev", false},
		{"system", "netdev", false},
		{"netdev", "system", false},
	}

	for _, tt := range tests {
		if got := datapathEquivalent(tt.a, tt.b); got != tt.want {
			t.Errorf("datapathEquivalent(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestApplyOVSOtherConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing desired is a no-op", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeOtherConfigClient{}

		err := app.applyOVSOtherConfig(ctx, fake, &sdn.OVSConfig{})
		if err != nil {
			t.Fatalf("applyOVSOtherConfig() = %v, want nil", err)
		}
		if fake.getCalls != 0 || len(fake.setCalls) != 0 {
			t.Fatalf("expected no client calls, got get=%d set=%d", fake.getCalls, len(fake.setCalls))
		}
	})

	t.Run("applies only changed keys", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeOtherConfigClient{
			current: map[string]string{"hw-offload": "true"},
		}

		err := app.applyOVSOtherConfig(ctx, fake, &sdn.OVSConfig{
			HWOffload: true,
			TCPolicy:  "skip_sw",
		})
		if err != nil {
			t.Fatalf("applyOVSOtherConfig() = %v, want nil", err)
		}
		if len(fake.setCalls) != 1 {
			t.Fatalf("expected 1 set call, got %d", len(fake.setCalls))
		}
		want := map[string]string{"tc-policy": "skip_sw"}
		if !reflect.DeepEqual(fake.setCalls[0], want) {
			t.Fatalf("set called with %v, want %v", fake.setCalls[0], want)
		}
	})

	t.Run("in sync skips set", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeOtherConfigClient{
			current: map[string]string{"hw-offload": "true"},
		}

		err := app.applyOVSOtherConfig(ctx, fake, &sdn.OVSConfig{HWOffload: true})
		if err != nil {
			t.Fatalf("applyOVSOtherConfig() = %v, want nil", err)
		}
		if len(fake.setCalls) != 0 {
			t.Fatalf("expected no set calls, got %d", len(fake.setCalls))
		}
	})

	t.Run("get error propagates", func(t *testing.T) {
		app := newOVSTestApp(t)
		wantErr := errors.New("get failed")
		fake := &fakeOtherConfigClient{getErr: wantErr}

		err := app.applyOVSOtherConfig(ctx, fake, &sdn.OVSConfig{HWOffload: true})
		if !errors.Is(err, wantErr) {
			t.Fatalf("applyOVSOtherConfig() = %v, want %v", err, wantErr)
		}
	})

	t.Run("set error propagates", func(t *testing.T) {
		app := newOVSTestApp(t)
		wantErr := errors.New("set failed")
		fake := &fakeOtherConfigClient{setErr: wantErr}

		err := app.applyOVSOtherConfig(ctx, fake, &sdn.OVSConfig{HWOffload: true})
		if !errors.Is(err, wantErr) {
			t.Fatalf("applyOVSOtherConfig() = %v, want %v", err, wantErr)
		}
	})
}

func TestReconcileBridgeDatapath(t *testing.T) {
	ctx := context.Background()

	t.Run("empty configured datapath is a no-op", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeDatapathClient{}

		err := app.reconcileBridgeDatapath(ctx, fake, &sdn.OVSConfig{Bridge: "br0"}, &ovs.Bridge{Name: "br0", DatapathType: "netdev"})
		if err != nil {
			t.Fatalf("reconcileBridgeDatapath() = %v, want nil", err)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("expected no calls, got %v", fake.calls)
		}
	})

	t.Run("system vs empty is equivalent", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeDatapathClient{}

		err := app.reconcileBridgeDatapath(ctx, fake, &sdn.OVSConfig{Bridge: "br0", Datapath: "system"}, &ovs.Bridge{Name: "br0", DatapathType: ""})
		if err != nil {
			t.Fatalf("reconcileBridgeDatapath() = %v, want nil", err)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("expected no calls, got %v", fake.calls)
		}
	})

	t.Run("differing datapath is reconciled", func(t *testing.T) {
		app := newOVSTestApp(t)
		fake := &fakeDatapathClient{}

		err := app.reconcileBridgeDatapath(ctx, fake, &sdn.OVSConfig{Bridge: "br0", Datapath: "netdev"}, &ovs.Bridge{Name: "br0", DatapathType: ""})
		if err != nil {
			t.Fatalf("reconcileBridgeDatapath() = %v, want nil", err)
		}
		if len(fake.calls) != 1 || fake.calls[0] != "br0=netdev" {
			t.Fatalf("expected [br0=netdev], got %v", fake.calls)
		}
	})

	t.Run("set error is wrapped", func(t *testing.T) {
		app := newOVSTestApp(t)
		wantErr := errors.New("update failed")
		fake := &fakeDatapathClient{err: wantErr}

		err := app.reconcileBridgeDatapath(ctx, fake, &sdn.OVSConfig{Bridge: "br0", Datapath: "netdev"}, &ovs.Bridge{Name: "br0", DatapathType: "system"})
		if !errors.Is(err, wantErr) {
			t.Fatalf("reconcileBridgeDatapath() = %v, want wrapped %v", err, wantErr)
		}
	})
}
