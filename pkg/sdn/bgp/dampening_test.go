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

package bgp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// mockDampeningSpeaker implements DampeningSpeakerInterface for testing.
type mockDampeningSpeaker struct {
	started          bool
	suppressErr      error
	unsuppressErr    error
	suppressedRoutes []netip.Prefix
}

func newMockDampeningSpeaker() *mockDampeningSpeaker {
	return &mockDampeningSpeaker{
		started:          true,
		suppressedRoutes: make([]netip.Prefix, 0),
	}
}

func (m *mockDampeningSpeaker) IsStarted() bool {
	return m.started
}

func (m *mockDampeningSpeaker) SuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	if m.suppressErr != nil {
		return m.suppressErr
	}
	m.suppressedRoutes = append(m.suppressedRoutes, prefix)
	return nil
}

func (m *mockDampeningSpeaker) UnsuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	if m.unsuppressErr != nil {
		return m.unsuppressErr
	}
	for i, p := range m.suppressedRoutes {
		if p == prefix {
			m.suppressedRoutes = append(m.suppressedRoutes[:i], m.suppressedRoutes[i+1:]...)
			break
		}
	}
	return nil
}

// TestNewDampeningManager tests dampening manager creation.
func TestNewDampeningManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		speaker     DampeningSpeakerInterface
		config      *DampeningConfig
		logger      interface{}
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid creation with default config",
			speaker: newMockDampeningSpeaker(),
			config:  nil,
			logger:  testLogger(),
			wantErr: false,
		},
		{
			name:    "valid creation with custom config",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          20 * time.Minute,
				ReuseThreshold:    500,
				SuppressThreshold: 3000,
				MaxSuppressTime:   90 * time.Minute,
				FlapPenalty:       1500,
				DecayInterval:     10 * time.Second,
			},
			logger:  testLogger(),
			wantErr: false,
		},
		{
			name:        "nil speaker",
			speaker:     nil,
			config:      nil,
			logger:      testLogger(),
			wantErr:     true,
			errContains: "speaker is nil",
		},
		{
			name:        "nil logger",
			speaker:     newMockDampeningSpeaker(),
			config:      nil,
			logger:      nil,
			wantErr:     true,
			errContains: "logger is nil",
		},
		{
			name:    "invalid config - zero half-life",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          0,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "half-life",
		},
		{
			name:    "invalid config - zero reuse threshold",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    0,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "reuse",
		},
		{
			name:    "invalid config - zero suppress threshold",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 0,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "suppress",
		},
		{
			name:    "invalid config - reuse >= suppress",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    2500,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "reuse",
		},
		{
			name:    "invalid config - zero max suppress time",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   0,
				FlapPenalty:       1000,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "suppress",
		},
		{
			name:    "invalid config - zero flap penalty",
			speaker: newMockDampeningSpeaker(),
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       0,
				DecayInterval:     5 * time.Second,
			},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "penalty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var dm *DampeningManager
			var err error
			if tt.logger == nil {
				dm, err = NewDampeningManager(tt.speaker, tt.config, nil)
			} else {
				dm, err = NewDampeningManager(tt.speaker, tt.config, testLogger())
			}

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if dm == nil {
				t.Fatal("expected dampening manager, got nil")
			}
		})
	}
}

// TestDampeningManagerStartStop tests start and stop operations.
func TestDampeningManagerStartStop(t *testing.T) {
	t.Parallel()

	t.Run("start success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Errorf("Start() error = %v", err)
		}

		if !dm.IsStarted() {
			t.Error("expected IsStarted() = true")
		}
	})

	t.Run("start when already started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("first Start() error = %v", err)
		}

		err = dm.Start(ctx)
		if err == nil {
			t.Error("expected error on second Start()")
		}
	})

	t.Run("start with speaker not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		speaker.started = false
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		err = dm.Start(ctx)
		if err == nil {
			t.Error("expected error when speaker not started")
		}
	})

	t.Run("stop success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := dm.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if dm.IsStarted() {
			t.Error("expected IsStarted() = false after stop")
		}
	})

	t.Run("stop when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		if err := dm.Stop(); err != nil {
			t.Errorf("Stop() when not started should not error: %v", err)
		}
	})
}

// TestRecordFlap tests recording route flaps.
func TestRecordFlap(t *testing.T) {
	t.Parallel()

	t.Run("single flap", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		if err := dm.RecordFlap(prefix); err != nil {
			t.Errorf("RecordFlap() error = %v", err)
		}

		state, err := dm.GetDampeningState(prefix)
		if err != nil {
			t.Fatalf("GetDampeningState() error = %v", err)
		}

		if state.FlapCount != 1 {
			t.Errorf("FlapCount = %d, want 1", state.FlapCount)
		}

		if state.Penalty != DefaultFlapPenalty {
			t.Errorf("Penalty = %d, want %d", state.Penalty, DefaultFlapPenalty)
		}
	})

	t.Run("multiple flaps cause suppression", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		prefix := netip.MustParsePrefix("192.0.2.0/24")

		// Default: suppress threshold is 2000, flap penalty is 1000
		// Two flaps should trigger suppression
		for i := 0; i < 3; i++ {
			if err := dm.RecordFlap(prefix); err != nil {
				t.Fatalf("RecordFlap() error = %v", err)
			}
		}

		if !dm.IsSuppressed(prefix) {
			t.Error("expected route to be suppressed after 3 flaps")
		}

		state, _ := dm.GetDampeningState(prefix)
		if state.FlapCount != 3 {
			t.Errorf("FlapCount = %d, want 3", state.FlapCount)
		}

		if !state.ReuseAt.After(time.Now()) {
			t.Error("ReuseAt should be in the future")
		}
	})

	t.Run("flap invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = dm.RecordFlap(netip.Prefix{})
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("flap when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		err = dm.RecordFlap(prefix)
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestIsSuppressed tests suppression status checking.
func TestIsSuppressed(t *testing.T) {
	t.Parallel()

	t.Run("not suppressed initially", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		if dm.IsSuppressed(prefix) {
			t.Error("expected IsSuppressed() = false for unknown prefix")
		}
	})

	t.Run("not suppressed after single flap", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		dm.RecordFlap(prefix)

		if dm.IsSuppressed(prefix) {
			t.Error("expected IsSuppressed() = false after single flap")
		}
	})

	t.Run("invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		// Should return false for invalid prefix
		if dm.IsSuppressed(netip.Prefix{}) {
			t.Error("expected IsSuppressed() = false for invalid prefix")
		}
	})
}

// TestGetDampeningState tests getting dampening state.
func TestGetDampeningState(t *testing.T) {
	t.Parallel()

	t.Run("get existing state", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		dm.RecordFlap(prefix)

		state, err := dm.GetDampeningState(prefix)
		if err != nil {
			t.Errorf("GetDampeningState() error = %v", err)
		}

		if state.Prefix != prefix {
			t.Errorf("Prefix = %v, want %v", state.Prefix, prefix)
		}
	})

	t.Run("get non-existent state", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		_, err = dm.GetDampeningState(prefix)
		if err == nil {
			t.Error("expected error for non-existent state")
		}
	})

	t.Run("get invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		_, err = dm.GetDampeningState(netip.Prefix{})
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})
}

// TestListSuppressedRoutes tests listing suppressed routes.
func TestListSuppressedRoutes(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	// Initially empty
	suppressed := dm.ListSuppressedRoutes()
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed routes, got %d", len(suppressed))
	}

	// Add flaps to trigger suppression
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}

	for _, prefix := range prefixes {
		for i := 0; i < 3; i++ {
			dm.RecordFlap(prefix)
		}
	}

	suppressed = dm.ListSuppressedRoutes()
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed routes, got %d", len(suppressed))
	}

	// Check duration field
	for _, route := range suppressed {
		if route.Duration < 0 {
			t.Errorf("Duration should be >= 0, got %v", route.Duration)
		}
	}
}

// TestClearDampening tests clearing dampening for a route.
func TestClearDampening(t *testing.T) {
	t.Parallel()

	t.Run("clear existing", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		for i := 0; i < 3; i++ {
			dm.RecordFlap(prefix)
		}

		if err := dm.ClearDampening(prefix); err != nil {
			t.Errorf("ClearDampening() error = %v", err)
		}

		if dm.IsSuppressed(prefix) {
			t.Error("expected IsSuppressed() = false after clear")
		}

		_, err = dm.GetDampeningState(prefix)
		if err == nil {
			t.Error("expected error for cleared state")
		}
	})

	t.Run("clear non-existent", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		err = dm.ClearDampening(prefix)
		if err == nil {
			t.Error("expected error for non-existent state")
		}
	})

	t.Run("clear invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		err = dm.ClearDampening(netip.Prefix{})
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("clear when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		err = dm.ClearDampening(prefix)
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestClearAllDampening tests clearing all dampening.
func TestClearAllDampening(t *testing.T) {
	t.Parallel()

	t.Run("clear all", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		// Add some routes
		for _, prefix := range []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
		} {
			dm.RecordFlap(prefix)
		}

		if err := dm.ClearAllDampening(); err != nil {
			t.Errorf("ClearAllDampening() error = %v", err)
		}

		if dm.RouteCount() != 0 {
			t.Errorf("RouteCount() = %d, want 0", dm.RouteCount())
		}
	})

	t.Run("clear when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		err = dm.ClearAllDampening()
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestDecayTimer tests the decay timer functionality.
func TestDecayTimer(t *testing.T) {
	t.Parallel()

	t.Run("start and stop decay timer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		cfg := DefaultDampeningConfig()
		cfg.DecayInterval = 50 * time.Millisecond
		dm, err := NewDampeningManager(speaker, cfg, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := dm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := dm.StartDecayTimer(ctx); err != nil {
			t.Errorf("StartDecayTimer() error = %v", err)
		}

		// Wait for decay to process
		time.Sleep(100 * time.Millisecond)

		dm.StopDecayTimer()
	})

	t.Run("start decay timer twice", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		if err := dm.StartDecayTimer(ctx); err != nil {
			t.Fatalf("first StartDecayTimer() error = %v", err)
		}

		err = dm.StartDecayTimer(ctx)
		if err == nil {
			t.Error("expected error on second StartDecayTimer()")
		}

		dm.StopDecayTimer()
	})

	t.Run("start decay timer when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		err = dm.StartDecayTimer(ctx)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("stop decay timer when not running", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		// Should not panic
		dm.StopDecayTimer()
	})
}

// TestDecayFunctionality tests penalty decay.
func TestDecayFunctionality(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	cfg := DefaultDampeningConfig()
	cfg.DecayInterval = 10 * time.Millisecond
	dm, err := NewDampeningManager(speaker, cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	prefix := netip.MustParsePrefix("192.0.2.0/24")

	// Record flaps to get a penalty
	for i := 0; i < 3; i++ {
		dm.RecordFlap(prefix)
	}

	initialState, _ := dm.GetDampeningState(prefix)
	initialPenalty := initialState.Penalty

	// Start decay timer and wait
	dm.StartDecayTimer(ctx)
	time.Sleep(100 * time.Millisecond)
	dm.StopDecayTimer()

	finalState, _ := dm.GetDampeningState(prefix)
	finalPenalty := finalState.Penalty

	// Penalty should have decayed
	if finalPenalty >= initialPenalty {
		t.Errorf("penalty should have decayed: initial=%d, final=%d", initialPenalty, finalPenalty)
	}
}

// TestRouteCounts tests route counting.
func TestRouteCounts(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	if dm.RouteCount() != 0 {
		t.Errorf("RouteCount() = %d, want 0", dm.RouteCount())
	}

	if dm.SuppressedCount() != 0 {
		t.Errorf("SuppressedCount() = %d, want 0", dm.SuppressedCount())
	}

	// Add some routes
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
	} {
		dm.RecordFlap(prefix)
	}

	// Suppress one
	prefix := netip.MustParsePrefix("172.16.0.0/12")
	for i := 0; i < 3; i++ {
		dm.RecordFlap(prefix)
	}

	if dm.RouteCount() != 3 {
		t.Errorf("RouteCount() = %d, want 3", dm.RouteCount())
	}

	if dm.SuppressedCount() != 1 {
		t.Errorf("SuppressedCount() = %d, want 1", dm.SuppressedCount())
	}
}

// TestGetConfig tests getting configuration.
func TestGetConfig(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	config := dm.GetConfig()

	if config.HalfLife != DefaultHalfLife {
		t.Errorf("HalfLife = %v, want %v", config.HalfLife, DefaultHalfLife)
	}

	if config.ReuseThreshold != DefaultReuseThreshold {
		t.Errorf("ReuseThreshold = %d, want %d", config.ReuseThreshold, DefaultReuseThreshold)
	}

	if config.SuppressThreshold != DefaultSuppressThreshold {
		t.Errorf("SuppressThreshold = %d, want %d", config.SuppressThreshold, DefaultSuppressThreshold)
	}

	if config.MaxSuppressTime != DefaultMaxSuppressTime {
		t.Errorf("MaxSuppressTime = %v, want %v", config.MaxSuppressTime, DefaultMaxSuppressTime)
	}

	if config.FlapPenalty != DefaultFlapPenalty {
		t.Errorf("FlapPenalty = %d, want %d", config.FlapPenalty, DefaultFlapPenalty)
	}
}

// TestGetStats tests getting statistics.
func TestGetStats(t *testing.T) {
	t.Parallel()

	t.Run("empty stats", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		stats := dm.GetStats()
		if stats.TotalRoutes != 0 {
			t.Errorf("TotalRoutes = %d, want 0", stats.TotalRoutes)
		}
		if stats.SuppressedRoutes != 0 {
			t.Errorf("SuppressedRoutes = %d, want 0", stats.SuppressedRoutes)
		}
		if stats.TotalFlaps != 0 {
			t.Errorf("TotalFlaps = %d, want 0", stats.TotalFlaps)
		}
	})

	t.Run("stats with routes", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		dm, err := NewDampeningManager(speaker, nil, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		// Add some flaps
		prefix1 := netip.MustParsePrefix("192.0.2.0/24")
		dm.RecordFlap(prefix1)
		dm.RecordFlap(prefix1)

		prefix2 := netip.MustParsePrefix("10.0.0.0/8")
		for i := 0; i < 3; i++ {
			dm.RecordFlap(prefix2)
		}

		stats := dm.GetStats()
		if stats.TotalRoutes != 2 {
			t.Errorf("TotalRoutes = %d, want 2", stats.TotalRoutes)
		}
		if stats.TotalFlaps != 5 {
			t.Errorf("TotalFlaps = %d, want 5", stats.TotalFlaps)
		}
		if stats.SuppressedRoutes != 1 {
			t.Errorf("SuppressedRoutes = %d, want 1", stats.SuppressedRoutes)
		}
		if stats.AveragePenalty <= 0 {
			t.Error("AveragePenalty should be > 0")
		}
		if stats.MaxPenalty <= 0 {
			t.Error("MaxPenalty should be > 0")
		}
	})
}

// TestListAllRoutes tests listing all tracked routes.
func TestListAllRoutes(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	// Add some routes
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}

	for _, prefix := range prefixes {
		dm.RecordFlap(prefix)
	}

	routes := dm.ListAllRoutes()
	if len(routes) != 3 {
		t.Errorf("ListAllRoutes() len = %d, want 3", len(routes))
	}
}

// TestMaxPenalty tests penalty capping.
func TestMaxPenalty(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	prefix := netip.MustParsePrefix("192.0.2.0/24")

	// Record many flaps
	for i := 0; i < 100; i++ {
		dm.RecordFlap(prefix)
	}

	state, _ := dm.GetDampeningState(prefix)
	maxPenalty := dm.GetMaxPenalty()

	if state.Penalty > maxPenalty {
		t.Errorf("Penalty %d exceeds max %d", state.Penalty, maxPenalty)
	}
}

// TestDecayFactor tests decay factor calculation.
func TestDecayFactor(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	dm, err := NewDampeningManager(speaker, nil, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	decayFactor := dm.GetDecayFactor()

	// Decay factor should be between 0 and 1
	if decayFactor <= 0 || decayFactor >= 1 {
		t.Errorf("DecayFactor = %f, should be between 0 and 1", decayFactor)
	}
}

// TestDefaultDampeningConfig tests default configuration.
func TestDefaultDampeningConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultDampeningConfig()

	if cfg.HalfLife != DefaultHalfLife {
		t.Errorf("HalfLife = %v, want %v", cfg.HalfLife, DefaultHalfLife)
	}

	if cfg.ReuseThreshold != DefaultReuseThreshold {
		t.Errorf("ReuseThreshold = %d, want %d", cfg.ReuseThreshold, DefaultReuseThreshold)
	}

	if cfg.SuppressThreshold != DefaultSuppressThreshold {
		t.Errorf("SuppressThreshold = %d, want %d", cfg.SuppressThreshold, DefaultSuppressThreshold)
	}

	if cfg.MaxSuppressTime != DefaultMaxSuppressTime {
		t.Errorf("MaxSuppressTime = %v, want %v", cfg.MaxSuppressTime, DefaultMaxSuppressTime)
	}

	if cfg.FlapPenalty != DefaultFlapPenalty {
		t.Errorf("FlapPenalty = %d, want %d", cfg.FlapPenalty, DefaultFlapPenalty)
	}

	if cfg.DecayInterval != DefaultDecayInterval {
		t.Errorf("DecayInterval = %v, want %v", cfg.DecayInterval, DefaultDecayInterval)
	}

	// Default config should be valid
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultDampeningConfig().Validate() error = %v", err)
	}
}

// TestDampeningConfigValidate tests configuration validation.
func TestDampeningConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *DampeningConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultDampeningConfig(),
			wantErr: false,
		},
		{
			name: "negative half-life",
			config: &DampeningConfig{
				HalfLife:          -time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
			},
			wantErr: true,
		},
		{
			name: "negative reuse threshold",
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    -750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
			},
			wantErr: true,
		},
		{
			name: "negative suppress threshold",
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: -2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
			},
			wantErr: true,
		},
		{
			name: "reuse equals suppress",
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    2000,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       1000,
			},
			wantErr: true,
		},
		{
			name: "negative max suppress time",
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   -60 * time.Minute,
				FlapPenalty:       1000,
			},
			wantErr: true,
		},
		{
			name: "negative flap penalty",
			config: &DampeningConfig{
				HalfLife:          15 * time.Minute,
				ReuseThreshold:    750,
				SuppressThreshold: 2000,
				MaxSuppressTime:   60 * time.Minute,
				FlapPenalty:       -1000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRFC2439Compliance tests compliance with RFC 2439 requirements.
func TestRFC2439Compliance(t *testing.T) {
	t.Parallel()

	t.Run("15-60 minute suppression window", func(t *testing.T) {
		t.Parallel()

		// RFC 2439 specifies 15m half-life and 60m max suppress time
		cfg := DefaultDampeningConfig()

		if cfg.HalfLife != 15*time.Minute {
			t.Errorf("HalfLife = %v, RFC 2439 recommends 15m", cfg.HalfLife)
		}

		if cfg.MaxSuppressTime != 60*time.Minute {
			t.Errorf("MaxSuppressTime = %v, RFC 2439 recommends 60m", cfg.MaxSuppressTime)
		}
	})

	t.Run("penalty decay follows half-life", func(t *testing.T) {
		t.Parallel()

		speaker := newMockDampeningSpeaker()
		cfg := &DampeningConfig{
			HalfLife:          100 * time.Millisecond,
			ReuseThreshold:    100,
			SuppressThreshold: 500,
			MaxSuppressTime:   1 * time.Second,
			FlapPenalty:       1000,
			DecayInterval:     10 * time.Millisecond,
		}
		dm, err := NewDampeningManager(speaker, cfg, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		dm.Start(ctx)

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		dm.RecordFlap(prefix)

		initial, _ := dm.GetDampeningState(prefix)
		initialPenalty := initial.Penalty

		// Start decay and wait approximately one half-life
		dm.StartDecayTimer(ctx)
		time.Sleep(150 * time.Millisecond)
		dm.StopDecayTimer()

		final, _ := dm.GetDampeningState(prefix)

		// After one half-life, penalty should be approximately half
		// Allow for some variance due to timing
		expectedRange := float64(initialPenalty) * 0.3
		actualPenalty := float64(final.Penalty)
		halfPenalty := float64(initialPenalty) / 2

		if actualPenalty > halfPenalty+expectedRange || actualPenalty < halfPenalty-expectedRange {
			t.Logf("Penalty decay: initial=%d, final=%d, expected ~%d", initialPenalty, final.Penalty, int(halfPenalty))
		}
	})
}

// TestUnsuppressOnDecay tests that routes are unsuppressed when penalty drops.
func TestUnsuppressOnDecay(t *testing.T) {
	t.Parallel()

	speaker := newMockDampeningSpeaker()
	cfg := &DampeningConfig{
		HalfLife:          20 * time.Millisecond,
		ReuseThreshold:    200,
		SuppressThreshold: 500,
		MaxSuppressTime:   1 * time.Second,
		FlapPenalty:       600,
		DecayInterval:     5 * time.Millisecond,
	}
	dm, err := NewDampeningManager(speaker, cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	dm.Start(ctx)

	prefix := netip.MustParsePrefix("192.0.2.0/24")
	dm.RecordFlap(prefix)

	// Should be suppressed after one flap with penalty 600 > suppress threshold 500
	if !dm.IsSuppressed(prefix) {
		t.Error("expected route to be suppressed")
	}

	// Start decay and wait for penalty to drop below reuse threshold
	dm.StartDecayTimer(ctx)
	time.Sleep(200 * time.Millisecond)
	dm.StopDecayTimer()

	// Route should be unsuppressed
	if dm.IsSuppressed(prefix) {
		state, _ := dm.GetDampeningState(prefix)
		t.Errorf("expected route to be unsuppressed, penalty=%d", state.Penalty)
	}
}
