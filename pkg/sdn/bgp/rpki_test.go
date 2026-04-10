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

// mockRPKISpeaker implements RPKISpeakerInterface for testing.
type mockRPKISpeaker struct {
	started bool
	asn     uint32
}

func newMockRPKISpeaker() *mockRPKISpeaker {
	return &mockRPKISpeaker{
		started: true,
		asn:     65000,
	}
}

func (m *mockRPKISpeaker) IsStarted() bool {
	return m.started
}

func (m *mockRPKISpeaker) GetASN() uint32 {
	return m.asn
}

// TestNewRPKIValidator tests RPKI validator creation.
func TestNewRPKIValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		speaker     RPKISpeakerInterface
		validators  []string
		logger      interface{}
		opts        []RPKIValidatorOption
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid creation",
			speaker:    newMockRPKISpeaker(),
			validators: []string{"rtr.rpki.cloudflare.com:8282"},
			logger:     testLogger(),
			wantErr:    false,
		},
		{
			name:       "valid creation with empty validators",
			speaker:    newMockRPKISpeaker(),
			validators: []string{},
			logger:     testLogger(),
			wantErr:    false,
		},
		{
			name:       "valid creation with options",
			speaker:    newMockRPKISpeaker(),
			validators: []string{"rtr.rpki.cloudflare.com:8282"},
			logger:     testLogger(),
			opts: []RPKIValidatorOption{
				WithFailOpen(true),
				WithCacheTimeout(2 * time.Hour),
			},
			wantErr: false,
		},
		{
			name:        "nil speaker",
			speaker:     nil,
			validators:  []string{},
			logger:      testLogger(),
			wantErr:     true,
			errContains: "speaker is nil",
		},
		{
			name:        "nil logger",
			speaker:     newMockRPKISpeaker(),
			validators:  []string{},
			logger:      nil,
			wantErr:     true,
			errContains: "logger is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rv *RPKIValidator
			var err error
			if tt.logger == nil {
				rv, err = NewRPKIValidator(tt.speaker, tt.validators, nil, tt.opts...)
			} else {
				rv, err = NewRPKIValidator(tt.speaker, tt.validators, testLogger(), tt.opts...)
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

			if rv == nil {
				t.Fatal("expected RPKI validator, got nil")
			}
		})
	}
}

// TestRPKIValidatorStartStop tests start and stop operations.
func TestRPKIValidatorStartStop(t *testing.T) {
	t.Parallel()

	t.Run("start success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Errorf("Start() error = %v", err)
		}

		if !rv.IsStarted() {
			t.Error("expected IsStarted() = true")
		}
	})

	t.Run("start when already started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("first Start() error = %v", err)
		}

		err = rv.Start(ctx)
		if err == nil {
			t.Error("expected error on second Start()")
		}
	})

	t.Run("start with speaker not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		speaker.started = false
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		err = rv.Start(ctx)
		if err == nil {
			t.Error("expected error when speaker not started")
		}
	})

	t.Run("stop success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := rv.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if rv.IsStarted() {
			t.Error("expected IsStarted() = false after stop")
		}
	})

	t.Run("stop when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		if err := rv.Stop(); err != nil {
			t.Errorf("Stop() when not started should not error: %v", err)
		}
	})
}

// TestValidateRoute tests route validation.
func TestValidateRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		prefix    netip.Prefix
		originASN uint32
		roas      []*ROAEntry
		failOpen  bool
		wantState RPKIValidationState
		wantErr   bool
	}{
		{
			name:      "valid route",
			prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			originASN: 65001,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 24,
					ASN:       65001,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			wantState: RPKIStateValid,
			wantErr:   false,
		},
		{
			name:      "valid route with longer prefix",
			prefix:    netip.MustParsePrefix("192.0.2.128/25"),
			originASN: 65001,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 26,
					ASN:       65001,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			wantState: RPKIStateValid,
			wantErr:   false,
		},
		{
			name:      "invalid route - wrong ASN",
			prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			originASN: 65002,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 24,
					ASN:       65001,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			wantState: RPKIStateInvalid,
			wantErr:   false,
		},
		{
			name:      "invalid route - prefix too long",
			prefix:    netip.MustParsePrefix("192.0.2.0/28"),
			originASN: 65001,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 24,
					ASN:       65001,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			wantState: RPKIStateInvalid,
			wantErr:   false,
		},
		{
			name:      "not found - no ROAs",
			prefix:    netip.MustParsePrefix("10.0.0.0/8"),
			originASN: 65001,
			roas:      []*ROAEntry{},
			wantState: RPKIStateNotFound,
			wantErr:   false,
		},
		{
			name:      "not found - no covering ROAs",
			prefix:    netip.MustParsePrefix("10.0.0.0/8"),
			originASN: 65001,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 24,
					ASN:       65001,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			wantState: RPKIStateNotFound,
			wantErr:   false,
		},
		{
			name:      "expired ROA",
			prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			originASN: 65001,
			roas: []*ROAEntry{
				{
					Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
					MaxLength: 24,
					ASN:       65001,
					ExpiresAt: time.Now().Add(-time.Hour), // Expired
				},
			},
			wantState: RPKIStateInvalid,
			wantErr:   false,
		},
		{
			name:      "invalid prefix",
			prefix:    netip.Prefix{},
			originASN: 65001,
			wantErr:   true,
		},
		{
			name:      "zero origin ASN",
			prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			originASN: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			speaker := newMockRPKISpeaker()
			rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
			if err != nil {
				t.Fatalf("failed to create validator: %v", err)
			}

			ctx := context.Background()
			if err := rv.Start(ctx); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			// Add ROAs
			for _, roa := range tt.roas {
				if err := rv.AddROA(roa); err != nil {
					t.Fatalf("AddROA() error = %v", err)
				}
			}

			if tt.failOpen {
				rv.SetFailOpen(true)
			}

			state, err := rv.ValidateRoute(tt.prefix, tt.originASN)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if state != tt.wantState {
				t.Errorf("state = %v, want %v", state, tt.wantState)
			}
		})
	}
}

// TestValidateRouteNoValidators tests validation without validators.
func TestValidateRouteNoValidators(t *testing.T) {
	t.Parallel()

	t.Run("fail closed", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		_, err = rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65001)
		if err == nil {
			t.Error("expected error when no validators and fail-closed")
		}
	})

	t.Run("fail open", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger(), WithFailOpen(true))
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		state, err := rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65001)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if state != RPKIStateNotFound {
			t.Errorf("state = %v, want %v", state, RPKIStateNotFound)
		}
	})
}

// TestValidateRouteNotStarted tests validation when not started.
func TestValidateRouteNotStarted(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	_, err = rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65001)
	if err == nil {
		t.Error("expected error when not started")
	}
}

// TestAddValidator tests adding validators.
func TestAddValidator(t *testing.T) {
	t.Parallel()

	t.Run("add validator", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := rv.AddValidator("validator:8282"); err != nil {
			t.Errorf("AddValidator() error = %v", err)
		}

		validators := rv.ListValidators()
		if len(validators) != 1 {
			t.Errorf("validator count = %d, want 1", len(validators))
		}
	})

	t.Run("add duplicate validator", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = rv.AddValidator("validator:8282")
		if err == nil {
			t.Error("expected error for duplicate validator")
		}
	})

	t.Run("add empty validator", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = rv.AddValidator("")
		if err == nil {
			t.Error("expected error for empty validator")
		}
	})

	t.Run("add when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		err = rv.AddValidator("validator:8282")
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestRemoveValidator tests removing validators.
func TestRemoveValidator(t *testing.T) {
	t.Parallel()

	t.Run("remove validator", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := rv.RemoveValidator("validator:8282"); err != nil {
			t.Errorf("RemoveValidator() error = %v", err)
		}

		validators := rv.ListValidators()
		if len(validators) != 0 {
			t.Errorf("validator count = %d, want 0", len(validators))
		}
	})

	t.Run("remove non-existent validator", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator1:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = rv.RemoveValidator("validator2:8282")
		if err == nil {
			t.Error("expected error for non-existent validator")
		}
	})

	t.Run("remove empty address", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		ctx := context.Background()
		if err := rv.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = rv.RemoveValidator("")
		if err == nil {
			t.Error("expected error for empty address")
		}
	})

	t.Run("remove when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		err = rv.RemoveValidator("validator:8282")
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestROAOperations tests ROA CRUD operations.
func TestROAOperations(t *testing.T) {
	t.Parallel()

	t.Run("add and get ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		roa := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 24,
			ASN:       65001,
			ExpiresAt: time.Now().Add(time.Hour),
			Source:    "test",
		}

		if err := rv.AddROA(roa); err != nil {
			t.Errorf("AddROA() error = %v", err)
		}

		roas, err := rv.GetROA(roa.Prefix)
		if err != nil {
			t.Errorf("GetROA() error = %v", err)
		}

		if len(roas) != 1 {
			t.Errorf("ROA count = %d, want 1", len(roas))
		}

		if roas[0].ASN != 65001 {
			t.Errorf("ROA ASN = %d, want 65001", roas[0].ASN)
		}
	})

	t.Run("add nil ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		err = rv.AddROA(nil)
		if err == nil {
			t.Error("expected error for nil ROA")
		}
	})

	t.Run("add ROA with invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		roa := &ROAEntry{
			Prefix:    netip.Prefix{},
			MaxLength: 24,
			ASN:       65001,
		}

		err = rv.AddROA(roa)
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("add ROA with zero ASN", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		roa := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 24,
			ASN:       0,
		}

		err = rv.AddROA(roa)
		if err == nil {
			t.Error("expected error for zero ASN")
		}
	})

	t.Run("update existing ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		roa := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 24,
			ASN:       65001,
			ExpiresAt: time.Now().Add(time.Hour),
			Source:    "original",
		}

		if err := rv.AddROA(roa); err != nil {
			t.Fatalf("AddROA() error = %v", err)
		}

		// Update with same prefix, ASN, and max length
		roa2 := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 24,
			ASN:       65001,
			ExpiresAt: time.Now().Add(2 * time.Hour),
			Source:    "updated",
		}

		if err := rv.AddROA(roa2); err != nil {
			t.Fatalf("AddROA() update error = %v", err)
		}

		roas, _ := rv.GetROA(roa.Prefix)
		if len(roas) != 1 {
			t.Errorf("ROA count = %d, want 1", len(roas))
		}

		if roas[0].Source != "updated" {
			t.Errorf("ROA source = %q, want %q", roas[0].Source, "updated")
		}
	})

	t.Run("remove ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		roa := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 24,
			ASN:       65001,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		if err := rv.AddROA(roa); err != nil {
			t.Fatalf("AddROA() error = %v", err)
		}

		if err := rv.RemoveROA(roa.Prefix, roa.ASN, roa.MaxLength); err != nil {
			t.Errorf("RemoveROA() error = %v", err)
		}

		_, err = rv.GetROA(roa.Prefix)
		if err == nil {
			t.Error("expected error for removed ROA")
		}
	})

	t.Run("remove non-existent ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		err = rv.RemoveROA(netip.MustParsePrefix("192.0.2.0/24"), 65001, 24)
		if err == nil {
			t.Error("expected error for non-existent ROA")
		}
	})

	t.Run("remove ROA invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		err = rv.RemoveROA(netip.Prefix{}, 65001, 24)
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("get non-existent ROA", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		_, err = rv.GetROA(netip.MustParsePrefix("10.0.0.0/8"))
		if err == nil {
			t.Error("expected error for non-existent ROA")
		}
	})

	t.Run("get ROA invalid prefix", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		_, err = rv.GetROA(netip.Prefix{})
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("clear ROA cache", func(t *testing.T) {
		t.Parallel()

		speaker := newMockRPKISpeaker()
		rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
		if err != nil {
			t.Fatalf("failed to create validator: %v", err)
		}

		// Add some ROAs
		for i := 0; i < 5; i++ {
			roa := &ROAEntry{
				Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
				MaxLength: 24 + i,
				ASN:       uint32(65001 + i),
				ExpiresAt: time.Now().Add(time.Hour),
			}
			if err := rv.AddROA(roa); err != nil {
				t.Fatalf("AddROA() error = %v", err)
			}
		}

		rv.ClearROACache()

		if rv.ROACount() != 0 {
			t.Errorf("ROACount() = %d, want 0 after clear", rv.ROACount())
		}
	})
}

// TestPruneExpiredROAs tests pruning expired ROAs.
func TestPruneExpiredROAs(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Add expired ROA
	expiredROA := &ROAEntry{
		Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
		MaxLength: 24,
		ASN:       65001,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if err := rv.AddROA(expiredROA); err != nil {
		t.Fatalf("AddROA() error = %v", err)
	}

	// Add valid ROA
	validROA := &ROAEntry{
		Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
		MaxLength: 24,
		ASN:       65002,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := rv.AddROA(validROA); err != nil {
		t.Fatalf("AddROA() error = %v", err)
	}

	pruned := rv.PruneExpiredROAs()
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}

	if rv.ROACount() != 1 {
		t.Errorf("ROACount() = %d, want 1", rv.ROACount())
	}
}

// TestROAEntry tests ROAEntry methods.
func TestROAEntry(t *testing.T) {
	t.Parallel()

	t.Run("IsExpired", func(t *testing.T) {
		t.Parallel()

		expired := &ROAEntry{ExpiresAt: time.Now().Add(-time.Hour)}
		if !expired.IsExpired() {
			t.Error("expected IsExpired() = true for expired ROA")
		}

		valid := &ROAEntry{ExpiresAt: time.Now().Add(time.Hour)}
		if valid.IsExpired() {
			t.Error("expected IsExpired() = false for valid ROA")
		}
	})

	t.Run("Covers", func(t *testing.T) {
		t.Parallel()

		roa := &ROAEntry{
			Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
			MaxLength: 26,
			ASN:       65001,
		}

		// Exact match
		if !roa.Covers(netip.MustParsePrefix("192.0.2.0/24"), 65001) {
			t.Error("expected Covers() = true for exact match")
		}

		// More specific within max length
		if !roa.Covers(netip.MustParsePrefix("192.0.2.0/26"), 65001) {
			t.Error("expected Covers() = true for /26 within max length")
		}

		// Too specific
		if roa.Covers(netip.MustParsePrefix("192.0.2.0/28"), 65001) {
			t.Error("expected Covers() = false for /28 beyond max length")
		}

		// Wrong ASN
		if roa.Covers(netip.MustParsePrefix("192.0.2.0/24"), 65002) {
			t.Error("expected Covers() = false for wrong ASN")
		}

		// Different prefix
		if roa.Covers(netip.MustParsePrefix("10.0.0.0/8"), 65001) {
			t.Error("expected Covers() = false for different prefix")
		}
	})
}

// TestRPKIStats tests validation statistics.
func TestRPKIStats(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	ctx := context.Background()
	if err := rv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add a ROA
	roa := &ROAEntry{
		Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
		MaxLength: 24,
		ASN:       65001,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := rv.AddROA(roa); err != nil {
		t.Fatalf("AddROA() error = %v", err)
	}

	// Validate some routes
	rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65001) // Valid
	rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65002) // Invalid
	rv.ValidateRoute(netip.MustParsePrefix("10.0.0.0/8"), 65001)   // Not found

	stats := rv.GetValidationStats()
	if stats.ValidCount != 1 {
		t.Errorf("ValidCount = %d, want 1", stats.ValidCount)
	}
	if stats.InvalidCount != 1 {
		t.Errorf("InvalidCount = %d, want 1", stats.InvalidCount)
	}
	if stats.NotFoundCount != 1 {
		t.Errorf("NotFoundCount = %d, want 1", stats.NotFoundCount)
	}
	if stats.ValidatorCount != 1 {
		t.Errorf("ValidatorCount = %d, want 1", stats.ValidatorCount)
	}
	if stats.ROACount != 1 {
		t.Errorf("ROACount = %d, want 1", stats.ROACount)
	}
}

// TestResetStats tests resetting statistics.
func TestResetStats(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{"validator:8282"}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	ctx := context.Background()
	if err := rv.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add a ROA and validate
	roa := &ROAEntry{
		Prefix:    netip.MustParsePrefix("192.0.2.0/24"),
		MaxLength: 24,
		ASN:       65001,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	rv.AddROA(roa)
	rv.ValidateRoute(netip.MustParsePrefix("192.0.2.0/24"), 65001)

	rv.ResetStats()

	stats := rv.GetValidationStats()
	if stats.ValidCount != 0 {
		t.Errorf("ValidCount = %d, want 0 after reset", stats.ValidCount)
	}
}

// TestFailOpenMode tests fail-open mode.
func TestFailOpenMode(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if rv.IsFailOpen() {
		t.Error("expected fail-open = false initially")
	}

	rv.SetFailOpen(true)

	if !rv.IsFailOpen() {
		t.Error("expected fail-open = true after setting")
	}

	rv.SetFailOpen(false)

	if rv.IsFailOpen() {
		t.Error("expected fail-open = false after unsetting")
	}
}

// TestSerialManagement tests serial number management.
func TestSerialManagement(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if rv.GetSerial() != 0 {
		t.Errorf("GetSerial() = %d, want 0 initially", rv.GetSerial())
	}

	rv.UpdateSerial(12345)

	if rv.GetSerial() != 12345 {
		t.Errorf("GetSerial() = %d, want 12345", rv.GetSerial())
	}

	updateTime := rv.LastUpdateTime()
	if updateTime.IsZero() {
		t.Error("LastUpdateTime() should not be zero after update")
	}
}

// TestValidatorCounts tests validator counting methods.
func TestValidatorCounts(t *testing.T) {
	t.Parallel()

	speaker := newMockRPKISpeaker()
	rv, err := NewRPKIValidator(speaker, []string{}, testLogger())
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	if rv.ValidatorCount() != 0 {
		t.Errorf("ValidatorCount() = %d, want 0", rv.ValidatorCount())
	}

	if rv.HasValidators() {
		t.Error("HasValidators() = true, want false")
	}

	ctx := context.Background()
	rv.Start(ctx)
	rv.AddValidator("validator1:8282")
	rv.AddValidator("validator2:8282")

	if rv.ValidatorCount() != 2 {
		t.Errorf("ValidatorCount() = %d, want 2", rv.ValidatorCount())
	}

	if !rv.HasValidators() {
		t.Error("HasValidators() = false, want true")
	}
}

// TestRPKIValidationStateString tests RPKIValidationState String method.
func TestRPKIValidationStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state RPKIValidationState
		want  string
	}{
		{RPKIStateNotFound, "NotFound"},
		{RPKIStateValid, "Valid"},
		{RPKIStateInvalid, "Invalid"},
		{RPKIStateUnknown, "Unknown"},
		{RPKIValidationState(255), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("RPKIValidationState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWithCacheTimeoutOption tests the option function.
func TestWithCacheTimeoutOption(t *testing.T) {
	t.Parallel()

	t.Run("valid timeout", func(t *testing.T) {
		t.Parallel()

		rv := &RPKIValidator{cacheTimeout: time.Hour}
		opt := WithCacheTimeout(2 * time.Hour)
		opt(rv)

		if rv.cacheTimeout != 2*time.Hour {
			t.Errorf("cacheTimeout = %v, want %v", rv.cacheTimeout, 2*time.Hour)
		}
	})

	t.Run("zero timeout", func(t *testing.T) {
		t.Parallel()

		rv := &RPKIValidator{cacheTimeout: time.Hour}
		opt := WithCacheTimeout(0)
		opt(rv)

		if rv.cacheTimeout != time.Hour {
			t.Errorf("cacheTimeout should not change for zero value")
		}
	})
}
