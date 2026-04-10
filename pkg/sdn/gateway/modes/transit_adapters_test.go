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

package modes

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// TestRPKISpeakerAdapter tests the rpkiSpeakerAdapter type.
func TestRPKISpeakerAdapter(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	adapter := &rpkiSpeakerAdapter{speaker: speaker}

	t.Run("IsStarted returns true when speaker is started", func(t *testing.T) {
		if !adapter.IsStarted() {
			t.Error("expected IsStarted() to return true when speaker is running")
		}
	})

	t.Run("GetASN returns speaker ASN", func(t *testing.T) {
		asn := adapter.GetASN()
		if asn != 65001 {
			t.Errorf("expected ASN 65001, got %d", asn)
		}
	})
}

// TestRPKISpeakerAdapter_NotStarted tests the adapter when speaker is not started.
func TestRPKISpeakerAdapter_NotStarted(t *testing.T) {
	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, err := bgp.NewSpeaker(config, testLogger(), bgp.WithBGPServer(mockServer))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}
	// Don't start the speaker

	adapter := &rpkiSpeakerAdapter{speaker: speaker}

	if adapter.IsStarted() {
		t.Error("expected IsStarted() to return false when speaker is not started")
	}
}

// TestDampeningSpeakerAdapter tests the dampeningSpeakerAdapter type.
func TestDampeningSpeakerAdapter(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	adapter := &dampeningSpeakerAdapter{speaker: speaker}

	t.Run("IsStarted returns true when speaker is started", func(t *testing.T) {
		if !adapter.IsStarted() {
			t.Error("expected IsStarted() to return true when speaker is running")
		}
	})

	t.Run("SuppressRoute returns nil", func(t *testing.T) {
		ctx := context.Background()
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := adapter.SuppressRoute(ctx, prefix)
		if err != nil {
			t.Errorf("expected no error from SuppressRoute, got: %v", err)
		}
	})

	t.Run("UnsuppressRoute returns nil", func(t *testing.T) {
		ctx := context.Background()
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := adapter.UnsuppressRoute(ctx, prefix)
		if err != nil {
			t.Errorf("expected no error from UnsuppressRoute, got: %v", err)
		}
	})
}

// TestDampeningSpeakerAdapter_NotStarted tests the adapter when speaker is not started.
func TestDampeningSpeakerAdapter_NotStarted(t *testing.T) {
	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, err := bgp.NewSpeaker(config, testLogger(), bgp.WithBGPServer(mockServer))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}
	// Don't start the speaker

	adapter := &dampeningSpeakerAdapter{speaker: speaker}

	if adapter.IsStarted() {
		t.Error("expected IsStarted() to return false when speaker is not started")
	}
}

// TestWithTransitManager tests the WithTransitManager option.
func TestWithTransitManager(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	// Create a mock transit manager
	tm := &bgp.TransitManager{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithTransitManager(tm),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if handler.transitManager != tm {
		t.Error("expected transit manager to be set")
	}
}

// TestWithRPKIValidator tests the WithRPKIValidator option.
func TestWithRPKIValidator(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	// Create a mock RPKI validator
	rv := &bgp.RPKIValidator{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithRPKIValidator(rv),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if handler.rpkiValidator != rv {
		t.Error("expected RPKI validator to be set")
	}
}

// TestWithDampeningManager tests the WithDampeningManager option.
func TestWithDampeningManager(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	// Create a mock dampening manager
	dm := &bgp.DampeningManager{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithDampeningManager(dm),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if handler.dampening != dm {
		t.Error("expected dampening manager to be set")
	}
}

// TestWithAllTransitOptions tests applying all options together.
func TestWithAllTransitOptions(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	tm := &bgp.TransitManager{}
	rv := &bgp.RPKIValidator{}
	dm := &bgp.DampeningManager{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithTransitManager(tm),
		WithRPKIValidator(rv),
		WithDampeningManager(dm),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if handler.transitManager != tm {
		t.Error("expected transit manager to be set")
	}
	if handler.rpkiValidator != rv {
		t.Error("expected RPKI validator to be set")
	}
	if handler.dampening != dm {
		t.Error("expected dampening manager to be set")
	}
}

// TestTransitModeHandler_RecordErrorWithNilError tests recordError with nil error.
func TestTransitModeHandler_RecordErrorWithNilError(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}
	defer handler.Stop(ctx)

	// Record an error with nil cause
	handler.recordError("test message", nil)

	status := handler.GetStatus()
	if status.LastError != "test message" {
		t.Errorf("expected last error 'test message', got %s", status.LastError)
	}
}

// TestTransitModeHandler_GetRouteVerificationCount_NotFound tests GetRouteVerificationCount for unknown prefix.
func TestTransitModeHandler_GetRouteVerificationCount_NotFound(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("192.168.0.0/24")
	count := handler.GetRouteVerificationCount(prefix)
	if count != 0 {
		t.Errorf("expected 0 verifiers for unknown prefix, got: %d", count)
	}
}

// TestTransitModeHandler_RecordRouteVerification_DuplicateVerifier tests duplicate verifier handling.
func TestTransitModeHandler_RecordRouteVerification_DuplicateVerifier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.MinGatewaysForRoute = 3
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("192.168.0.0/24")

	// Record same verifier multiple times
	handler.recordRouteVerification(prefix, "gateway-1")
	handler.recordRouteVerification(prefix, "gateway-1")
	handler.recordRouteVerification(prefix, "gateway-1")

	// Should only count as 1 unique verifier
	count := handler.GetRouteVerificationCount(prefix)
	if count != 1 {
		t.Errorf("expected 1 unique verifier, got: %d", count)
	}

	// Should not be verified (need 3 unique verifiers)
	if handler.IsRouteVerified(prefix) {
		t.Error("expected route to not be verified with only 1 unique verifier")
	}
}
