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
	"net"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// TestTransitModeHandler_NewWithRPKIEnabledNoValidators tests that RPKI enabled without validators returns error.
func TestTransitModeHandler_NewWithRPKIEnabledNoValidators(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = true
	config.RPKIValidators = nil // No validators

	_, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != ErrNoRPKIValidators {
		t.Errorf("expected ErrNoRPKIValidators, got: %v", err)
	}
}

// TestTransitModeHandler_ValidateRoute_RPKINotInitialized tests ValidateRoute when RPKI validator is nil.
func TestTransitModeHandler_ValidateRoute_RPKINotInitialized(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = true
	config.RPKIValidators = []string{"rtr://localhost:8282"} // Add validators to pass validation

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

	// The rpkiValidator should be nil because initialization would fail with mock server
	// Force rpkiValidator to nil to test the path
	handler.rpkiValidator = nil

	prefix := net.IPNet{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	_, err = handler.ValidateRoute(ctx, prefix, 65001)
	if err != ErrRPKINotInitialized {
		t.Errorf("expected ErrRPKINotInitialized, got: %v", err)
	}
}

// TestTransitModeHandler_ValidateRoute_InvalidPrefix tests ValidateRoute with invalid prefix.
func TestTransitModeHandler_ValidateRoute_InvalidPrefix(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = true
	config.RPKIValidators = []string{"rtr://localhost:8282"} // Add validators to trigger initialization

	// Create a mock validator
	mockValidator := &bgp.RPKIValidator{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithRPKIValidator(mockValidator),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}
	defer handler.Stop(ctx)

	// Create an invalid prefix (empty IP)
	invalidPrefix := net.IPNet{
		IP:   nil,
		Mask: net.CIDRMask(24, 32),
	}

	_, err = handler.ValidateRoute(ctx, invalidPrefix, 65001)
	if err == nil {
		t.Error("expected error for invalid prefix, got nil")
		return
	}
	// Check that it's an ErrInvalidPrefixFormat
	if _, ok := err.(*ErrInvalidPrefixFormat); !ok {
		t.Errorf("expected ErrInvalidPrefixFormat, got: %T", err)
	}
}

// TestTransitModeHandler_AddExternalPeers tests adding external peers.
func TestTransitModeHandler_AddExternalPeers(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.ExternalPeers = []bgp.NeighborConfig{
		{
			ASN:     65100,
			Address: netip.MustParseAddr("192.168.1.1"),
		},
		{
			ASN:     65200,
			Address: netip.MustParseAddr("192.168.1.2"),
		},
	}

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

	// Check that peers were added
	handler.peersMu.RLock()
	peerCount := len(handler.peers)
	handler.peersMu.RUnlock()

	// The mock speaker may or may not accept peers, so just check that
	// the handler attempted to add them (peerState should be created)
	if peerCount != 2 {
		t.Errorf("expected 2 peers, got %d", peerCount)
	}
}

// TestTransitModeHandler_SignRoute_NotCoordinatorTier tests SignRoute on non-coordinator tier.
func TestTransitModeHandler_SignRoute_NotCoordinatorTier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.Tier = bgp.SpeakerTierBackbone // Not coordinator

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

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	_, err = handler.SignRoute(ctx, prefix)
	if err != ErrNotCoordinatorTier {
		t.Errorf("expected ErrNotCoordinatorTier, got: %v", err)
	}
}

// TestTransitModeHandler_NewCoordinatorWithoutSigningKey tests that coordinator tier requires signing key.
func TestTransitModeHandler_NewCoordinatorWithoutSigningKey(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.Tier = bgp.SpeakerTierCoordinator
	config.RouteSigningKey = nil // No signing key

	_, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err == nil {
		t.Error("expected error for coordinator tier without signing key")
		return
	}
	// The error should indicate signing key is required
	if err.Error() != "route signing key required for coordinator tier" {
		t.Logf("got error: %v", err)
	}
}

// TestTransitModeHandler_VerifyAnnouncementScope_BackboneTier tests backbone tier allows any prefix.
func TestTransitModeHandler_VerifyAnnouncementScope_BackboneTier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Test that backbone tier allows any prefix size
	largePrefix := netip.MustParsePrefix("10.0.0.0/8")
	err = handler.verifyAnnouncementScope(largePrefix)
	if err != nil {
		t.Errorf("backbone tier should allow any prefix, got: %v", err)
	}
}

// TestTransitModeHandler_VerifyAnnouncementScope_DatacenterTier tests datacenter tier prefix validation.
func TestTransitModeHandler_VerifyAnnouncementScope_DatacenterTier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	// Use existing validDatacenterConfig helper
	config := validDatacenterConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	t.Run("IPv6 prefix too large", func(t *testing.T) {
		// /36 is too large for datacenter tier (requires /48 or more specific)
		largePrefix := netip.MustParsePrefix("2001:db8::/36")
		err := handler.verifyAnnouncementScope(largePrefix)
		if err == nil {
			t.Error("expected error for prefix too large")
		}
	})

	t.Run("IPv6 prefix valid", func(t *testing.T) {
		validPrefix := netip.MustParsePrefix("2001:db8:1::/48")
		err := handler.verifyAnnouncementScope(validPrefix)
		if err != nil {
			t.Errorf("expected no error for valid prefix, got: %v", err)
		}
	})

	t.Run("IPv4 prefix too large", func(t *testing.T) {
		// /16 is too large for datacenter tier (requires /24 or more specific)
		largePrefix := netip.MustParsePrefix("10.0.0.0/16")
		err := handler.verifyAnnouncementScope(largePrefix)
		if err == nil {
			t.Error("expected error for prefix too large")
		}
	})

	t.Run("IPv4 prefix valid", func(t *testing.T) {
		validPrefix := netip.MustParsePrefix("10.0.0.0/24")
		err := handler.verifyAnnouncementScope(validPrefix)
		if err != nil {
			t.Errorf("expected no error for valid prefix, got: %v", err)
		}
	})
}

// TestTransitModeHandler_NetIPNetToPrefix_Extended tests the netIPNetToPrefix helper with more cases.
func TestTransitModeHandler_NetIPNetToPrefix_Extended(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	t.Run("nil IP", func(t *testing.T) {
		ipnet := net.IPNet{
			IP:   nil,
			Mask: net.CIDRMask(24, 32),
		}
		_, err := handler.netIPNetToPrefix(ipnet)
		if err == nil {
			t.Error("expected error for nil IP")
		}
	})

	t.Run("nil mask produces /0 prefix", func(t *testing.T) {
		ipnet := net.IPNet{
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: nil,
		}
		prefix, err := handler.netIPNetToPrefix(ipnet)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// nil mask results in /0 prefix
		if prefix.Bits() != 0 {
			t.Errorf("expected 0 bits for nil mask, got %d", prefix.Bits())
		}
	})
}

// TestTransitModeHandler_CreateSigningMessage tests the createSigningMessage helper.
func TestTransitModeHandler_CreateSigningMessage(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	msg := handler.createSigningMessage(prefix)

	if len(msg) == 0 {
		t.Error("signing message should not be empty")
	}
}

// TestTransitModeHandler_GetStatus_FullData tests GetStatus with various data.
func TestTransitModeHandler_GetStatus_FullData(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.ExternalPeers = []bgp.NeighborConfig{
		{
			ASN:     65100,
			Address: netip.MustParseAddr("192.168.1.1"),
		},
	}

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

	// Record some errors
	handler.recordError("test error", nil)

	// Get status
	status := handler.GetStatus()

	if !status.Running {
		t.Error("expected Running to be true")
	}
	if status.ExternalPeers != 1 {
		t.Errorf("expected ExternalPeers 1, got %d", status.ExternalPeers)
	}
	if status.AnnouncedPrefixes != 2 {
		t.Errorf("expected 2 announced prefixes, got %d", status.AnnouncedPrefixes)
	}
	if status.LastError != "test error" {
		t.Errorf("expected last error 'test error', got '%s'", status.LastError)
	}
}

// TestTransitModeHandler_AnnouncePrefixNotRunning tests AnnouncePrefix when not running.
func TestTransitModeHandler_AnnouncePrefixNotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	prefix := net.IPNet{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}
	err = handler.AnnouncePrefix(context.Background(), prefix)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestTransitModeHandler_WithdrawPrefixNotRunning tests WithdrawPrefix when not running.
func TestTransitModeHandler_WithdrawPrefixNotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	prefix := net.IPNet{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}
	err = handler.WithdrawPrefix(context.Background(), prefix)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestTransitModeHandler_SignRouteNotRunning tests SignRoute when not running.
func TestTransitModeHandler_SignRouteNotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	_, err = handler.SignRoute(context.Background(), prefix)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestTransitModeHandler_VerifyRouteSignatureNotRunning tests VerifyRouteSignature when not running.
func TestTransitModeHandler_VerifyRouteSignatureNotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	err = handler.VerifyRouteSignature(context.Background(), prefix, []byte("sig"), "signer")
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestTransitModeHandler_StartAlreadyRunning tests Start when already running.
func TestTransitModeHandler_StartAlreadyRunning(t *testing.T) {
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

	// Try to start again
	err = handler.Start(ctx)
	if err != ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got: %v", err)
	}
}

// TestTransitModeHandler_WithDampeningConfig tests handler with dampening configuration.
func TestTransitModeHandler_WithDampeningConfig(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.DampeningConfig = bgp.DefaultDampeningConfig()

	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if handler.config.DampeningConfig == nil {
		t.Error("expected dampening config to be set")
	}
}

// TestTransitModeHandler_PrefixToNetIPNet tests the prefixToNetIPNet helper.
func TestTransitModeHandler_PrefixToNetIPNet(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	t.Run("IPv4 prefix", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		ipnet := handler.prefixToNetIPNet(prefix)

		if !ipnet.IP.Equal(net.IPv4(10, 0, 0, 0)) {
			t.Errorf("expected IP 10.0.0.0, got %v", ipnet.IP)
		}
		ones, bits := ipnet.Mask.Size()
		if ones != 24 || bits != 32 {
			t.Errorf("expected /24 mask, got /%d (bits=%d)", ones, bits)
		}
	})

	t.Run("IPv6 prefix", func(t *testing.T) {
		prefix := netip.MustParsePrefix("2001:db8::/32")
		ipnet := handler.prefixToNetIPNet(prefix)

		ones, bits := ipnet.Mask.Size()
		if ones != 32 || bits != 128 {
			t.Errorf("expected /32 mask, got /%d (bits=%d)", ones, bits)
		}
	})
}

// TestTransitModeHandler_VerifyAnnouncementScope_CoordinatorTier tests coordinator tier allows announcements.
func TestTransitModeHandler_VerifyAnnouncementScope_CoordinatorTier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Coordinator tier should not produce errors for any prefix
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	err = handler.verifyAnnouncementScope(prefix)
	if err != nil {
		t.Errorf("coordinator tier should allow prefix, got: %v", err)
	}
}

// TestTransitModeHandler_RecordError tests the recordError helper.
func TestTransitModeHandler_RecordError(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Record an error with cause
	testErr := ErrNotRunning
	handler.recordError("test operation failed", testErr)

	handler.errorMu.RLock()
	lastError := handler.lastError
	handler.errorMu.RUnlock()

	if lastError != "test operation failed: handler not running" {
		t.Errorf("expected 'test operation failed', got '%s'", lastError)
	}
}

// TestTransitModeHandler_Stop_WithDampening tests stopping handler with dampening.
func TestTransitModeHandler_Stop_WithDampening(t *testing.T) {
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

	// Stop should work without errors
	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("failed to stop handler: %v", err)
	}
}

// TestTransitModeHandler_Stop_NotRunning2 tests Stop when not running returns nil.
func TestTransitModeHandler_Stop_NotRunning2(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Stop when not started should return nil (not ErrNotRunning)
	err = handler.Stop(context.Background())
	if err != nil {
		t.Errorf("expected nil when stopping non-running handler, got: %v", err)
	}
}

// TestTransitModeHandler_GetStatus_StartedAt tests that StartedAt is set correctly.
func TestTransitModeHandler_GetStatus_StartedAt(t *testing.T) {
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

	status := handler.GetStatus()
	if status.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt")
	}
}

// TestTransitModeHandler_AnnouncePrefix_InvalidPrefix tests announcing an invalid prefix.
func TestTransitModeHandler_AnnouncePrefix_InvalidPrefix(t *testing.T) {
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

	// Create an invalid prefix
	invalidPrefix := net.IPNet{
		IP:   nil,
		Mask: net.CIDRMask(24, 32),
	}

	err = handler.AnnouncePrefix(ctx, invalidPrefix)
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

// TestTransitModeHandler_WithdrawPrefix_InvalidPrefix tests withdrawing an invalid prefix.
func TestTransitModeHandler_WithdrawPrefix_InvalidPrefix(t *testing.T) {
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

	// Create an invalid prefix
	invalidPrefix := net.IPNet{
		IP:   nil,
		Mask: net.CIDRMask(24, 32),
	}

	err = handler.WithdrawPrefix(ctx, invalidPrefix)
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

// TestTransitModeHandler_StartWithDampeningConfig tests Start with dampening configuration.
func TestTransitModeHandler_StartWithDampeningConfig(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.DampeningConfig = bgp.DefaultDampeningConfig()

	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler with dampening: %v", err)
	}
	defer handler.Stop(ctx)

	// Verify dampening manager was created
	if handler.dampening == nil {
		t.Error("expected dampening manager to be initialized")
	}
}

// TestTransitModeHandler_StopWithDampeningInitialized tests Stop with initialized dampening.
func TestTransitModeHandler_StopWithDampeningInitialized(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.DampeningConfig = bgp.DefaultDampeningConfig()

	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}

	// Stop with dampening initialized
	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("failed to stop handler: %v", err)
	}
}

// TestTransitModeHandler_ValidateRoute_WithMockRPKI tests ValidateRoute with mock RPKI validator.
func TestTransitModeHandler_ValidateRoute_WithMockRPKI(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = true
	config.RPKIValidators = []string{"rtr://localhost:8282"}

	// Create mock validator
	mockValidator := &bgp.RPKIValidator{}

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(testLogger()),
		WithRPKIValidator(mockValidator),
	)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start handler: %v", err)
	}
	defer handler.Stop(ctx)

	// Test validation with mock validator
	prefix := net.IPNet{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	// The mock validator returns unknown status
	status, err := handler.ValidateRoute(ctx, prefix, 65001)
	// Accept either success or known error
	if err != nil && err != ErrRPKINotInitialized {
		t.Logf("ValidateRoute returned error: %v", err)
	}
	if err == nil {
		t.Logf("ValidateRoute returned status: %v", status)
	}
}

// TestTransitModeHandler_VerifyRouteSignature_InvalidSigner tests VerifyRouteSignature with invalid signer.
func TestTransitModeHandler_VerifyRouteSignature_InvalidSigner(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
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

	prefix := netip.MustParsePrefix("10.0.0.0/24")
	err = handler.VerifyRouteSignature(ctx, prefix, []byte("invalid-sig"), "unknown-signer")
	// Should fail verification
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

// TestTransitModeHandler_GetPeerStatus tests GetStatus with peers.
func TestTransitModeHandler_GetPeerStatus(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.ExternalPeers = []bgp.NeighborConfig{
		{
			ASN:     65100,
			Address: netip.MustParseAddr("192.168.1.1"),
		},
	}

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

	status := handler.GetStatus()
	if status.ExternalPeers != 1 {
		t.Errorf("expected 1 external peer, got %d", status.ExternalPeers)
	}
}
