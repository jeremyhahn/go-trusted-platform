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
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// TestSentinelErrors_TransitMode tests all transit mode sentinel error types.
func TestSentinelErrors_TransitMode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrConfigNil", ErrConfigNil, "configuration is nil"},
		{"ErrSpeakerNil", ErrSpeakerNil, "BGP speaker is nil"},
		{"ErrAlreadyRunning", ErrAlreadyRunning, "handler already running"},
		{"ErrNotRunning", ErrNotRunning, "handler not running"},
		{"ErrInvalidTier", ErrInvalidTier, "invalid speaker tier"},
		{"ErrNoPrefixesConfigured", ErrNoPrefixesConfigured, "no prefixes configured for announcement"},
		{"ErrInvalidIPv6Prefix", ErrInvalidIPv6Prefix, "invalid IPv6 prefix"},
		{"ErrInvalidIPv4Prefix", ErrInvalidIPv4Prefix, "invalid IPv4 prefix"},
		{"ErrInvalidASN", ErrInvalidASN, "invalid ASN: must be non-zero"},
		{"ErrNoRPKIValidators", ErrNoRPKIValidators, "RPKI enabled but no validators configured"},
		{"ErrSigningKeyRequired", ErrSigningKeyRequired, "route signing key required for coordinator tier"},
		{"ErrInvalidMinGateways", ErrInvalidMinGateways, "MinGatewaysForRoute cannot be negative"},
		{"ErrNotCoordinatorTier", ErrNotCoordinatorTier, "route signing only available on coordinator tier"},
		{"ErrSigningKeyNotConfigured", ErrSigningKeyNotConfigured, "route signing key not configured"},
		{"ErrEmptySignature", ErrEmptySignature, "signature is empty"},
		{"ErrEmptySignerID", ErrEmptySignerID, "signer ID is empty"},
		{"ErrRPKINotInitialized", ErrRPKINotInitialized, "RPKI validator not initialized"},
		{"ErrInvalidIPAddress", ErrInvalidIPAddress, "invalid IP address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

// TestSentinelErrors_EdgeMode tests all edge mode sentinel error types.
func TestSentinelErrors_EdgeMode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidIPv6Pool", ErrInvalidIPv6Pool, "invalid IPv6 pool"},
		{"ErrInvalidIPv6Address", ErrInvalidIPv6Address, "invalid IPv6 address"},
		{"ErrIPv6PoolExhausted", ErrIPv6PoolExhausted, "IPv6 pool exhausted"},
		{"ErrIPv6AllocationFailed", ErrIPv6AllocationFailed, "IPv6 allocation failed"},
		{"ErrIPv6AlreadyAllocated", ErrIPv6AlreadyAllocated, "IPv6 address already allocated"},
		{"ErrIPv6OutOfPool", ErrIPv6OutOfPool, "IPv6 address outside pool"},
		{"ErrIPv6NotAllocated", ErrIPv6NotAllocated, "IPv6 address not allocated"},
		{"ErrDeviceIDRequired", ErrDeviceIDRequired, "device ID required"},
		{"ErrNodeIDRequired", ErrNodeIDRequired, "node ID required"},
		{"ErrPeerIDRequired", ErrPeerIDRequired, "peer ID required"},
		{"ErrRequestNil", ErrRequestNil, "request is nil"},
		{"ErrTPMEKRequired", ErrTPMEKRequired, "TPM endorsement key required"},
		{"ErrTPMQuoteRequired", ErrTPMQuoteRequired, "TPM quote required"},
		{"ErrFROSTPoolRequired", ErrFROSTPoolRequired, "FROST pool ID required for ACME enrollment"},
		{"ErrRateLimitExceeded", ErrRateLimitExceeded, "rate limit exceeded"},
		{"ErrP2PNotEnabled", ErrP2PNotEnabled, "gateway: P2P support not enabled (build with -tags platform_p2p)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

// TestSentinelErrors_OverlayMode tests all overlay mode sentinel error types.
func TestSentinelErrors_OverlayMode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrVTEPConfigNil", ErrVTEPConfigNil, "VTEP configuration is nil"},
		{"ErrBridgeNameEmpty", ErrBridgeNameEmpty, "bridge name is empty"},
		{"ErrLoggerNil", ErrLoggerNil, "logger is nil"},
		{"ErrOVSClientNil", ErrOVSClientNil, "OVS client is nil"},
		{"ErrOpenFlowClientNil", ErrOpenFlowClientNil, "OpenFlow client is nil"},
		{"ErrVNIOutOfRange", ErrVNIOutOfRange, "VNI must be between 1 and 16777215"},
		{"ErrVLANOutOfRange", ErrVLANOutOfRange, "VLAN ID must be between 0 and 4094"},
		{"ErrVNIAlreadyExists", ErrVNIAlreadyExists, "VNI already exists"},
		{"ErrVNINotFound", ErrVNINotFound, "VNI not found"},
		{"ErrMACNil", ErrMACNil, "MAC address is nil"},
		{"ErrMACInvalid", ErrMACInvalid, "MAC address must be 6 bytes"},
		{"ErrMACNotFound", ErrMACNotFound, "MAC address not found"},
		{"ErrARPPacketNil", ErrARPPacketNil, "ARP packet is nil"},
		{"ErrInvalidVTEPIP", ErrInvalidVTEPIP, "invalid VTEP IP address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

// TestContextualErrors_TransitMode tests transit mode contextual error types.
func TestContextualErrors_TransitMode(t *testing.T) {
	t.Run("ErrComponentInitFailed with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrComponentInitFailed{Component: "rpki_validator", Cause: cause}
		if got := err.Error(); got != "failed to initialize rpki_validator: underlying error" {
			t.Errorf("Error() = %q, want contains 'rpki_validator' and 'underlying error'", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrComponentInitFailed without cause", func(t *testing.T) {
		err := &ErrComponentInitFailed{Component: "evpn"}
		if got := err.Error(); got != "failed to initialize evpn" {
			t.Errorf("Error() = %q, want 'failed to initialize evpn'", got)
		}
	})

	t.Run("ErrInvalidPrefixFormat with cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := &ErrInvalidPrefixFormat{Prefix: "invalid", Cause: cause}
		if got := err.Error(); got != `invalid prefix format "invalid": parse error` {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrInvalidPrefixFormat without cause", func(t *testing.T) {
		err := &ErrInvalidPrefixFormat{Prefix: "bad"}
		if got := err.Error(); got != `invalid prefix format "bad"` {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrPrefixAlreadyAnnounced", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrPrefixAlreadyAnnounced{Prefix: prefix}
		if got := err.Error(); got != "prefix 10.0.0.0/24 already announced" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrPrefixNotAnnounced", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrPrefixNotAnnounced{Prefix: prefix}
		if got := err.Error(); got != "prefix 10.0.0.0/24 not announced" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrAnnounceFailed with cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		cause := errors.New("speaker error")
		err := &ErrAnnounceFailed{Prefix: prefix, Cause: cause}
		if got := err.Error(); got != "failed to announce prefix 10.0.0.0/24: speaker error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrAnnounceFailed without cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrAnnounceFailed{Prefix: prefix}
		if got := err.Error(); got != "failed to announce prefix 10.0.0.0/24" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrWithdrawFailed with cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		cause := errors.New("withdraw error")
		err := &ErrWithdrawFailed{Prefix: prefix, Cause: cause}
		if got := err.Error(); got != "failed to withdraw prefix 10.0.0.0/24: withdraw error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrWithdrawFailed without cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrWithdrawFailed{Prefix: prefix}
		if got := err.Error(); got != "failed to withdraw prefix 10.0.0.0/24" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrPrefixTooLarge", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/8")
		err := &ErrPrefixTooLarge{Prefix: prefix, MaxBits: 24, Tier: bgp.SpeakerTierDatacenter}
		if got := err.Error(); got != "prefix 10.0.0.0/8 too large for tier datacenter (max /24)" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrRPKIValidationFailed with cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		cause := errors.New("validator error")
		err := &ErrRPKIValidationFailed{Prefix: prefix, Cause: cause}
		if got := err.Error(); got != "RPKI validation failed for prefix 10.0.0.0/24: validator error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrRPKIValidationFailed without cause", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrRPKIValidationFailed{Prefix: prefix}
		if got := err.Error(); got != "RPKI validation failed for prefix 10.0.0.0/24" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrSignerNotFound", func(t *testing.T) {
		err := ErrSignerNotFound{SignerID: "signer-001"}
		if got := err.Error(); got != "signer not found: signer-001" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrSignatureInvalid", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		err := &ErrSignatureInvalid{Prefix: prefix, SignerID: "signer-001"}
		if got := err.Error(); got != "invalid signature for prefix 10.0.0.0/24 from signer signer-001" {
			t.Errorf("Error() = %q", got)
		}
	})
}

// TestContextualErrors_EdgeMode tests edge mode contextual error types.
func TestContextualErrors_EdgeMode(t *testing.T) {
	t.Run("ErrStartFailed", func(t *testing.T) {
		cause := errors.New("start error")
		err := &ErrStartFailed{Component: "allocator", Cause: cause}
		if got := err.Error(); got != "failed to start allocator: start error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrStopFailed", func(t *testing.T) {
		cause := errors.New("stop error")
		err := &ErrStopFailed{Component: "limiter", Cause: cause}
		if got := err.Error(); got != "failed to stop limiter: stop error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrMultipleFailures empty", func(t *testing.T) {
		err := &ErrMultipleFailures{}
		if got := err.Error(); got != "multiple failures occurred" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrMultipleFailures single", func(t *testing.T) {
		err := &ErrMultipleFailures{Errors: []error{errors.New("single")}}
		if got := err.Error(); got != "single" {
			t.Errorf("Error() = %q, want 'single'", got)
		}
	})

	t.Run("ErrMultipleFailures multiple", func(t *testing.T) {
		err := &ErrMultipleFailures{Errors: []error{
			errors.New("first"),
			errors.New("second"),
			errors.New("third"),
		}}
		got := err.Error()
		if got != "multiple failures: first; second; third" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrOnboardingFailed", func(t *testing.T) {
		cause := errors.New("validation error")
		err := &ErrOnboardingFailed{Step: "tpm_validation", Cause: cause}
		if got := err.Error(); got != `onboarding failed at step "tpm_validation": validation error` {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrTPMValidationFailed", func(t *testing.T) {
		err := &ErrTPMValidationFailed{Reason: "invalid quote"}
		if got := err.Error(); got != "TPM validation failed: invalid quote" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrIDevIDIssuanceFailed", func(t *testing.T) {
		cause := errors.New("signing error")
		err := &ErrIDevIDIssuanceFailed{DeviceID: "device-001", Cause: cause}
		if got := err.Error(); got != "failed to issue IDevID for device device-001: signing error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrDHTRegistrationFailed", func(t *testing.T) {
		cause := errors.New("dht error")
		err := &ErrDHTRegistrationFailed{DeviceID: "device-002", Cause: cause}
		if got := err.Error(); got != "failed to register device device-002 in DHT: dht error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrIPv6AllocationError with IP", func(t *testing.T) {
		err := &ErrIPv6AllocationError{DeviceID: "dev", IP: "::1", Reason: "already allocated"}
		if got := err.Error(); got != "IPv6 allocation error for device dev (IP ::1): already allocated" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrIPv6AllocationError without IP", func(t *testing.T) {
		err := &ErrIPv6AllocationError{DeviceID: "dev", Reason: "pool exhausted"}
		if got := err.Error(); got != "IPv6 allocation error for device dev: pool exhausted" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrRateLimitError", func(t *testing.T) {
		err := &ErrRateLimitError{PeerID: "peer-123", Reputation: 0.45, Limit: 10}
		got := err.Error()
		if got != "rate limit exceeded for peer peer-123 (reputation: 0.45, limit: 10 req/s)" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrACMEChallengeFailed", func(t *testing.T) {
		err := &ErrACMEChallengeFailed{ChallengeType: "endorse-01", DeviceID: "dev-001", Reason: "invalid EK"}
		if got := err.Error(); got != "ACME endorse-01 challenge failed for device dev-001: invalid EK" {
			t.Errorf("Error() = %q", got)
		}
	})

	t.Run("ErrNATTraversalFailed", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrNATTraversalFailed{Method: "ICE", Cause: cause}
		if got := err.Error(); got != "NAT traversal via ICE failed: timeout" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})
}

// TestContextualErrors_OverlayMode tests overlay mode contextual error types.
func TestContextualErrors_OverlayMode(t *testing.T) {
	t.Run("ErrOverlayInitFailed", func(t *testing.T) {
		cause := errors.New("vtep error")
		err := &ErrOverlayInitFailed{Component: "VTEPManager", Cause: cause}
		if got := err.Error(); got != "overlay initialization failed for VTEPManager: vtep error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrOverlayStartFailed", func(t *testing.T) {
		cause := errors.New("start error")
		err := &ErrOverlayStartFailed{Component: "EVPNManager", Cause: cause}
		if got := err.Error(); got != "overlay start failed for EVPNManager: start error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrVNIOperationFailed", func(t *testing.T) {
		cause := errors.New("flow error")
		err := &ErrVNIOperationFailed{VNI: 1000, Operation: "add", Cause: cause}
		if got := err.Error(); got != "VNI 1000 add failed: flow error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrMACOperationFailed", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		cause := errors.New("mac error")
		err := &ErrMACOperationFailed{MAC: mac, Operation: "learn", Cause: cause}
		if got := err.Error(); got != "MAC aa:bb:cc:dd:ee:ff learn failed: mac error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrVTEPOperationFailed", func(t *testing.T) {
		vtepIP := netip.MustParseAddr("10.0.0.2")
		cause := errors.New("tunnel error")
		err := &ErrVTEPOperationFailed{VTEPIP: vtepIP, Operation: "add-tunnel", Cause: cause}
		if got := err.Error(); got != "VTEP 10.0.0.2 add-tunnel failed: tunnel error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrFlowOperationFailed", func(t *testing.T) {
		cause := errors.New("openflow error")
		err := &ErrFlowOperationFailed{Table: 30, Operation: "install", Cause: cause}
		if got := err.Error(); got != "flow install on table 30 failed: openflow error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})
}
