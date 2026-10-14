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
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrSpeakerNil(t *testing.T) {
	// ErrSpeakerNil is a sentinel error
	err := ErrSpeakerNil
	assert.Equal(t, "BGP speaker is nil", err.Error())
}

func TestErrLoggerNil(t *testing.T) {
	// ErrLoggerNil is a sentinel error
	err := ErrLoggerNil
	assert.Equal(t, "logger is nil", err.Error())
}

func TestErrInvalidRouteDistinguisher(t *testing.T) {
	t.Run("with RD", func(t *testing.T) {
		err := ErrInvalidRouteDistinguisher{RD: "65000:100", Reason: "invalid format"}
		assert.Contains(t, err.Error(), "65000:100")
		assert.Contains(t, err.Error(), "invalid format")
	})

	t.Run("without RD", func(t *testing.T) {
		err := ErrInvalidRouteDistinguisher{Reason: "empty RD"}
		assert.Contains(t, err.Error(), "empty RD")
	})
}

func TestErrRouteTargetInvalid(t *testing.T) {
	t.Run("with RT", func(t *testing.T) {
		err := ErrRouteTargetInvalid{RT: "65000:100", Reason: "invalid format"}
		assert.Contains(t, err.Error(), "65000:100")
		assert.Contains(t, err.Error(), "invalid format")
	})

	t.Run("without RT", func(t *testing.T) {
		err := ErrRouteTargetInvalid{Reason: "empty RT"}
		assert.Contains(t, err.Error(), "empty RT")
	})
}

func TestErrInvalidVNI(t *testing.T) {
	err := ErrInvalidVNI{VNI: 0, Reason: "must be between 1 and 16777215"}
	assert.Contains(t, err.Error(), "0")
	assert.Contains(t, err.Error(), "must be between 1 and 16777215")
}

func TestErrInvalidMAC(t *testing.T) {
	t.Run("with MAC", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err := ErrInvalidMAC{MAC: mac, Reason: "invalid length"}
		assert.Contains(t, err.Error(), "00:11:22:33:44:55")
	})

	t.Run("nil MAC", func(t *testing.T) {
		err := ErrInvalidMAC{MAC: nil, Reason: "MAC is nil"}
		assert.Contains(t, err.Error(), "MAC is nil")
	})
}

func TestErrInvalidIP(t *testing.T) {
	t.Run("with IP", func(t *testing.T) {
		ip := netip.MustParseAddr("192.168.1.1")
		err := ErrInvalidIP{IP: ip, Reason: "unspecified"}
		assert.Contains(t, err.Error(), "192.168.1.1")
	})

	t.Run("invalid IP", func(t *testing.T) {
		err := ErrInvalidIP{IP: netip.Addr{}, Reason: "not valid"}
		assert.Contains(t, err.Error(), "not valid")
	})
}

func TestErrPrefixInvalid(t *testing.T) {
	t.Run("with prefix", func(t *testing.T) {
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		err := ErrPrefixInvalid{Prefix: prefix, Reason: "overlaps"}
		assert.Contains(t, err.Error(), "192.168.1.0/24")
	})

	t.Run("invalid prefix", func(t *testing.T) {
		err := ErrPrefixInvalid{Prefix: netip.Prefix{}, Reason: "not valid"}
		assert.Contains(t, err.Error(), "not valid")
	})
}

func TestErrMACNotFound(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	err := ErrMACNotFound{VNI: 100, MAC: mac}
	assert.Contains(t, err.Error(), "100")
	assert.Contains(t, err.Error(), "00:11:22:33:44:55")
}

func TestErrMACIPNotFound(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := netip.MustParseAddr("192.168.1.100")
	err := ErrMACIPNotFound{VNI: 100, MAC: mac, IP: ip}
	assert.Contains(t, err.Error(), "100")
	assert.Contains(t, err.Error(), "00:11:22:33:44:55")
	assert.Contains(t, err.Error(), "192.168.1.100")
}

func TestErrIMETNotFound(t *testing.T) {
	err := ErrIMETNotFound{VNI: 100}
	assert.Contains(t, err.Error(), "100")
}

func TestErrPrefixNotFound(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.1.0/24")
	err := ErrPrefixNotFound{VNI: 100, Prefix: prefix}
	assert.Contains(t, err.Error(), "100")
	assert.Contains(t, err.Error(), "192.168.1.0/24")
}

func TestErrRouteEncodingFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: assert.AnError}
		assert.Contains(t, err.Error(), "mac-ip-advertisement")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement}
		assert.Contains(t, err.Error(), "mac-ip-advertisement")
	})
}

func TestErrRouteDecodingFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrRouteDecodingFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: assert.AnError}
		assert.Contains(t, err.Error(), "inclusive-multicast")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrRouteDecodingFailed{RouteType: EVPNTypeInclusiveMulticast}
		assert.Contains(t, err.Error(), "inclusive-multicast")
	})
}

func TestErrRouteAdvertisementFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrRouteAdvertisementFailed{RouteType: EVPNTypeIPPrefix, Cause: assert.AnError}
		assert.Contains(t, err.Error(), "ip-prefix")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrRouteAdvertisementFailed{RouteType: EVPNTypeIPPrefix}
		assert.Contains(t, err.Error(), "ip-prefix")
	})
}

func TestErrRouteWithdrawalFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrRouteWithdrawalFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: assert.AnError}
		assert.Contains(t, err.Error(), "mac-ip-advertisement")
		assert.Equal(t, assert.AnError, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrRouteWithdrawalFailed{RouteType: EVPNTypeMACIPAdvertisement}
		assert.Contains(t, err.Error(), "mac-ip-advertisement")
	})
}

func TestErrInvalidEVPNRoute(t *testing.T) {
	err := ErrInvalidEVPNRoute{RouteType: EVPNTypeMACIPAdvertisement, Reason: "missing MAC"}
	assert.Contains(t, err.Error(), "mac-ip-advertisement")
	assert.Contains(t, err.Error(), "missing MAC")
}

func TestErrMACMobilityConflict(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	err := ErrMACMobilityConflict{
		VNI:         100,
		MAC:         mac,
		OldVTEP:     netip.MustParseAddr("10.0.0.1"),
		NewVTEP:     netip.MustParseAddr("10.0.0.2"),
		OldSequence: 1,
		NewSequence: 0,
	}
	assert.Contains(t, err.Error(), "100")
	assert.Contains(t, err.Error(), "00:11:22:33:44:55")
	assert.Contains(t, err.Error(), "10.0.0.1")
	assert.Contains(t, err.Error(), "10.0.0.2")
}

func TestErrUnsupportedRouteType(t *testing.T) {
	err := ErrUnsupportedRouteType{RouteType: EVPNRouteType(99)}
	assert.Contains(t, err.Error(), "unknown")
}

func TestErrNLRITooShort(t *testing.T) {
	err := ErrNLRITooShort{Expected: 10, Actual: 5}
	assert.Contains(t, err.Error(), "10")
	assert.Contains(t, err.Error(), "5")
}

func TestErrInvalidNLRI(t *testing.T) {
	err := ErrInvalidNLRI{Reason: "malformed data"}
	assert.Contains(t, err.Error(), "malformed data")
}

func TestErrEntryNil(t *testing.T) {
	err := ErrEntryNil{EntryType: "MACIPEntry"}
	assert.Contains(t, err.Error(), "MACIPEntry")
}

func TestErrManagerNotStarted(t *testing.T) {
	// ErrManagerNotStarted is a sentinel error
	err := ErrManagerNotStarted
	assert.Equal(t, "EVPN manager not started", err.Error())
}

func TestErrManagerAlreadyStarted(t *testing.T) {
	// ErrManagerAlreadyStarted is a sentinel error
	err := ErrManagerAlreadyStarted
	assert.Equal(t, "EVPN manager already started", err.Error())
}

// Test all remaining sentinel errors
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrSpeakerNotStarted", ErrSpeakerNotStarted, "BGP speaker not started"},
		{"ErrSpeakerAlreadyRunning", ErrSpeakerAlreadyRunning, "BGP speaker already running"},
		{"ErrInvalidRouterID", ErrInvalidRouterID, "invalid router ID"},
		{"ErrInvalidASN", ErrInvalidASN, "invalid AS number"},
		{"ErrInvalidPeerASN", ErrInvalidPeerASN, "invalid peer AS number"},
		{"ErrInvalidHoldTime", ErrInvalidHoldTime, "invalid hold time (minimum 3 seconds)"},
		{"ErrPeerNotFound", ErrPeerNotFound, "peer not found"},
		{"ErrPeerAlreadyExists", ErrPeerAlreadyExists, "peer already exists"},
		{"ErrConfigNil", ErrConfigNil, "configuration is nil"},
		{"ErrServerNil", ErrServerNil, "BGP server is nil"},
		{"ErrShutdownTimeout", ErrShutdownTimeout, "shutdown timeout exceeded"},
		{"ErrSessionNotEstablished", ErrSessionNotEstablished, "BGP session not established"},
		{"ErrSessionFailed", ErrSessionFailed, "BGP session failed"},
		{"ErrRPKIValidationFailed", ErrRPKIValidationFailed, "RPKI validation failed"},
		{"ErrRouteRejected", ErrRouteRejected, "route rejected by policy"},
		{"ErrDampeningActive", ErrDampeningActive, "route dampening active"},
		{"ErrInvalidPrefix", ErrInvalidPrefix, "invalid IP prefix"},
		{"ErrInvalidRouteTarget", ErrInvalidRouteTarget, "invalid route target"},
		{"ErrConfigurationInvalid", ErrConfigurationInvalid, "invalid configuration"},
		{"ErrIPv6Required", ErrIPv6Required, "IPv6 prefix required"},
		{"ErrIPv4Required", ErrIPv4Required, "IPv4 prefix required"},
		{"ErrPrefixNotAnnounced", ErrPrefixNotAnnounced, "prefix not announced"},
		{"ErrInvalidASPathPrepend", ErrInvalidASPathPrepend, "invalid AS path prepend count"},
		{"ErrInvalidSpeakerTier", ErrInvalidSpeakerTier, "invalid speaker tier"},
		{"ErrInvalidRemoteAS", ErrInvalidRemoteAS, "invalid remote AS number"},
		{"ErrInvalidPeerType", ErrInvalidPeerType, "invalid peer type"},
		{"ErrInvalidPeerConfig", ErrInvalidPeerConfig, "invalid peer configuration"},
		{"ErrHealthMonitorAlreadyRunning", ErrHealthMonitorAlreadyRunning, "health monitor already running"},
		{"ErrNoValidatorsAvailable", ErrNoValidatorsAvailable, "no RPKI validators available"},
		{"ErrInvalidOriginAS", ErrInvalidOriginAS, "invalid origin AS number"},
		{"ErrInvalidValidatorAddress", ErrInvalidValidatorAddress, "invalid validator address"},
		{"ErrValidatorExists", ErrValidatorExists, "validator already exists"},
		{"ErrValidatorNotFound", ErrValidatorNotFound, "validator not found"},
		{"ErrInvalidROA", ErrInvalidROA, "invalid ROA"},
		{"ErrROANotFound", ErrROANotFound, "ROA not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// Test additional sentinel errors for dampening
func TestDampeningSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidHalfLife", ErrInvalidHalfLife, "invalid half-life value"},
		{"ErrInvalidReuseThreshold", ErrInvalidReuseThreshold, "invalid reuse threshold"},
		{"ErrInvalidSuppressThreshold", ErrInvalidSuppressThreshold, "invalid suppress threshold"},
		{"ErrReuseExceedsSuppressThreshold", ErrReuseExceedsSuppressThreshold, "reuse threshold must be less than suppress threshold"},
		{"ErrInvalidMaxSuppressTime", ErrInvalidMaxSuppressTime, "invalid max suppress time"},
		{"ErrInvalidFlapPenalty", ErrInvalidFlapPenalty, "invalid flap penalty"},
		{"ErrDampeningStateNotFound", ErrDampeningStateNotFound, "dampening state not found"},
		{"ErrDecayTimerAlreadyRunning", ErrDecayTimerAlreadyRunning, "decay timer already running"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// Test ErrPeerOperationFailed error type
func TestErrPeerOperationFailed(t *testing.T) {
	cause := errors.New("connection refused")
	err := &ErrPeerOperationFailed{
		Operation:   "add",
		PeerAddress: netip.MustParseAddr("10.0.0.1"),
		Cause:       cause,
	}

	assert.Contains(t, err.Error(), "10.0.0.1")
	assert.Contains(t, err.Error(), "add")
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrPathOperationFailed error type
func TestErrPathOperationFailed(t *testing.T) {
	cause := errors.New("invalid path")
	err := &ErrPathOperationFailed{
		Operation: "announce",
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		Cause:     cause,
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "announce")
	assert.Contains(t, err.Error(), "invalid path")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrServerOperationFailed error type
func TestErrServerOperationFailed(t *testing.T) {
	cause := errors.New("server down")
	err := &ErrServerOperationFailed{
		Operation: "start",
		Cause:     cause,
	}

	assert.Contains(t, err.Error(), "start")
	assert.Contains(t, err.Error(), "server down")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrRIBQueryFailed error type
func TestErrRIBQueryFailed(t *testing.T) {
	cause := errors.New("query timeout")
	err := &ErrRIBQueryFailed{
		Family:  AFamilyIPv4Unicast,
		RIBType: RIBLocal,
		Cause:   cause,
	}

	assert.Contains(t, err.Error(), "ipv4-unicast")
	assert.Contains(t, err.Error(), "local")
	assert.Contains(t, err.Error(), "query timeout")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrRPKIValidation error type
func TestErrRPKIValidation(t *testing.T) {
	err := ErrRPKIValidation{
		Prefix: netip.MustParsePrefix("192.168.1.0/24"),
		ASN:    65000,
		State:  RPKIStateInvalid,
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "65000")
	// State.String() returns "Invalid" (PascalCase)
	assert.Contains(t, err.Error(), "Invalid")
}

// Test ErrRouteDampened error type
func TestErrRouteDampened(t *testing.T) {
	err := ErrRouteDampened{
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		Penalty:   2500,
		ReuseTime: "5m30s",
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "2500")
	assert.Contains(t, err.Error(), "5m30s")
}

// Test ErrSpeakerOperationFailed error type
func TestErrSpeakerOperationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := ErrSpeakerOperationFailed{
			Operation: "configure",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "configure")
		assert.Contains(t, err.Error(), "timeout")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSpeakerOperationFailed{
			Operation: "configure",
		}

		assert.Contains(t, err.Error(), "configure")
		assert.Nil(t, err.Unwrap())
	})
}

// Test ErrConfigValidationFailed error type
func TestErrConfigValidationFailed(t *testing.T) {
	t.Run("with value", func(t *testing.T) {
		err := ErrConfigValidationFailed{
			Field:  "HoldTime",
			Value:  "1",
			Reason: "must be at least 3 seconds",
		}

		assert.Contains(t, err.Error(), "HoldTime")
		assert.Contains(t, err.Error(), "1")
		assert.Contains(t, err.Error(), "must be at least 3 seconds")
	})

	t.Run("without value", func(t *testing.T) {
		err := ErrConfigValidationFailed{
			Field:  "RouterID",
			Reason: "must be specified",
		}

		assert.Contains(t, err.Error(), "RouterID")
		assert.Contains(t, err.Error(), "must be specified")
	})
}

// Test ErrSessionEstablishmentFailed error type
func TestErrSessionEstablishmentFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection reset")
		err := ErrSessionEstablishmentFailed{
			PeerAddress: netip.MustParseAddr("10.0.0.1"),
			State:       PeerStateActive,
			Cause:       cause,
		}

		assert.Contains(t, err.Error(), "10.0.0.1")
		// State.String() returns "Active" (PascalCase)
		assert.Contains(t, err.Error(), "Active")
		assert.Contains(t, err.Error(), "connection reset")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrSessionEstablishmentFailed{
			PeerAddress: netip.MustParseAddr("10.0.0.1"),
			State:       PeerStateIdle,
		}

		assert.Contains(t, err.Error(), "10.0.0.1")
		// State.String() returns "Idle" (PascalCase)
		assert.Contains(t, err.Error(), "Idle")
		assert.Nil(t, err.Unwrap())
	})
}

// Test ErrPrefixAlreadyAnnounced error type
func TestErrPrefixAlreadyAnnounced(t *testing.T) {
	err := &ErrPrefixAlreadyAnnounced{
		Prefix: netip.MustParsePrefix("192.168.1.0/24"),
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "already announced")
}

// Test ErrAnnouncementFailed error type
func TestErrAnnouncementFailed(t *testing.T) {
	cause := errors.New("speaker error")
	err := &ErrAnnouncementFailed{
		Prefix: netip.MustParsePrefix("192.168.1.0/24"),
		Cause:  cause,
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "speaker error")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrWithdrawalFailed error type
func TestErrWithdrawalFailed(t *testing.T) {
	cause := errors.New("path not found")
	err := &ErrWithdrawalFailed{
		Prefix: netip.MustParsePrefix("192.168.1.0/24"),
		Cause:  cause,
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "path not found")
	assert.Equal(t, cause, err.Unwrap())
}

// Test ErrPeerExists error type
func TestErrPeerExists(t *testing.T) {
	err := &ErrPeerExists{
		Address: netip.MustParseAddr("10.0.0.1"),
	}

	assert.Contains(t, err.Error(), "10.0.0.1")
	assert.Contains(t, err.Error(), "already exists")
}

// TestErrAuthTypeUnavailableInFIPS_NamesWhatWorks pins the operator hint to
// auth-type none: a tcp-ao peer is refused at start
// (ErrTCPAOSessionBindingUnsupported), so "use tcp-ao" would send the operator
// from one refusal to another.
func TestErrAuthTypeUnavailableInFIPS_NamesWhatWorks(t *testing.T) {
	err := ErrAuthTypeUnavailableInFIPS{Peer: "10.0.0.2", AuthType: AuthTypeMD5}

	msg := err.Error()
	assert.Contains(t, msg, "10.0.0.2")
	assert.Contains(t, msg, "auth-type md5 is not available in a FIPS build")
	assert.Contains(t, msg, "use auth-type none")
	assert.NotContains(t, msg, "use tcp-ao")
}

// Test ErrDampeningOperationFailed error type
func TestErrDampeningOperationFailed(t *testing.T) {
	cause := errors.New("internal error")
	err := &ErrDampeningOperationFailed{
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		Operation: "record_flap",
		Cause:     cause,
	}

	assert.Contains(t, err.Error(), "192.168.1.0/24")
	assert.Contains(t, err.Error(), "record_flap")
	assert.Contains(t, err.Error(), "internal error")
	assert.Equal(t, cause, err.Unwrap())
}
