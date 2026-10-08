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
	"net/netip"
	"testing"
	"time"
)

func TestSpeakerTier_String(t *testing.T) {
	tests := []struct {
		name     string
		tier     SpeakerTier
		expected string
	}{
		{"backbone", SpeakerTierBackbone, "backbone"},
		{"datacenter", SpeakerTierDatacenter, "datacenter"},
		{"coordinator", SpeakerTierCoordinator, "coordinator"},
		{"unknown", SpeakerTierUnknown, "unknown"},
		{"invalid high value", SpeakerTier(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tier.String(); got != tt.expected {
				t.Errorf("SpeakerTier.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSpeakerTier_Valid(t *testing.T) {
	tests := []struct {
		name     string
		tier     SpeakerTier
		expected bool
	}{
		{"backbone valid", SpeakerTierBackbone, true},
		{"datacenter valid", SpeakerTierDatacenter, true},
		{"coordinator valid", SpeakerTierCoordinator, true},
		{"unknown invalid", SpeakerTierUnknown, false},
		{"high value invalid", SpeakerTier(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tier.Valid(); got != tt.expected {
				t.Errorf("SpeakerTier.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthType_String(t *testing.T) {
	tests := []struct {
		name     string
		authType AuthType
		expected string
	}{
		{"none", AuthTypeNone, "none"},
		{"md5", AuthTypeMD5, "md5"},
		{"tcp-ao", AuthTypeTCPAO, "tcp-ao"},
		{"invalid", AuthType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.authType.String(); got != tt.expected {
				t.Errorf("AuthType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		authType AuthType
		expected bool
	}{
		{"none valid", AuthTypeNone, true},
		{"md5 valid", AuthTypeMD5, true},
		{"tcp-ao valid", AuthTypeTCPAO, true},
		{"invalid", AuthType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.authType.Valid(); got != tt.expected {
				t.Errorf("AuthType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPeerState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    PeerState
		expected string
	}{
		{"idle", PeerStateIdle, "Idle"},
		{"connect", PeerStateConnect, "Connect"},
		{"active", PeerStateActive, "Active"},
		{"opensent", PeerStateOpenSent, "OpenSent"},
		{"openconfirm", PeerStateOpenConfirm, "OpenConfirm"},
		{"established", PeerStateEstablished, "Established"},
		{"invalid", PeerState(100), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("PeerState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPeerState_Valid(t *testing.T) {
	tests := []struct {
		name     string
		state    PeerState
		expected bool
	}{
		{"idle valid", PeerStateIdle, true},
		{"established valid", PeerStateEstablished, true},
		{"invalid", PeerState(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.expected {
				t.Errorf("PeerState.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPeerState_IsUp(t *testing.T) {
	tests := []struct {
		name     string
		state    PeerState
		expected bool
	}{
		{"idle not up", PeerStateIdle, false},
		{"connect not up", PeerStateConnect, false},
		{"established is up", PeerStateEstablished, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsUp(); got != tt.expected {
				t.Errorf("PeerState.IsUp() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAddressFamily_String(t *testing.T) {
	tests := []struct {
		name     string
		af       AddressFamily
		expected string
	}{
		{"ipv4 unicast", AFamilyIPv4Unicast, "ipv4-unicast"},
		{"ipv6 unicast", AFamilyIPv6Unicast, "ipv6-unicast"},
		{"evpn", AFamilyEVPN, "evpn"},
		{"invalid", AddressFamily(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.af.String(); got != tt.expected {
				t.Errorf("AddressFamily.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAddressFamily_Valid(t *testing.T) {
	tests := []struct {
		name     string
		af       AddressFamily
		expected bool
	}{
		{"ipv4 unicast valid", AFamilyIPv4Unicast, true},
		{"evpn valid", AFamilyEVPN, true},
		{"invalid", AddressFamily(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.af.Valid(); got != tt.expected {
				t.Errorf("AddressFamily.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRIBType_String(t *testing.T) {
	tests := []struct {
		name     string
		rib      RIBType
		expected string
	}{
		{"local", RIBLocal, "local"},
		{"adj-in", RIBAdjIn, "adj-in"},
		{"adj-out", RIBAdjOut, "adj-out"},
		{"invalid", RIBType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rib.String(); got != tt.expected {
				t.Errorf("RIBType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRIBType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		rib      RIBType
		expected bool
	}{
		{"local valid", RIBLocal, true},
		{"adj-out valid", RIBAdjOut, true},
		{"invalid", RIBType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rib.Valid(); got != tt.expected {
				t.Errorf("RIBType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOriginType_String(t *testing.T) {
	tests := []struct {
		name     string
		origin   OriginType
		expected string
	}{
		{"igp", OriginIGP, "igp"},
		{"egp", OriginEGP, "egp"},
		{"incomplete", OriginIncomplete, "incomplete"},
		{"invalid", OriginType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.origin.String(); got != tt.expected {
				t.Errorf("OriginType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOriginType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		origin   OriginType
		expected bool
	}{
		{"igp valid", OriginIGP, true},
		{"incomplete valid", OriginIncomplete, true},
		{"invalid", OriginType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.origin.Valid(); got != tt.expected {
				t.Errorf("OriginType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		name     string
		event    EventType
		expected string
	}{
		{"peer state change", EventPeerStateChange, "peer-state-change"},
		{"path received", EventPathReceived, "path-received"},
		{"path withdrawn", EventPathWithdrawn, "path-withdrawn"},
		{"invalid", EventType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.String(); got != tt.expected {
				t.Errorf("EventType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEventType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		event    EventType
		expected bool
	}{
		{"peer state change valid", EventPeerStateChange, true},
		{"path withdrawn valid", EventPathWithdrawn, true},
		{"invalid", EventType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.Valid(); got != tt.expected {
				t.Errorf("EventType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRouteType_String(t *testing.T) {
	tests := []struct {
		name     string
		route    RouteType
		expected string
	}{
		{"evpn type2", RouteTypeEVPNType2, "evpn-type2"},
		{"evpn type3", RouteTypeEVPNType3, "evpn-type3"},
		{"evpn type5", RouteTypeEVPNType5, "evpn-type5"},
		{"ipv4 unicast", RouteTypeIPv4Unicast, "ipv4-unicast"},
		{"ipv6 unicast", RouteTypeIPv6Unicast, "ipv6-unicast"},
		{"unknown", RouteTypeUnknown, "unknown"},
		{"invalid", RouteType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.String(); got != tt.expected {
				t.Errorf("RouteType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRouteType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		route    RouteType
		expected bool
	}{
		{"evpn type2 valid", RouteTypeEVPNType2, true},
		{"ipv6 unicast valid", RouteTypeIPv6Unicast, true},
		{"unknown invalid", RouteTypeUnknown, false},
		{"invalid high", RouteType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.Valid(); got != tt.expected {
				t.Errorf("RouteType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRouteType_IsEVPN(t *testing.T) {
	tests := []struct {
		name     string
		route    RouteType
		expected bool
	}{
		{"evpn type2 is evpn", RouteTypeEVPNType2, true},
		{"evpn type3 is evpn", RouteTypeEVPNType3, true},
		{"evpn type5 is evpn", RouteTypeEVPNType5, true},
		{"ipv4 unicast not evpn", RouteTypeIPv4Unicast, false},
		{"ipv6 unicast not evpn", RouteTypeIPv6Unicast, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.IsEVPN(); got != tt.expected {
				t.Errorf("RouteType.IsEVPN() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEVPNRouteType_String(t *testing.T) {
	tests := []struct {
		name     string
		route    EVPNRouteType
		expected string
	}{
		{"type1", EVPNTypeEthernetAutoDiscovery, "ethernet-auto-discovery"},
		{"type2", EVPNTypeMACIPAdvertisement, "mac-ip-advertisement"},
		{"type3", EVPNTypeInclusiveMulticast, "inclusive-multicast"},
		{"type4", EVPNTypeEthernetSegment, "ethernet-segment"},
		{"type5", EVPNTypeIPPrefix, "ip-prefix"},
		{"invalid", EVPNRouteType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.String(); got != tt.expected {
				t.Errorf("EVPNRouteType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEVPNRouteType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		route    EVPNRouteType
		expected bool
	}{
		{"type1 valid", EVPNTypeEthernetAutoDiscovery, true},
		{"type5 valid", EVPNTypeIPPrefix, true},
		{"zero invalid", EVPNRouteType(0), false},
		{"high invalid", EVPNRouteType(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.Valid(); got != tt.expected {
				t.Errorf("EVPNRouteType.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRPKIValidationState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    RPKIValidationState
		expected string
	}{
		{"not found", RPKIStateNotFound, "NotFound"},
		{"valid", RPKIStateValid, "Valid"},
		{"invalid", RPKIStateInvalid, "Invalid"},
		{"unknown", RPKIStateUnknown, "Unknown"},
		{"out of range", RPKIValidationState(100), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("RPKIValidationState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRPKIValidationState_Valid(t *testing.T) {
	tests := []struct {
		name     string
		state    RPKIValidationState
		expected bool
	}{
		{"not found valid", RPKIStateNotFound, true},
		{"unknown valid", RPKIStateUnknown, true},
		{"invalid high", RPKIValidationState(100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.expected {
				t.Errorf("RPKIValidationState.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRPKIValidationState_IsAcceptable(t *testing.T) {
	tests := []struct {
		name     string
		state    RPKIValidationState
		expected bool
	}{
		{"valid is acceptable", RPKIStateValid, true},
		{"not found is acceptable", RPKIStateNotFound, true},
		{"unknown is acceptable", RPKIStateUnknown, true},
		{"invalid not acceptable", RPKIStateInvalid, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsAcceptable(); got != tt.expected {
				t.Errorf("RPKIValidationState.IsAcceptable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBGPCapabilities_HasAnyAFI(t *testing.T) {
	tests := []struct {
		name         string
		capabilities BGPCapabilities
		expected     bool
	}{
		{
			name:         "no afi",
			capabilities: BGPCapabilities{},
			expected:     false,
		},
		{
			name:         "ipv4 only",
			capabilities: BGPCapabilities{IPv4Unicast: true},
			expected:     true,
		},
		{
			name:         "ipv6 only",
			capabilities: BGPCapabilities{IPv6Unicast: true},
			expected:     true,
		},
		{
			name:         "evpn only",
			capabilities: BGPCapabilities{EVPN: true},
			expected:     true,
		},
		{
			name:         "all afi",
			capabilities: BGPCapabilities{IPv4Unicast: true, IPv6Unicast: true, EVPN: true},
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.capabilities.HasAnyAFI(); got != tt.expected {
				t.Errorf("BGPCapabilities.HasAnyAFI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBGPCapabilities_Validate(t *testing.T) {
	tests := []struct {
		name         string
		capabilities BGPCapabilities
		wantErr      bool
	}{
		{
			name:         "no afi fails",
			capabilities: BGPCapabilities{},
			wantErr:      true,
		},
		{
			name:         "with ipv4 succeeds",
			capabilities: BGPCapabilities{IPv4Unicast: true},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.capabilities.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("BGPCapabilities.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBGPConfig_Validate(t *testing.T) {
	validRouterID := netip.MustParseAddr("10.0.0.1")

	tests := []struct {
		name    string
		config  BGPConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: BGPConfig{
				RouterID:   validRouterID,
				ASN:        65001,
				ListenPort: 179,
				Tier:       SpeakerTierBackbone,
			},
			wantErr: false,
		},
		{
			name: "invalid router id - unspecified",
			config: BGPConfig{
				RouterID:   netip.Addr{},
				ASN:        65001,
				ListenPort: 179,
			},
			wantErr: true,
		},
		{
			name: "invalid asn - zero",
			config: BGPConfig{
				RouterID:   validRouterID,
				ASN:        0,
				ListenPort: 179,
			},
			wantErr: true,
		},
		{
			name: "evpn needs no route distinguisher: each EVI derives its own",
			config: BGPConfig{
				RouterID:     validRouterID,
				ASN:          65001,
				ListenPort:   179,
				Capabilities: BGPCapabilities{EVPN: true},
			},
			wantErr: false,
		},
		{
			name: "dampening without half life",
			config: BGPConfig{
				RouterID:         validRouterID,
				ASN:              65001,
				ListenPort:       179,
				DampeningEnabled: true,
			},
			wantErr: true,
		},
		{
			name: "dampening with invalid max suppress",
			config: BGPConfig{
				RouterID:             validRouterID,
				ASN:                  65001,
				ListenPort:           179,
				DampeningEnabled:     true,
				DampeningHalfLife:    15 * time.Minute,
				DampeningMaxSuppress: 5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "route reflector without cluster id",
			config: BGPConfig{
				RouterID:         validRouterID,
				ASN:              65001,
				ListenPort:       179,
				IsRouteReflector: true,
			},
			wantErr: true,
		},
		{
			name: "defaults listen port when zero",
			config: BGPConfig{
				RouterID:   validRouterID,
				ASN:        65001,
				ListenPort: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("BGPConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBGPConfig_IsPrivateASN(t *testing.T) {
	tests := []struct {
		name     string
		asn      uint32
		expected bool
	}{
		{"public asn", 1000, false},
		{"private 16-bit start", 64512, true},
		{"private 16-bit end", 65534, true},
		{"private 32-bit start", 4200000000, true},
		{"private 32-bit end", 4294967294, true},
		{"public 32-bit", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := BGPConfig{ASN: tt.asn}
			if got := config.IsPrivateASN(); got != tt.expected {
				t.Errorf("BGPConfig.IsPrivateASN() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNeighborConfig_Validate(t *testing.T) {
	validAddr := netip.MustParseAddr("10.0.0.2")

	tests := []struct {
		name    string
		config  NeighborConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: NeighborConfig{
				Address: validAddr,
				ASN:     65002,
			},
			wantErr: false,
		},
		{
			name: "invalid address",
			config: NeighborConfig{
				Address: netip.Addr{},
				ASN:     65002,
			},
			wantErr: true,
		},
		{
			name: "invalid asn",
			config: NeighborConfig{
				Address: validAddr,
				ASN:     0,
			},
			wantErr: true,
		},
		{
			name: "md5 without key",
			config: NeighborConfig{
				Address:  validAddr,
				ASN:      65002,
				AuthType: AuthTypeMD5,
			},
			wantErr: true,
		},
		{
			name: "tcp-ao without key",
			config: NeighborConfig{
				Address:  validAddr,
				ASN:      65002,
				AuthType: AuthTypeTCPAO,
			},
			wantErr: true,
		},
		{
			name: "hold time too low",
			config: NeighborConfig{
				Address:  validAddr,
				ASN:      65002,
				HoldTime: 1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("NeighborConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNeighborConfig_HasAnyAFI(t *testing.T) {
	tests := []struct {
		name     string
		config   NeighborConfig
		expected bool
	}{
		{
			name:     "no afi",
			config:   NeighborConfig{},
			expected: false,
		},
		{
			name:     "ipv4 enabled",
			config:   NeighborConfig{IPv4Unicast: true},
			expected: true,
		},
		{
			name:     "enabled families",
			config:   NeighborConfig{EnabledFamilies: []AddressFamily{AFamilyEVPN}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.HasAnyAFI(); got != tt.expected {
				t.Errorf("NeighborConfig.HasAnyAFI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTransitRoute_Validate(t *testing.T) {
	tests := []struct {
		name    string
		route   TransitRoute
		wantErr bool
	}{
		{
			name: "valid route",
			route: TransitRoute{
				Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				NextHop: netip.MustParseAddr("10.0.0.1"),
				Origin:  OriginIGP,
			},
			wantErr: false,
		},
		{
			name: "invalid prefix",
			route: TransitRoute{
				Prefix:  netip.Prefix{},
				NextHop: netip.MustParseAddr("10.0.0.1"),
				Origin:  OriginIGP,
			},
			wantErr: true,
		},
		{
			name: "invalid next hop",
			route: TransitRoute{
				Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				NextHop: netip.Addr{},
				Origin:  OriginIGP,
			},
			wantErr: true,
		},
		{
			name: "invalid origin",
			route: TransitRoute{
				Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				NextHop: netip.MustParseAddr("10.0.0.1"),
				Origin:  OriginType(100),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("TransitRoute.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDampeningState_IsActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		state    DampeningState
		expected bool
	}{
		{
			name: "suppressed with future reuse",
			state: DampeningState{
				Suppressed: true,
				ReuseAt:    now.Add(time.Hour),
			},
			expected: true,
		},
		{
			name: "suppressed with past reuse",
			state: DampeningState{
				Suppressed: true,
				ReuseAt:    now.Add(-time.Hour),
			},
			expected: false,
		},
		{
			name: "not suppressed",
			state: DampeningState{
				Suppressed: false,
				ReuseAt:    now.Add(time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsActive(); got != tt.expected {
				t.Errorf("DampeningState.IsActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPeerStatus_Uptime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		status   PeerStatus
		expected bool // whether uptime should be > 0
	}{
		{
			name: "established with uptime",
			status: PeerStatus{
				State:       PeerStateEstablished,
				UptimeSince: now.Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "not established",
			status: PeerStatus{
				State:       PeerStateIdle,
				UptimeSince: now.Add(-time.Hour),
			},
			expected: false,
		},
		{
			name: "zero uptime since",
			status: PeerStatus{
				State:       PeerStateEstablished,
				UptimeSince: time.Time{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uptime := tt.status.Uptime()
			if tt.expected && uptime == 0 {
				t.Errorf("PeerStatus.Uptime() = 0, expected > 0")
			}
			if !tt.expected && uptime != 0 {
				t.Errorf("PeerStatus.Uptime() = %v, expected 0", uptime)
			}
		})
	}
}

func TestSpeakerStatus_Uptime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		status   SpeakerStatus
		expected bool // whether uptime should be > 0
	}{
		{
			name: "running with start time",
			status: SpeakerStatus{
				Running:   true,
				StartedAt: now.Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "not running",
			status: SpeakerStatus{
				Running:   false,
				StartedAt: now.Add(-time.Hour),
			},
			expected: false,
		},
		{
			name: "zero start time",
			status: SpeakerStatus{
				Running:   true,
				StartedAt: time.Time{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uptime := tt.status.Uptime()
			if tt.expected && uptime == 0 {
				t.Errorf("SpeakerStatus.Uptime() = 0, expected > 0")
			}
			if !tt.expected && uptime != 0 {
				t.Errorf("SpeakerStatus.Uptime() = %v, expected 0", uptime)
			}
		})
	}
}

func TestWatchOptions(t *testing.T) {
	t.Run("WithPeerStateChanges", func(t *testing.T) {
		opts := &watchOptions{}
		WithPeerStateChanges()(opts)
		if !opts.peerStateChanges {
			t.Error("expected peerStateChanges to be true")
		}
	})

	t.Run("WithPathChanges", func(t *testing.T) {
		opts := &watchOptions{}
		WithPathChanges()(opts)
		if !opts.pathChanges {
			t.Error("expected pathChanges to be true")
		}
	})

	t.Run("WithBestPathOnly", func(t *testing.T) {
		opts := &watchOptions{}
		WithBestPathOnly()(opts)
		if !opts.bestPathOnly {
			t.Error("expected bestPathOnly to be true")
		}
	})

	t.Run("WithFamilies", func(t *testing.T) {
		opts := &watchOptions{}
		WithFamilies(AFamilyIPv4Unicast, AFamilyEVPN)(opts)
		if len(opts.families) != 2 {
			t.Errorf("expected 2 families, got %d", len(opts.families))
		}
	})

	t.Run("WithPeerFilter", func(t *testing.T) {
		opts := &watchOptions{}
		addr := netip.MustParseAddr("10.0.0.1")
		WithPeerFilter(addr)(opts)
		if opts.peerAddress != addr {
			t.Errorf("expected peerAddress %v, got %v", addr, opts.peerAddress)
		}
	})
}

func TestConstants(t *testing.T) {
	if DefaultBGPPort != 179 {
		t.Errorf("DefaultBGPPort = %d, want 179", DefaultBGPPort)
	}
	if DefaultHoldTime != 90 {
		t.Errorf("DefaultHoldTime = %d, want 90", DefaultHoldTime)
	}
	if DefaultKeepaliveInterval != 30 {
		t.Errorf("DefaultKeepaliveInterval = %d, want 30", DefaultKeepaliveInterval)
	}
	if MinHoldTime != 3 {
		t.Errorf("MinHoldTime = %d, want 3", MinHoldTime)
	}
	if MinASN != 1 {
		t.Errorf("MinASN = %d, want 1", MinASN)
	}
	if MaxASN != 4294967295 {
		t.Errorf("MaxASN = %d, want 4294967295", MaxASN)
	}
	if PrivateASNMin != 64512 {
		t.Errorf("PrivateASNMin = %d, want 64512", PrivateASNMin)
	}
	if PrivateASNMax != 65534 {
		t.Errorf("PrivateASNMax = %d, want 65534", PrivateASNMax)
	}
	if PrivateASN4Min != 4200000000 {
		t.Errorf("PrivateASN4Min = %d, want 4200000000", PrivateASN4Min)
	}
	if PrivateASN4Max != 4294967294 {
		t.Errorf("PrivateASN4Max = %d, want 4294967294", PrivateASN4Max)
	}
}
