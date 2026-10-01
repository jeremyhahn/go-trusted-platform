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
	"errors"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startedSpeaker(t *testing.T, cfg *BGPConfig) (*Speaker, *mockBGPServer) {
	t.Helper()
	mock := newMockBGPServer()
	sp, err := NewSpeaker(cfg, speakerTestLogger(), WithBGPServer(mock))
	require.NoError(t, err)
	require.NoError(t, sp.Start(context.Background()))
	t.Cleanup(func() { _ = sp.Stop(context.Background()) })
	return sp, mock
}

func baseConfig() *BGPConfig {
	return &BGPConfig{
		RouterID:        netip.MustParseAddr("23.143.36.4"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
		Announce:        &AnnounceConfig{IPv4Prefixes: []string{"23.143.36.0/24"}, IPv6Prefixes: []string{"2602:f5bb::/36"}},
	}
}

// --- enum text round trips -------------------------------------------------

func TestEnumText_RoundTrips(t *testing.T) {
	for _, a := range []AuthType{AuthTypeNone, AuthTypeMD5, AuthTypeTCPAO} {
		text, err := a.MarshalText()
		require.NoError(t, err)
		var back AuthType
		require.NoError(t, back.UnmarshalText(text))
		assert.Equal(t, a, back)
	}
	for _, af := range []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast, AFamilyEVPN} {
		text, err := af.MarshalText()
		require.NoError(t, err)
		var back AddressFamily
		require.NoError(t, back.UnmarshalText(text))
		assert.Equal(t, af, back)
	}
	for _, tier := range []SpeakerTier{SpeakerTierUnknown, SpeakerTierBackbone, SpeakerTierDatacenter, SpeakerTierCoordinator} {
		text, err := tier.MarshalText()
		require.NoError(t, err)
		var back SpeakerTier
		require.NoError(t, back.UnmarshalText(text))
		assert.Equal(t, tier, back)
	}
	for _, alg := range []TCPAOAlgorithm{TCPAOAlgorithmHMACSHA256_128, TCPAOAlgorithmHMACSHA256_96, TCPAOAlgorithmAES128CMAC96, TCPAOAlgorithmHMACSHA1_96} {
		text, err := alg.MarshalText()
		require.NoError(t, err)
		var back TCPAOAlgorithm
		require.NoError(t, back.UnmarshalText(text))
		assert.Equal(t, alg, back)
	}
}

func TestEnumText_RejectsUnknown(t *testing.T) {
	var a AuthType
	var e1 ErrUnknownAuthType
	require.True(t, errors.As(a.UnmarshalText([]byte("sha1")), &e1))
	var af AddressFamily
	var e2 ErrUnknownAddressFamily
	require.True(t, errors.As(af.UnmarshalText([]byte("ipv7")), &e2))
	var tier SpeakerTier
	var e3 ErrUnknownSpeakerTier
	require.True(t, errors.As(tier.UnmarshalText([]byte("core")), &e3))
	var alg TCPAOAlgorithm
	var e4 ErrUnknownTCPAOAlgorithm
	require.True(t, errors.As(alg.UnmarshalText([]byte("md5")), &e4))
	// The empty string is the zero value for the types that have a sensible one.
	require.NoError(t, a.UnmarshalText(nil))
	assert.Equal(t, AuthTypeNone, a)
	require.NoError(t, tier.UnmarshalText(nil))
	assert.Equal(t, SpeakerTierUnknown, tier)
}

// --- config semantics -------------------------------------------------------

func TestBGPConfig_GracefulRestartDefaultsOn(t *testing.T) {
	cfg := baseConfig()
	assert.True(t, cfg.GracefulRestartEnabled())
	require.NoError(t, cfg.Validate())
	assert.Equal(t, DefaultGracefulRestartTime, cfg.GracefulRestartTime)

	off := false
	cfg.GracefulRestart = &off
	assert.False(t, cfg.GracefulRestartEnabled())
}

func TestNeighborConfig_FamiliesFoldFlagsAndList(t *testing.T) {
	n := NeighborConfig{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast}, IPv6Unicast: true}
	require.NoError(t, n.Validate())
	assert.True(t, n.IPv4Unicast, "the list sets the flag")
	assert.Equal(t, []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast}, n.Families())
	assert.Equal(t, DefaultMaxPrefixes, n.MaxPrefixes)
}

func TestNeighborConfig_AuthRequiresASecretReference(t *testing.T) {
	md5 := NeighborConfig{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeMD5}
	err := md5.Validate()
	if md5SessionAuthPermitted() {
		var want ErrAuthSecretRequired
		require.True(t, errors.As(err, &want), "got %v", err)
		md5.AuthKeyRef = "kms://platform/bgp/miami"
		require.NoError(t, md5.Validate())
	} else {
		var want ErrAuthTypeUnavailableInFIPS
		require.True(t, errors.As(err, &want), "got %v", err)
	}

	ao := NeighborConfig{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeTCPAO}
	var want ErrAuthSecretRequired
	require.True(t, errors.As(ao.Validate(), &want))
	ao.Keychain = "vps"
	require.NoError(t, ao.Validate())
}

func TestBGPConfig_KeychainReferencesMustResolve(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeTCPAO, Keychain: "vps"}}
	var notFound ErrKeychainNotFound
	require.True(t, errors.As(cfg.Validate(), &notFound))

	cfg.Keychains = []TCPAOKeychainConfig{{Name: "vps", Keys: []TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, MasterKeyRef: "kms://platform/bgp/vps"}}}}
	require.NoError(t, cfg.Validate())

	cfg.Keychains = append(cfg.Keychains, cfg.Keychains[0])
	var dup ErrDuplicateKeychain
	require.True(t, errors.As(cfg.Validate(), &dup))

	var invalid ErrKeychainInvalid
	require.True(t, errors.As((&TCPAOKeychainConfig{Name: "x"}).Validate(), &invalid))
	require.True(t, errors.As((&TCPAOKeychainConfig{Name: "x", Keys: []TCPAOKeyConfig{{}}}).Validate(), &invalid))
	require.True(t, errors.As((&TCPAOKeychainConfig{Keys: []TCPAOKeyConfig{{MasterKeyRef: "kms://k"}}}).Validate(), &invalid))
}

func TestBFDConfig_DefaultsAndFloor(t *testing.T) {
	b := &BFDConfig{Enabled: true}
	require.NoError(t, b.Validate())
	assert.Equal(t, DefaultBFDPort, b.Port)
	assert.Equal(t, DefaultBFDInterval, b.DesiredMinTxInterval)
	assert.Equal(t, DefaultBFDDetectionMultiplier, b.DetectionMultiplier)

	short := &BFDConfig{Enabled: true, DesiredMinTxInterval: time.Millisecond}
	var want ErrBFDIntervalTooShort
	require.True(t, errors.As(short.Validate(), &want))
	require.NoError(t, (&BFDConfig{}).Validate(), "disabled BFD needs nothing")
}

func TestPrefixMatch_Validate(t *testing.T) {
	require.NoError(t, (&PrefixMatch{Prefix: netip.MustParsePrefix("10.0.0.0/8"), MaxLength: 24}).Validate())
	require.Error(t, (&PrefixMatch{}).Validate())
	require.Error(t, (&PrefixMatch{Prefix: netip.MustParsePrefix("10.0.0.0/16"), MaxLength: 8}).Validate())
	require.Error(t, (&PrefixMatch{Prefix: netip.MustParsePrefix("10.0.0.0/16"), MaxLength: 40}).Validate())
	p := PeerPolicyConfig{ImportAllow: []PrefixMatch{{}}}
	require.Error(t, p.Validate())
}

// --- secrets ----------------------------------------------------------------

func TestBGPConfig_ResolveSecrets(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeMD5, AuthKeyRef: "kms://platform/bgp/miami"}}
	cfg.Keychains = []TCPAOKeychainConfig{{Name: "vps", Keys: []TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, MasterKeyRef: "kms://platform/bgp/vps"}}}}

	var resolverRequired ErrSecretResolverRequired
	require.True(t, errors.As(cfg.ResolveSecrets(context.Background(), nil), &resolverRequired))

	resolved := map[string][]byte{"kms://platform/bgp/miami": []byte("s3cret"), "kms://platform/bgp/vps": []byte("master")}
	resolve := func(_ context.Context, ref string) ([]byte, error) {
		v, ok := resolved[ref]
		if !ok {
			return nil, errors.New("no such secret")
		}
		return v, nil
	}
	require.NoError(t, cfg.ResolveSecrets(context.Background(), resolve))
	assert.Equal(t, "s3cret", cfg.Neighbors[0].AuthKey)
	assert.Equal(t, []byte("master"), cfg.Keychains[0].Keys[0].MasterKey)

	// A second resolution is a no-op for already resolved material.
	require.NoError(t, cfg.ResolveSecrets(context.Background(), func(context.Context, string) ([]byte, error) {
		t.Fatal("resolved material must not be re-resolved")
		return nil, nil
	}))

	bad := baseConfig()
	bad.Neighbors = []NeighborConfig{{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeMD5, AuthKeyRef: "kms://missing"}}
	var failed ErrSecretResolutionFailed
	err := bad.ResolveSecrets(context.Background(), resolve)
	require.True(t, errors.As(err, &failed))
	assert.Contains(t, err.Error(), "kms://missing")
	assert.NotContains(t, err.Error(), "s3cret")
}

// --- speaker: start installs keychains and policies -------------------------

// TestBGPConfig_ResolveSecrets_EmptyValueIsRefused pins the review finding
// on #580: a reference that resolves to zero bytes must not yield a session
// the configuration calls md5 (or a keychain) with no secret behind it.
func TestBGPConfig_ResolveSecrets_EmptyValueIsRefused(t *testing.T) {
	empty := func(context.Context, string) ([]byte, error) { return []byte{}, nil }

	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, AuthType: AuthTypeMD5, AuthKeyRef: "kms://platform/bgp/miami"}}
	err := cfg.ResolveSecrets(context.Background(), empty)
	var failed ErrSecretResolutionFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.ErrorIs(t, err, ErrSecretEmpty{})
	assert.Empty(t, cfg.Neighbors[0].AuthKey)

	cfg = baseConfig()
	cfg.Keychains = []TCPAOKeychainConfig{{Name: "vps", Keys: []TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, MasterKeyRef: "kms://platform/bgp/vps"}}}}
	err = cfg.ResolveSecrets(context.Background(), empty)
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Empty(t, cfg.Keychains[0].Keys[0].MasterKey)
}

// TestSpeaker_AddPeerInstallsItsPolicyFirst pins the review advisory on
// #580: a neighbor added at runtime that the initial config did not name
// gets its import/export policy installed before its session exists, and a
// deleted neighbor leaves the policy set.
func TestSpeaker_AddPeerInstallsItsPolicyFirst(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = nil
	s, mock := startedSpeaker(t, cfg)

	peer := &NeighborConfig{Address: netip.MustParseAddr("10.255.0.99"), ASN: 401870, EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast}}
	require.NoError(t, s.AddPeer(context.Background(), peer))

	mock.mu.Lock()
	policies := mock.policies
	mock.mu.Unlock()
	require.NotNil(t, policies)
	want := policyName(policyPrefixImport, peer.Address)
	assert.NotEmpty(t, statementsFor(t, policies, policyPrefixImport, want),
		"the runtime-added peer's import statements %q were not installed", want)
	assert.Len(t, s.config.Neighbors, 1)

	require.NoError(t, s.DeletePeer(context.Background(), peer.Address))
	assert.Empty(t, s.config.Neighbors)
}

// TestFSMStateToAPI pins the internal→gRPC state conversion the #580 review
// questioned: GoBGP's FSMState is 0-based (BGP_FSM_IDLE=0 … ESTABLISHED=5)
// while api.PeerState_SessionState reserves 0 for UNSPECIFIED (IDLE=1 …
// ESTABLISHED=6), so the +1 is required — the same one GoBGP's own
// grpc_server.go applies.
func TestFSMStateToAPI(t *testing.T) {
	assert.Equal(t, api.PeerState_SESSION_STATE_IDLE, fsmStateToAPI(gobgp.BGP_FSM_IDLE))
	assert.Equal(t, api.PeerState_SESSION_STATE_CONNECT, fsmStateToAPI(gobgp.BGP_FSM_CONNECT))
	assert.Equal(t, api.PeerState_SESSION_STATE_ACTIVE, fsmStateToAPI(gobgp.BGP_FSM_ACTIVE))
	assert.Equal(t, api.PeerState_SESSION_STATE_OPENSENT, fsmStateToAPI(gobgp.BGP_FSM_OPENSENT))
	assert.Equal(t, api.PeerState_SESSION_STATE_OPENCONFIRM, fsmStateToAPI(gobgp.BGP_FSM_OPENCONFIRM))
	assert.Equal(t, api.PeerState_SESSION_STATE_ESTABLISHED, fsmStateToAPI(gobgp.BGP_FSM_ESTABLISHED))
	assert.Equal(t, PeerStateEstablished, (&Speaker{}).sessionStateToState(fsmStateToAPI(gobgp.BGP_FSM_ESTABLISHED)))
}

func TestAddressFamilyToAPI_UnknownIsNil(t *testing.T) {
	s := &Speaker{}
	assert.Nil(t, s.addressFamilyToAPI(AddressFamily(255)))
	assert.NotNil(t, s.addressFamilyToAPI(AFamilyIPv4Unicast))
}

func TestSpeaker_StartInstallsKeychainsAndPolicies(t *testing.T) {
	cfg := baseConfig()
	cfg.Keychains = []TCPAOKeychainConfig{{Name: "vps", Keys: []TCPAOKeyConfig{{SendID: 1, ReceiveID: 2, Algorithm: TCPAOAlgorithmAES128CMAC96, MasterKey: []byte("k")}}}}
	cfg.Neighbors = []NeighborConfig{
		{Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870, EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
			Policy: PeerPolicyConfig{ImportAllow: []PrefixMatch{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}}},
	}
	require.NoError(t, cfg.Validate())
	_, mock := startedSpeaker(t, cfg)

	require.Len(t, mock.keychains, 1)
	assert.Equal(t, "vps", mock.keychains[0].Name)
	assert.Equal(t, uint32(2), mock.keychains[0].Keys[0].ReceiveId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, mock.keychains[0].Keys[0].Algorithm)
	assert.Equal(t, []byte("k"), mock.keychains[0].Keys[0].MasterKey)

	require.NotNil(t, mock.policies)
	// The peer's neighbor set, then two directions, each split into a v4
	// and a v6 prefix set: GoBGP refuses a set that holds both families
	// (#620).
	require.Len(t, mock.policies.DefinedSets, 5)
	neighbors := mock.policies.DefinedSets[0]
	assert.Equal(t, api.DefinedType_DEFINED_TYPE_NEIGHBOR, neighbors.DefinedType)
	assert.Equal(t, "tp-peer-10-255-0-2", neighbors.Name)
	assert.Equal(t, []string{"10.255.0.2/32"}, neighbors.List)
	importV4 := mock.policies.DefinedSets[1]
	assert.Equal(t, "tp-import-10-255-0-2-prefixes-v4", importV4.Name)
	require.Len(t, importV4.Prefixes, 1)
	assert.Equal(t, "0.0.0.0/0", importV4.Prefixes[0].IpPrefix)
	assert.Equal(t, uint32(0), importV4.Prefixes[0].MaskLengthMax, "exact match only")
	assert.Empty(t, mock.policies.DefinedSets[2].Prefixes,
		"tp-import-10-255-0-2-prefixes-v6 is empty, so v6 falls to the reject default")

	exportV4 := mock.policies.DefinedSets[3]
	assert.Equal(t, "tp-export-10-255-0-2-prefixes-v4", exportV4.Name)
	require.Len(t, exportV4.Prefixes, 1, "export defaults to the announced prefixes, v4 half")
	assert.Equal(t, "23.143.36.0/24", exportV4.Prefixes[0].IpPrefix)
	exportV6 := mock.policies.DefinedSets[4]
	assert.Equal(t, "tp-export-10-255-0-2-prefixes-v6", exportV6.Name)
	require.Len(t, exportV6.Prefixes, 1, "and its v6 half")
	assert.Equal(t, "2602:f5bb::/36", exportV6.Prefixes[0].IpPrefix)

	// Two global policies. Import opens with the local-origin accept, then
	// one accept statement per family, both naming their own set and both
	// scoped to the peer.
	require.Len(t, mock.policies.Policies, 2)
	importPolicy := mock.policies.Policies[0]
	assert.Equal(t, policyPrefixImport, importPolicy.Name)
	assert.Equal(t, policyPrefixExport, mock.policies.Policies[1].Name)
	require.Len(t, importPolicy.Statements, 3)
	local := importPolicy.Statements[0]
	assert.Equal(t, localOriginStatement, local.Name)
	assert.Equal(t, api.Conditions_ROUTE_TYPE_LOCAL, local.Conditions.RouteType)
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_ACCEPT, local.Actions.RouteAction)
	v4 := importPolicy.Statements[1]
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_ACCEPT, v4.Actions.RouteAction)
	assert.Equal(t, api.MatchSet_TYPE_ANY, v4.Conditions.PrefixSet.Type)
	assert.Equal(t, importV4.Name, v4.Conditions.PrefixSet.Name)
	assert.Equal(t, neighbors.Name, v4.Conditions.NeighborSet.Name)
	assert.Equal(t, "tp-import-10-255-0-2-prefixes-v6",
		importPolicy.Statements[2].Conditions.PrefixSet.Name)

	// Both global policies are assigned to the global RIB with the RFC 8212
	// reject default: GoBGP evaluates every non-route-server peer there.
	require.Len(t, mock.assigned, 2)
	for i, dir := range []api.PolicyDirection{api.PolicyDirection_POLICY_DIRECTION_IMPORT, api.PolicyDirection_POLICY_DIRECTION_EXPORT} {
		assert.Equal(t, dir, mock.assigned[i].Direction)
		assert.Empty(t, mock.assigned[i].Name, "the empty name is the global RIB")
		assert.Equal(t, api.RouteAction_ROUTE_ACTION_REJECT, mock.assigned[i].DefaultAction)
		require.Len(t, mock.assigned[i].Policies, 1)
	}
	assert.Equal(t, policyPrefixImport, mock.assigned[0].Policies[0].Name)
	assert.Equal(t, policyPrefixExport, mock.assigned[1].Policies[0].Name)

	// Graceful restart is advertised by default.
	require.NotNil(t, mock.global)
	require.NotNil(t, mock.global.GracefulRestart)
	assert.True(t, mock.global.GracefulRestart.Enabled)
	assert.Equal(t, uint32(DefaultGracefulRestartTime), mock.global.GracefulRestart.RestartTime)
}

func TestSpeaker_PeerCarriesPolicyBFDAndPrefixLimit(t *testing.T) {
	cfg := baseConfig()
	_, mock := startedSpeaker(t, cfg)
	sp, err := NewSpeaker(cfg, speakerTestLogger(), WithBGPServer(mock))
	require.NoError(t, err)

	n := &NeighborConfig{
		Address: netip.MustParseAddr("10.255.0.2"), ASN: 401870,
		AuthType: AuthTypeMD5, AuthKey: "s3cret",
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
		MaxPrefixes:     7,
		RemovePrivateAS: true,
		BFD:             &BFDConfig{Enabled: true},
		Policy:          PeerPolicyConfig{ExportDefaultAccept: true},
	}
	if !md5SessionAuthPermitted() {
		n.AuthType, n.AuthKey = AuthTypeNone, ""
	}
	require.NoError(t, n.Validate())
	peer := sp.neighborConfigToPeer(n)

	if md5SessionAuthPermitted() {
		assert.Equal(t, "s3cret", peer.Conf.AuthPassword)
	} else {
		assert.Empty(t, peer.Conf.AuthPassword)
	}
	assert.Equal(t, api.RemovePrivate_REMOVE_PRIVATE_ALL, peer.Conf.RemovePrivate)
	require.NotNil(t, peer.Bfd)
	assert.True(t, peer.Bfd.Enabled)
	assert.Equal(t, uint32(DefaultBFDPort), peer.Bfd.Port)
	assert.Equal(t, uint32(300000), peer.Bfd.DesiredMinimumTxInterval, "microseconds")
	assert.Equal(t, uint32(DefaultBFDDetectionMultiplier), peer.Bfd.DetectionMultiplier)
	require.Len(t, peer.AfiSafis, 2)
	for _, as := range peer.AfiSafis {
		require.NotNil(t, as.PrefixLimits)
		assert.Equal(t, uint32(7), as.PrefixLimits.MaxPrefixes)
		assert.Equal(t, uint32(prefixLimitWarnPct), as.PrefixLimits.ShutdownThresholdPct)
	}
	assert.Nil(t, peer.ApplyPolicy,
		"GoBGP ignores a per-peer assignment on a non-route-server peer; the policy is global (#717)")
	require.NotNil(t, peer.GracefulRestart)
	assert.True(t, peer.GracefulRestart.Enabled)
}

func TestSpeaker_TCPAOPeerIsRefusedUntilGoBGPBindsIt(t *testing.T) {
	cfg := baseConfig()
	cfg.Keychains = []TCPAOKeychainConfig{{Name: "vps", Keys: []TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, MasterKey: []byte("k")}}}}
	sp, mock := startedSpeaker(t, cfg)

	err := sp.AddPeer(context.Background(), &NeighborConfig{Address: netip.MustParseAddr("10.255.0.18"), ASN: 401870,
		AuthType: AuthTypeTCPAO, Keychain: "vps", EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast}})
	var want ErrTCPAOSessionBindingUnsupported
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Contains(t, err.Error(), goBGPVersion)
	assert.Empty(t, mock.peers, "no unauthenticated session is created")
}

// --- wrapper conversions ----------------------------------------------------

func TestPathConversion_RoundTrip(t *testing.T) {
	sp := &Speaker{}
	in := &Path{
		Family:      AFamilyIPv4Unicast,
		Prefix:      netip.MustParsePrefix("23.143.36.0/24"),
		NextHop:     netip.MustParseAddr("10.255.0.1"),
		Origin:      OriginIGP,
		ASPath:      []uint32{401870},
		LocalPref:   200,
		MED:         50,
		Communities: []uint32{0x6200A001},
	}
	apiPath, err := sp.pathToAPIPath(in)
	require.NoError(t, err)
	native, err := apiPathToNative(apiPath)
	require.NoError(t, err)
	assert.Equal(t, "23.143.36.0/24", native.Nlri.String())
	require.Len(t, native.Attrs, 6)

	back := nativePathToAPI(native)
	require.NotNil(t, back)
	out := sp.apiPathToPath(back, AFamilyIPv4Unicast)
	require.NotNil(t, out)
	assert.Equal(t, in.Prefix, out.Prefix, "the prefix length survives (the v3 code formatted it as a rune)")
	assert.Equal(t, in.NextHop, out.NextHop)
	assert.Equal(t, in.ASPath, out.ASPath)
	assert.Equal(t, in.LocalPref, out.LocalPref)
	assert.Equal(t, in.MED, out.MED)
	assert.Equal(t, in.Communities, out.Communities)
	assert.Equal(t, in.Origin, out.Origin)

	assert.Nil(t, nativePathToAPI(nil))
	assert.Nil(t, nativePathToAPI(&apiutil.Path{}))
	_, err = apiPathToNative(&api.Path{})
	require.Error(t, err, "a path without NLRI cannot be converted")
}

func TestPathConversion_IPv6UsesMPReach(t *testing.T) {
	sp := &Speaker{}
	apiPath, err := sp.pathToAPIPath(&Path{Family: AFamilyIPv6Unicast, Prefix: netip.MustParsePrefix("2602:f5bb::/36"), NextHop: netip.MustParseAddr("2602:f5bb:cafe:1::1")})
	require.NoError(t, err)
	native, err := apiPathToNative(apiPath)
	require.NoError(t, err)
	out := sp.apiPathToPath(nativePathToAPI(native), AFamilyIPv6Unicast)
	assert.Equal(t, netip.MustParsePrefix("2602:f5bb::/36"), out.Prefix)
	assert.Equal(t, netip.MustParseAddr("2602:f5bb:cafe:1::1"), out.NextHop)
}

func TestWrapper_WatchEventRefusesAnEmptyRequest(t *testing.T) {
	w := &gobgpServerWrapper{}
	err := w.WatchEvent(context.Background(), &api.WatchEventRequest{}, func(*api.WatchEventResponse) {})
	var want *ErrServerOperationFailed
	require.True(t, errors.As(err, &want))
	var unknown ErrWatchFilterUnknown
	require.True(t, errors.As(err, &unknown))
	require.Error(t, w.WatchEvent(context.Background(), nil, nil))
	_, err = w.AddPath(context.Background(), &api.AddPathRequest{})
	require.Error(t, err)
	require.Error(t, w.DeletePath(context.Background(), nil))
	require.Error(t, w.ListPath(context.Background(), nil, nil))
}
