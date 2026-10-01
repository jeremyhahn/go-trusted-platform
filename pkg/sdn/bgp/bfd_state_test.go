// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Per-peer prefix counters and BFD session state feed the gateway snapshot
// (#594); both come from the peer GoBGP reports, never from configuration.

func peerWithFamilies(afiSafis []*api.AfiSafi, bfd *api.BfdPeerConfig, bfdState *api.BfdPeerState) *api.Peer {
	return &api.Peer{
		Conf:     &api.PeerConf{NeighborAddress: "10.255.0.2", PeerAsn: 64512},
		State:    &api.PeerState{SessionState: api.PeerState_SESSION_STATE_ESTABLISHED, BfdState: bfdState},
		Bfd:      bfd,
		AfiSafis: append([]*api.AfiSafi(nil), afiSafis...),
	}
}

func TestPeerToPeerInfo_PrefixCountersSumAcrossFamilies(t *testing.T) {
	speaker, err := NewSpeaker(speakerTestConfig(), speakerTestLogger(), WithBGPServer(newMockBGPServer()))
	require.NoError(t, err)

	info := speaker.peerToPeerInfo(peerWithFamilies([]*api.AfiSafi{
		{
			Config: &api.AfiSafiConfig{Enabled: true, Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}},
			State:  &api.AfiSafiState{Received: 120, Accepted: 118, Advertised: 3},
		},
		{
			Config: &api.AfiSafiConfig{Enabled: true, Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}},
			State:  &api.AfiSafiState{Received: 40, Accepted: 40, Advertised: 1},
		},
	}, nil, nil))

	require.NotNil(t, info)
	assert.Equal(t, int64(160), info.PrefixesReceived)
	assert.Equal(t, int64(158), info.PrefixesAccepted, "max-prefix and import policy rejections show as the gap")
	assert.Equal(t, int64(4), info.PrefixesSent)
	assert.Len(t, info.EnabledFamilies, 2)
}

func TestPeerToPeerInfo_PrefixCountersWithoutFamilyState(t *testing.T) {
	speaker, err := NewSpeaker(speakerTestConfig(), speakerTestLogger(), WithBGPServer(newMockBGPServer()))
	require.NoError(t, err)

	info := speaker.peerToPeerInfo(peerWithFamilies([]*api.AfiSafi{
		{Config: &api.AfiSafiConfig{Enabled: true, Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}},
	}, nil, nil))

	require.NotNil(t, info)
	assert.Zero(t, info.PrefixesReceived, "a family GoBGP reports no state for counts nothing")
	assert.Zero(t, info.PrefixesAccepted)
	assert.Zero(t, info.PrefixesSent)
}

func TestPeerToPeerInfo_BFDSessionReported(t *testing.T) {
	speaker, err := NewSpeaker(speakerTestConfig(), speakerTestLogger(), WithBGPServer(newMockBGPServer()))
	require.NoError(t, err)

	failure := time.Date(2026, 9, 8, 21, 15, 0, 0, time.UTC)
	info := speaker.peerToPeerInfo(peerWithFamilies(nil,
		&api.BfdPeerConfig{
			Enabled:                  true,
			Port:                     3784,
			DesiredMinimumTxInterval: 300000,
			RequiredMinimumReceive:   300000,
			DetectionMultiplier:      3,
		},
		&api.BfdPeerState{
			SessionState:         api.BfdSessionState_BFD_SESSION_STATE_UP,
			RemoteSessionState:   api.BfdSessionState_BFD_SESSION_STATE_UP,
			LocalDiscriminator:   7,
			RemoteDiscriminator:  9,
			FailureTransitions:   2,
			LastFailureTime:      uint64(failure.Unix()),
			LocalDiagnosticCode:  api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_DETECTION_TIMEOUT,
			RemoteDiagnosticCode: api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC,
		}))

	require.NotNil(t, info)
	require.NotNil(t, info.BFD)
	assert.Equal(t, BFDSessionUp, info.BFD.LocalState)
	assert.Equal(t, BFDSessionUp, info.BFD.RemoteState)
	assert.Equal(t, uint32(7), info.BFD.LocalDiscriminator)
	assert.Equal(t, uint32(9), info.BFD.RemoteDiscriminator)
	assert.Equal(t, uint64(2), info.BFD.FailureTransitions)
	assert.Equal(t, failure, info.BFD.LastFailure)
	assert.Equal(t, "detection-timeout", info.BFD.LocalDiagnostic)
	assert.Equal(t, "none", info.BFD.RemoteDiagnostic)
	assert.Equal(t, 300*time.Millisecond, info.BFD.DesiredMinTxInterval)
	assert.Equal(t, 300*time.Millisecond, info.BFD.RequiredMinRxInterval)
	assert.Equal(t, uint8(3), info.BFD.DetectionMultiplier)
}

func TestPeerToPeerInfo_BFDAbsentOrUnnegotiated(t *testing.T) {
	speaker, err := NewSpeaker(speakerTestConfig(), speakerTestLogger(), WithBGPServer(newMockBGPServer()))
	require.NoError(t, err)

	t.Run("bfd not configured", func(t *testing.T) {
		info := speaker.peerToPeerInfo(peerWithFamilies(nil, nil, nil))
		require.NotNil(t, info)
		assert.Nil(t, info.BFD, "a peer without BFD reports no session")
	})

	t.Run("bfd configured but disabled", func(t *testing.T) {
		info := speaker.peerToPeerInfo(peerWithFamilies(nil, &api.BfdPeerConfig{Enabled: false}, nil))
		require.NotNil(t, info)
		assert.Nil(t, info.BFD)
	})

	t.Run("bfd enabled before the session comes up", func(t *testing.T) {
		info := speaker.peerToPeerInfo(peerWithFamilies(nil,
			&api.BfdPeerConfig{Enabled: true, DetectionMultiplier: 3}, nil))
		require.NotNil(t, info)
		require.NotNil(t, info.BFD)
		assert.Equal(t, BFDSessionUnknown, info.BFD.LocalState, "no state is unknown, not down")
		assert.Equal(t, BFDSessionUnknown, info.BFD.RemoteState)
		assert.Zero(t, info.BFD.LocalDiscriminator)
		assert.True(t, info.BFD.LastFailure.IsZero())
	})

	t.Run("a detection multiplier beyond a byte is clamped", func(t *testing.T) {
		info := speaker.peerToPeerInfo(peerWithFamilies(nil,
			&api.BfdPeerConfig{Enabled: true, DetectionMultiplier: 4096}, nil))
		require.NotNil(t, info.BFD)
		assert.Equal(t, uint8(255), info.BFD.DetectionMultiplier)
	})
}

func TestBFDStateAndDiagnosticMapping(t *testing.T) {
	states := map[api.BfdSessionState]BFDSessionState{
		api.BfdSessionState_BFD_SESSION_STATE_UP:          BFDSessionUp,
		api.BfdSessionState_BFD_SESSION_STATE_DOWN:        BFDSessionDown,
		api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN:  BFDSessionAdminDown,
		api.BfdSessionState_BFD_SESSION_STATE_INIT:        BFDSessionInit,
		api.BfdSessionState_BFD_SESSION_STATE_UNSPECIFIED: BFDSessionUnknown,
	}
	for in, want := range states {
		assert.Equal(t, want, bfdSessionStateToState(in))
	}
	assert.Equal(t, BFDSessionUnknown, bfdSessionStateToState(api.BfdSessionState(99)))

	assert.Equal(t, "path-down", bfdDiagnosticName(api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_PATH_DOWN))
	assert.Equal(t, "code-42", bfdDiagnosticName(api.BfdDiagnosticCode(42)), "an unmapped code is reported by number")
}
