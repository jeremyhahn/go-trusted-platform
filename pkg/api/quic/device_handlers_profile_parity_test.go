// createTestDeviceHandler and EncodePayload live behind the same constraint in
// device_handlers_test.go; without it the untagged lint compile of this
// package cannot see them.
//go:build codec_msgpack

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

package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

const testTLSServerName = "compute.example.internal"

// TestDeviceHandler_TLSServerName_SurvivesUpdateWithoutIt is the dark QUIC
// round trip: create with the name, get, update without it, get again. This
// handler merges the update onto the stored record itself, so the
// preservation under test is the handler's own.
func TestDeviceHandler_TLSServerName_SurvivesUpdateWithoutIt(t *testing.T) {
	handler, _, _ := createTestDeviceHandler()

	var created ProfileCreateResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceCreateProfile, &ProfileCreateRequest{
		Name: "compute", Role: "worker", TLSServerName: testTLSServerName,
	}, &created)
	require.NotNil(t, created.Profile)
	assert.Equal(t, testTLSServerName, created.Profile.TLSServerName)
	id := created.Profile.ID

	var got ProfileGetResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceGetProfile, &ProfileGetRequest{ID: id}, &got)
	assert.Equal(t, testTLSServerName, got.Profile.TLSServerName)

	var updated ProfileUpdateResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceSetProfile, &ProfileUpdateRequest{ID: id, Model: "X10SDV"}, &updated)
	assert.Equal(t, "X10SDV", updated.Profile.Model)
	assert.Equal(t, testTLSServerName, updated.Profile.TLSServerName)

	var again ProfileGetResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceGetProfile, &ProfileGetRequest{ID: id}, &again)
	assert.Equal(t, testTLSServerName, again.Profile.TLSServerName, "an update that omits tls_server_name must not erase it")
}

// TestDeviceHandler_TLSServerName_UpdateReplaces proves a caller that names
// the field still wins.
func TestDeviceHandler_TLSServerName_UpdateReplaces(t *testing.T) {
	handler, _, profiles := createTestDeviceHandler()
	profiles.profiles[9] = &entities.DeviceProfile{ID: 9, Name: "gw", TLSServerName: "old"}

	var updated ProfileUpdateResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceSetProfile, &ProfileUpdateRequest{ID: 9, TLSServerName: testTLSServerName}, &updated)
	assert.Equal(t, testTLSServerName, updated.Profile.TLSServerName)
	assert.Equal(t, testTLSServerName, profiles.profiles[9].TLSServerName)
}

// TestProfileToInfo_CarriesPCRBaseline pins the serialiser every profile
// reply goes through: the recorded baseline reaches the wire as hex digests
// keyed by register index, and a profile without one sends none.
func TestProfileToInfo_CarriesPCRBaseline(t *testing.T) {
	handler, _, _ := createTestDeviceHandler()
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	info := handler.profileToInfo(&entities.DeviceProfile{ID: 1, Name: "p", PCRBaseline: &entities.PCRBaseline{
		Values: map[int][]byte{0: {0xaa, 0xbb}, 7: {0x01}}, Source: entities.BaselineSourceTOFU, RecordedAt: recorded, RecordedFromDeviceID: 77,
	}})
	require.NotNil(t, info.PCRBaseline)
	assert.Equal(t, map[string]string{"0": "aabb", "7": "01"}, info.PCRBaseline.Values)
	assert.Equal(t, "tofu", info.PCRBaseline.Source)
	assert.Equal(t, recorded.Unix(), info.PCRBaseline.RecordedAt)
	assert.Equal(t, uint64(77), info.PCRBaseline.RecordedFromDeviceID)

	assert.Nil(t, handler.profileToInfo(&entities.DeviceProfile{ID: 2, Name: "q"}).PCRBaseline)
	assert.Nil(t, pcrBaselineEntityToInfo(nil))
	assert.Zero(t, pcrBaselineEntityToInfo(&entities.PCRBaseline{Source: entities.BaselineSourceSigned}).RecordedAt,
		"an unset recording time must not become the epoch")
}

// TestDeviceHandler_PCRBaseline_ReadOnly pins that a create or update payload
// naming pcr_baseline reaches the stored profile with none, while a get
// reports the baseline the verifier recorded.
func TestDeviceHandler_PCRBaseline_ReadOnly(t *testing.T) {
	handler, _, profiles := createTestDeviceHandler()
	// The shape a client would send if it believed the baseline were
	// settable: the request fields plus a pcr_baseline key.
	type createWithBaseline struct {
		Name        string           `codec:"name"`
		Role        string           `codec:"role"`
		PCRBaseline *PCRBaselineInfo `codec:"pcr_baseline"`
	}
	type updateWithBaseline struct {
		ID          uint64           `codec:"id"`
		Model       string           `codec:"model"`
		PCRBaseline *PCRBaselineInfo `codec:"pcr_baseline"`
	}
	supplied := &PCRBaselineInfo{Values: map[string]string{"0": "ee"}, Source: "signed", RecordedAt: 1}

	var created ProfileCreateResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceCreateProfile, &createWithBaseline{Name: "workers", Role: "worker", PCRBaseline: supplied}, &created)
	require.NotNil(t, created.Profile)
	assert.Nil(t, created.Profile.PCRBaseline, "a caller-supplied baseline must not be stored")
	assert.Nil(t, profiles.profiles[created.Profile.ID].PCRBaseline)

	// The verifier records one; the wire reports it and an update naming a
	// different one changes nothing.
	profiles.profiles[created.Profile.ID].PCRBaseline = &entities.PCRBaseline{
		Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: time.Now().UTC(),
	}
	var updated ProfileUpdateResponse
	quicDeviceCall(t, handler, quicwire.OpDeviceSetProfile, &updateWithBaseline{ID: created.Profile.ID, Model: "X10SDV", PCRBaseline: supplied}, &updated)
	require.NotNil(t, updated.Profile.PCRBaseline)
	assert.Equal(t, "tofu", updated.Profile.PCRBaseline.Source)
	assert.Equal(t, "bb", updated.Profile.PCRBaseline.Values["7"])
}
