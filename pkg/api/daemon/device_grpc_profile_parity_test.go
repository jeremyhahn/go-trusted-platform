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

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testTLSServerName = "compute.example.internal"

// newRealProfileService builds the production profile service over the
// in-memory storage mock so the round trips below exercise the service's
// own preservation rules rather than a test double's.
func newRealProfileService(t *testing.T) *device.ProfileService {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	svc, err := device.NewProfileService(device.NewDatastore(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	return svc
}

func testBaseline(recorded time.Time) *entities.PCRBaseline {
	return &entities.PCRBaseline{
		Values:               map[int][]byte{0: {0xaa}, 7: {0xbb}},
		Source:               entities.BaselineSourceTOFU,
		RecordedAt:           recorded,
		RecordedFromDeviceID: 77,
	}
}

// TestDeviceGRPCService_Conversions_CarryTLSServerName pins that the
// pb<->entity conversions behind gRPC, Unix and the live QUIC dispatcher carry
// tls_server_name in both directions (#430, #448).
func TestDeviceGRPCService_Conversions_CarryTLSServerName(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	entity, err := svc.pbToProfile(&platformv1.DeviceProfile{Id: 1, Name: "p", TlsServerName: testTLSServerName})
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, entity.TLSServerName)

	pb := svc.profileToPb(&entities.DeviceProfile{ID: 1, Name: "p", TLSServerName: testTLSServerName})
	assert.Equal(t, testTLSServerName, pb.GetTlsServerName())

	// Absent stays absent in both directions.
	empty, err := svc.pbToProfile(&platformv1.DeviceProfile{Id: 2, Name: "q"})
	require.NoError(t, err)
	assert.Empty(t, empty.TLSServerName)
	assert.Empty(t, svc.profileToPb(&entities.DeviceProfile{ID: 2, Name: "q"}).GetTlsServerName())
}

// TestDeviceGRPCService_ProfileToPb_CarriesPCRBaseline pins the read side:
// a recorded baseline reaches the wire with its digests, source, timestamp
// and seeding device, and a profile without one sends none.
func TestDeviceGRPCService_ProfileToPb_CarriesPCRBaseline(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	pb := svc.profileToPb(&entities.DeviceProfile{ID: 1, Name: "p", PCRBaseline: testBaseline(recorded)})
	require.NotNil(t, pb.GetPcrBaseline())
	assert.Equal(t, []byte{0xbb}, pb.GetPcrBaseline().GetValues()[7])
	assert.Equal(t, "tofu", pb.GetPcrBaseline().GetSource())
	assert.True(t, recorded.Equal(pb.GetPcrBaseline().GetRecordedAt().AsTime()))
	assert.Equal(t, uint64(77), pb.GetPcrBaseline().GetRecordedFromDeviceId())

	assert.Nil(t, svc.profileToPb(&entities.DeviceProfile{ID: 2, Name: "q"}).GetPcrBaseline(),
		"no baseline recorded must be an unset field, not an empty message")
}

// TestDeviceGRPCService_PbToProfile_IgnoresPCRBaseline pins the read-only
// rule (#373, #448): a pb that names pcr_baseline reaches the entity with
// none. Making pbToProfile copy the field must fail this test.
func TestDeviceGRPCService_PbToProfile_IgnoresPCRBaseline(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	entity, err := svc.pbToProfile(&platformv1.DeviceProfile{
		Id: 1, Name: "p",
		PcrBaseline: &platformv1.PCRBaseline{
			Values:     map[uint32][]byte{0: {0x01}},
			Source:     "signed",
			RecordedAt: timestamppb.Now(),
		},
	})
	require.NoError(t, err)
	assert.Nil(t, entity.PCRBaseline, "a caller-supplied baseline must never reach the entity")
}

// TestDeviceGRPCService_TLSServerName_SurvivesUpdateWithoutIt is the
// transport round trip: create with the name, read it back, update without
// naming it (a full-replace UpdateProfile from a client that predates the
// field), read it back again. gRPC, Unix and the live QUIC dispatcher all
// route through this service over the real ProfileService.
func TestDeviceGRPCService_TLSServerName_SurvivesUpdateWithoutIt(t *testing.T) {
	ctx := context.Background()
	svc := NewDeviceGRPCService(newMockDeviceService(), newRealProfileService(t), nil)

	created, err := svc.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4480, Name: "compute", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER, TlsServerName: testTLSServerName,
	}})
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, created.GetProfile().GetTlsServerName())

	got, err := svc.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 4480})
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, got.GetProfile().GetTlsServerName(), "the name must be readable after create")

	updated, err := svc.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4480, Name: "compute-renamed", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER,
	}})
	require.NoError(t, err)
	assert.Equal(t, "compute-renamed", updated.GetProfile().GetName())
	assert.Equal(t, testTLSServerName, updated.GetProfile().GetTlsServerName(), "the update response must report the preserved name")

	again, err := svc.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 4480})
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, again.GetProfile().GetTlsServerName(), "an update that omits tls_server_name must not erase it")

	// A caller that names the field still wins.
	replaced, err := svc.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4480, Name: "compute-renamed", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER, TlsServerName: "gw.example.internal",
	}})
	require.NoError(t, err)
	assert.Equal(t, "gw.example.internal", replaced.GetProfile().GetTlsServerName())
}

// TestDeviceGRPCService_PCRBaseline_ReadOnlyRoundTrip is the #448 round
// trip: create profile -> verifier-style baseline write -> get shows it ->
// update without it (and an update that tries to overwrite it) -> get still
// shows the recorded one.
func TestDeviceGRPCService_PCRBaseline_ReadOnlyRoundTrip(t *testing.T) {
	ctx := context.Background()
	profiles := newRealProfileService(t)
	svc := NewDeviceGRPCService(newMockDeviceService(), profiles, nil)
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	_, err := svc.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4481, Name: "workers", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER,
	}})
	require.NoError(t, err)

	// The verifier is the one legitimate writer: it goes through the service
	// with the entity, exactly as the in-process TOFU capture does.
	stored, err := profiles.Get(ctx, 4481)
	require.NoError(t, err)
	stored.PCRBaseline = testBaseline(recorded)
	require.NoError(t, profiles.Update(ctx, stored))

	got, err := svc.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 4481})
	require.NoError(t, err)
	require.NotNil(t, got.GetProfile().GetPcrBaseline(), "the recorded baseline must be readable")
	assert.Equal(t, "tofu", got.GetProfile().GetPcrBaseline().GetSource())

	// An update that omits the baseline keeps it ...
	_, err = svc.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4481, Name: "workers-renamed", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER,
	}})
	require.NoError(t, err)

	// ... and an update that supplies one is ignored, not honoured.
	_, err = svc.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 4481, Name: "workers-renamed", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER,
		PcrBaseline: &platformv1.PCRBaseline{Values: map[uint32][]byte{0: {0xee}}, Source: "signed", RecordedAt: timestamppb.Now()},
	}})
	require.NoError(t, err)

	again, err := svc.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 4481})
	require.NoError(t, err)
	require.NotNil(t, again.GetProfile().GetPcrBaseline(), "an update that cannot carry the baseline must not erase it")
	assert.Equal(t, "tofu", again.GetProfile().GetPcrBaseline().GetSource(), "a caller-supplied baseline must not replace the recorded one")
	assert.Equal(t, []byte{0xbb}, again.GetProfile().GetPcrBaseline().GetValues()[7])
	assert.True(t, recorded.Equal(again.GetProfile().GetPcrBaseline().GetRecordedAt().AsTime()))
	assert.Equal(t, "workers-renamed", again.GetProfile().GetName())
}
