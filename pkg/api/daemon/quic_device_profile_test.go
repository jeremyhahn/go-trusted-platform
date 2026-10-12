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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The tests in this file exercise the daemon-side QUIC device handlers
// against the canonical wire contract: the platform.v1 protobuf
// request/response messages encoded with the QUIC payload codec, exactly
// as the SDK QUIC transport adapter sends them.

// newQUICDeviceProfileHandler builds a QUICServiceHandler backed by the
// shared mock device and profile services.
func newQUICDeviceProfileHandler(t *testing.T) (*QUICServiceHandler, *mockProfileService) {
	t.Helper()
	profileSvc := newMockProfileService()
	handler := newTestQUICServiceHandler(
		logging.DefaultLogger(),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(profileSvc),
	)
	return handler, profileSvc
}

// encodeQUICRequest encodes v as a QUIC request payload for opcode.
func encodeQUICRequest(t *testing.T, opcode byte, v interface{}) *quicwire.Request {
	t.Helper()
	payload, err := quicwire.EncodePayload(v)
	require.NoError(t, err)
	return &quicwire.Request{Opcode: opcode, Payload: payload}
}

// encodeQUICCategoryRequest encodes v prefixed with a sub-opcode byte,
// mirroring the SDK category-opcode framing (payload[0] = sub-opcode).
func encodeQUICCategoryRequest(t *testing.T, opcode, subOpcode byte, v interface{}) *quicwire.Request {
	t.Helper()
	payload, err := quicwire.EncodePayload(v)
	require.NoError(t, err)
	framed := append([]byte{subOpcode}, payload...)
	return &quicwire.Request{Opcode: opcode, Payload: framed}
}

// decodeQUICResponse decodes a StatusOK QUIC response payload into out.
func decodeQUICResponse(t *testing.T, resp *quicwire.Response, out interface{}) {
	t.Helper()
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload: %s", string(resp.Payload))
	require.NoError(t, quicwire.DecodePayload(resp.Payload, out))
}

// TestQUICDeviceCreateProfile_EKPrestageFields verifies the QUIC create
// path persists and echoes the device-identity, EK-cert prestage, config,
// and assignment fields using the pb wire shapes (transport parity with
// gRPC and REST).
func TestQUICDeviceCreateProfile_EKPrestageFields(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ekCert := newEKCertPEMForTest(t)

	req := encodeQUICRequest(t, quicwire.OpDeviceCreateProfile, &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:       "node-02",
			Model:      "X10SDV",
			Role:       platformv1.DeviceRole_DEVICE_ROLE_SERVER,
			EkSerial:   "EK-1001",
			MacAddress: "00:25:90:ff:aa:02",
			EkCert:     ekCert,
			Config:     []byte(`{"hostname":"node-02"}`),
		},
	})

	resp := handler.HandleRequest(context.Background(), req)

	var created platformv1.CreateProfileResponse
	decodeQUICResponse(t, resp, &created)
	require.NotNil(t, created.GetProfile())
	assert.NotZero(t, created.GetProfile().GetId())
	assert.Equal(t, "EK-1001", created.GetProfile().GetEkSerial())
	assert.Equal(t, "00:25:90:ff:aa:02", created.GetProfile().GetMacAddress())
	assert.Equal(t, ekCert, created.GetProfile().GetEkCert())
	assert.Equal(t, []byte(`{"hostname":"node-02"}`), created.GetProfile().GetConfig())

	stored := profileSvc.profiles[created.GetProfile().GetId()]
	require.NotNil(t, stored)
	assert.Equal(t, "EK-1001", stored.EKSerial)
	assert.Equal(t, ekCert, stored.EKCert)
}

// TestQUICDeviceCreateProfile_InvalidEKCert verifies an unparseable EK
// certificate is rejected at the QUIC boundary.
func TestQUICDeviceCreateProfile_InvalidEKCert(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)

	req := encodeQUICRequest(t, quicwire.OpDeviceCreateProfile, &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:   "bad-cert",
			EkCert: "not a pem certificate",
		},
	})

	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// TestQUICDeviceCreateProfile_InvalidConfig verifies config bytes that are
// not valid JSON are rejected at the QUIC boundary.
func TestQUICDeviceCreateProfile_InvalidConfig(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)

	req := encodeQUICRequest(t, quicwire.OpDeviceCreateProfile, &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:   "bad-config",
			Config: []byte("{not-json"),
		},
	})

	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// TestQUICDeviceSetProfile_FullReplace verifies OpDeviceSetProfile has
// gRPC UpdateProfile semantics: the profile carried in the request
// replaces the stored profile.
func TestQUICDeviceSetProfile_FullReplace(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ekCert := newEKCertPEMForTest(t)

	profileSvc.profiles[42] = &entities.DeviceProfile{
		ID:   42,
		Name: "before",
	}

	req := encodeQUICRequest(t, quicwire.OpDeviceSetProfile, &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:         42,
			Name:       "after",
			EkSerial:   "EK-2002",
			MacAddress: "52:54:00:ab:cd:ef",
			EkCert:     ekCert,
		},
	})

	resp := handler.HandleRequest(context.Background(), req)

	var updated platformv1.UpdateProfileResponse
	decodeQUICResponse(t, resp, &updated)
	assert.Equal(t, "after", updated.GetProfile().GetName())
	assert.Equal(t, "EK-2002", updated.GetProfile().GetEkSerial())

	stored := profileSvc.profiles[42]
	require.NotNil(t, stored)
	assert.Equal(t, "after", stored.Name)
	assert.Equal(t, "EK-2002", stored.EKSerial)
	assert.Equal(t, "52:54:00:ab:cd:ef", stored.MACAddress)
	assert.Equal(t, ekCert, stored.EKCert)
}

// TestQUICDeviceSetProfile_Errors verifies invalid update requests map to
// the QUIC error statuses.
func TestQUICDeviceSetProfile_Errors(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)
	ctx := context.Background()

	t.Run("MissingProfile", func(t *testing.T) {
		req := encodeQUICRequest(t, quicwire.OpDeviceSetProfile, &platformv1.UpdateProfileRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		req := encodeQUICRequest(t, quicwire.OpDeviceSetProfile, &platformv1.UpdateProfileRequest{
			Profile: &platformv1.DeviceProfile{Id: 9999, Name: "ghost"},
		})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		req := encodeQUICRequest(t, quicwire.OpDeviceSetProfile, &platformv1.UpdateProfileRequest{
			Profile: &platformv1.DeviceProfile{Id: 7, EkCert: "garbage"},
		})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// TestQUICDeviceGetProfile_EKPrestageFields verifies the QUIC get path
// echoes the identity / prestage / assignment fields through the pb
// response shape.
func TestQUICDeviceGetProfile_EKPrestageFields(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ekCert := newEKCertPEMForTest(t)

	profileSvc.profiles[77] = &entities.DeviceProfile{
		ID:         77,
		Name:       "prestaged",
		EKSerial:   "EK-7007",
		MACAddress: "00:25:90:aa:bb:cc",
		EKCert:     ekCert,
		Assigned:   true,
	}

	req := encodeQUICRequest(t, quicwire.OpDeviceGetProfile, &platformv1.GetProfileRequest{Id: 77})
	resp := handler.HandleRequest(context.Background(), req)

	var got platformv1.GetProfileResponse
	decodeQUICResponse(t, resp, &got)
	assert.Equal(t, uint64(77), got.GetProfile().GetId())
	assert.Equal(t, "EK-7007", got.GetProfile().GetEkSerial())
	assert.Equal(t, ekCert, got.GetProfile().GetEkCert())
	assert.True(t, got.GetProfile().GetAssigned())
}

// TestQUICDeviceGetProfile_NotFound verifies a missing profile maps to
// StatusNotFound.
func TestQUICDeviceGetProfile_NotFound(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)

	req := encodeQUICRequest(t, quicwire.OpDeviceGetProfile, &platformv1.GetProfileRequest{Id: 4040})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
}

// TestQUICDeviceListProfiles_CountViaPagination verifies the list reply
// carries the total profile count in the pagination so the SDK can derive
// CountProfilesResponse from the same wire payload.
func TestQUICDeviceListProfiles_CountViaPagination(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "a"}
	profileSvc.profiles[2] = &entities.DeviceProfile{ID: 2, Name: "b"}

	req := encodeQUICRequest(t, quicwire.OpDeviceListProfiles, &platformv1.ListProfilesRequest{})
	resp := handler.HandleRequest(context.Background(), req)

	var list platformv1.ListProfilesResponse
	decodeQUICResponse(t, resp, &list)
	assert.Len(t, list.GetProfiles(), 2)
	require.NotNil(t, list.GetPagination())
	assert.Equal(t, uint64(2), list.GetPagination().GetTotalItems())
}

// TestQUICDeviceProfileAssign_HappyPath verifies the assignment
// sub-opcode binds the EK identity and prestages the EK certificate.
func TestQUICDeviceProfileAssign_HappyPath(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ekCert := newEKCertPEMForTest(t)

	profileSvc.profiles[300] = &entities.DeviceProfile{ID: 300, Name: "assign-me"}

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
		&platformv1.AssignProfileToDeviceRequest{
			ProfileId:  300,
			EkSerial:   "EK-3003",
			MacAddress: "00:25:90:dd:ee:ff",
			EkCert:     ekCert,
		})

	resp := handler.HandleRequest(context.Background(), req)

	var assigned platformv1.AssignProfileToDeviceResponse
	decodeQUICResponse(t, resp, &assigned)
	assert.Equal(t, uint64(300), assigned.GetProfile().GetId())
	assert.True(t, assigned.GetProfile().GetAssigned())
	assert.Equal(t, "EK-3003", assigned.GetProfile().GetEkSerial())
	assert.Equal(t, ekCert, assigned.GetProfile().GetEkCert())

	stored := profileSvc.profiles[300]
	assert.True(t, stored.Assigned)
	assert.Equal(t, ekCert, stored.EKCert)
	assert.False(t, stored.AssignedAt.IsZero())
}

// TestQUICDeviceProfileAssign_Errors verifies boundary validation on the
// assignment sub-opcode.
func TestQUICDeviceProfileAssign_Errors(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ctx := context.Background()
	profileSvc.profiles[301] = &entities.DeviceProfile{ID: 301, Name: "p"}

	t.Run("MissingProfileID", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
			&platformv1.AssignProfileToDeviceRequest{EkSerial: "EK-1"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("MissingIdentity", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
			&platformv1.AssignProfileToDeviceRequest{ProfileId: 301})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
			&platformv1.AssignProfileToDeviceRequest{ProfileId: 301, EkSerial: "EK-1", EkCert: "junk"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
			&platformv1.AssignProfileToDeviceRequest{ProfileId: 999999, EkSerial: "EK-1"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger())
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign,
			&platformv1.AssignProfileToDeviceRequest{ProfileId: 301, EkSerial: "EK-1"})
		resp := bare.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

// TestQUICDeviceProfileUnassign verifies the unassign sub-opcode clears
// the device binding, and validates its error paths.
func TestQUICDeviceProfileUnassign(t *testing.T) {
	handler, profileSvc := newQUICDeviceProfileHandler(t)
	ctx := context.Background()

	profileSvc.profiles[400] = &entities.DeviceProfile{
		ID:       400,
		Name:     "bound",
		EKSerial: "EK-4004",
		EKCert:   newEKCertPEMForTest(t),
		Assigned: true,
	}

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubUnassign,
		&platformv1.UnassignProfileFromDeviceRequest{ProfileId: 400})
	resp := handler.HandleRequest(ctx, req)

	var unassigned platformv1.UnassignProfileFromDeviceResponse
	decodeQUICResponse(t, resp, &unassigned)
	assert.False(t, unassigned.GetProfile().GetAssigned())
	assert.Empty(t, unassigned.GetProfile().GetEkSerial())
	assert.Empty(t, unassigned.GetProfile().GetEkCert())

	stored := profileSvc.profiles[400]
	assert.False(t, stored.Assigned)
	assert.Empty(t, stored.EKSerial)
	assert.Empty(t, stored.EKCert)

	t.Run("MissingProfileID", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubUnassign,
			&platformv1.UnassignProfileFromDeviceRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubUnassign,
			&platformv1.UnassignProfileFromDeviceRequest{ProfileId: 888888})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// TestQUICDeviceRegisterGetDelete verifies the device CRUD path over the
// pb wire shapes, including the OpDeviceGet union (Id vs Serial).
func TestQUICDeviceRegisterGetDelete(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)
	ctx := context.Background()

	createReq := encodeQUICRequest(t, quicwire.OpDeviceRegister, &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{
			Id:     5001,
			Serial: "SN-5001",
			Model:  "X10SDV",
		},
	})
	resp := handler.HandleRequest(ctx, createReq)
	var created platformv1.CreateDeviceResponse
	decodeQUICResponse(t, resp, &created)
	assert.Equal(t, uint64(5001), created.GetDevice().GetId())

	// Get by ID (GetDeviceRequest shape).
	getReq := encodeQUICRequest(t, quicwire.OpDeviceGet, &platformv1.GetDeviceRequest{Id: 5001})
	resp = handler.HandleRequest(ctx, getReq)
	var got platformv1.GetDeviceResponse
	decodeQUICResponse(t, resp, &got)
	assert.Equal(t, "SN-5001", got.GetDevice().GetSerial())

	// Get by serial (FindDeviceBySerialRequest shape on the same opcode).
	findReq := encodeQUICRequest(t, quicwire.OpDeviceGet, &platformv1.FindDeviceBySerialRequest{Serial: "SN-5001"})
	resp = handler.HandleRequest(ctx, findReq)
	var found platformv1.FindDeviceBySerialResponse
	decodeQUICResponse(t, resp, &found)
	assert.Equal(t, uint64(5001), found.GetDevice().GetId())

	// List carries the count in the pagination totals.
	listReq := encodeQUICRequest(t, quicwire.OpDeviceList, &platformv1.ListDevicesRequest{})
	resp = handler.HandleRequest(ctx, listReq)
	var list platformv1.ListDevicesResponse
	decodeQUICResponse(t, resp, &list)
	assert.Len(t, list.GetDevices(), 1)
	assert.Equal(t, uint64(1), list.GetPagination().GetTotalItems())

	// Delete.
	deleteReq := encodeQUICRequest(t, quicwire.OpDeviceUnregister, &platformv1.DeleteDeviceRequest{Id: 5001})
	resp = handler.HandleRequest(ctx, deleteReq)
	var deleted platformv1.DeleteDeviceResponse
	decodeQUICResponse(t, resp, &deleted)
	assert.True(t, deleted.GetStatus().GetSuccess())
}

// TestQUICDeviceRegister_MissingDevice verifies an empty create request
// is rejected with InvalidArgument.
func TestQUICDeviceRegister_MissingDevice(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)

	req := encodeQUICRequest(t, quicwire.OpDeviceRegister, &platformv1.CreateDeviceRequest{})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}
