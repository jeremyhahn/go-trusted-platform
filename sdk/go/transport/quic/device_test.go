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

// The framing assertions encode payloads through quicapi.EncodePayload, which
// resolves the MsgPack codec from go-codec's factory. That codec is only
// compiled in under codec_msgpack, so the tests carry the tag — as do the
// sibling category, provisioning and EAB framing tests they share
// recordingSender and newConnWithSender with.
//go:build codec_msgpack

package quic

import (
	"context"
	"testing"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestGRPCMethodToOpcodeMap_Device pins the device method-to-opcode
// mappings, including the UpdateProfile -> OpDeviceSetProfile mapping and
// the assignment methods multiplexed under OpProvisioningCategory.
func TestGRPCMethodToOpcodeMap_Device(t *testing.T) {
	tests := []struct {
		method string
		opcode byte
	}{
		{"/platform.v1.DeviceService/CreateDevice", quicapi.OpDeviceRegister},
		{"/platform.v1.DeviceService/DeleteDevice", quicapi.OpDeviceUnregister},
		{"/platform.v1.DeviceService/GetDevice", quicapi.OpDeviceGet},
		{"/platform.v1.DeviceService/FindDeviceBySerial", quicapi.OpDeviceGet},
		{"/platform.v1.DeviceService/ListDevices", quicapi.OpDeviceList},
		{"/platform.v1.DeviceService/CountDevices", quicapi.OpDeviceList},
		{"/platform.v1.DeviceService/UpdateDevice", quicapi.OpDeviceUpdate},
		{"/platform.v1.DeviceService/ActivateDevice", quicapi.OpDeviceActivate},
		{"/platform.v1.DeviceService/CreateProfile", quicapi.OpDeviceCreateProfile},
		{"/platform.v1.DeviceService/GetProfile", quicapi.OpDeviceGetProfile},
		{"/platform.v1.DeviceService/ListProfiles", quicapi.OpDeviceListProfiles},
		{"/platform.v1.DeviceService/CountProfiles", quicapi.OpDeviceListProfiles},
		{"/platform.v1.DeviceService/UpdateProfile", quicapi.OpDeviceSetProfile},
		{"/platform.v1.DeviceService/DeleteProfile", quicapi.OpDeviceDeleteProfile},
		{"/platform.v1.DeviceService/AssignProfileToDevice", quicapi.OpProvisioningCategory},
		{"/platform.v1.DeviceService/UnassignProfileFromDevice", quicapi.OpProvisioningCategory},
	}

	for _, tt := range tests {
		opcode, ok := grpcMethodToOpcodeMap[tt.method]
		if !ok {
			t.Errorf("method %q not mapped", tt.method)
			continue
		}
		if opcode != tt.opcode {
			t.Errorf("method %q opcode = 0x%02X, want 0x%02X", tt.method, opcode, tt.opcode)
		}
	}

	subTests := []struct {
		method string
		sub    byte
	}{
		{"/platform.v1.DeviceService/AssignProfileToDevice", quicapi.DeviceProfileSubAssign},
		{"/platform.v1.DeviceService/UnassignProfileFromDevice", quicapi.DeviceProfileSubUnassign},
		{"/platform.v1.DeviceService/RecordAttestationCertificate", quicapi.DeviceSubRecordAttestCert},
	}
	for _, tt := range subTests {
		sub, ok := categorySubOpcodeMap[tt.method]
		if !ok {
			t.Errorf("method %q has no category sub-opcode", tt.method)
			continue
		}
		if sub != tt.sub {
			t.Errorf("method %q sub-opcode = 0x%02X, want 0x%02X", tt.method, sub, tt.sub)
		}
	}
}

// TestInvoke_DeviceAssign_CategoryFraming verifies AssignProfileToDevice
// travels under OpProvisioningCategory with the DeviceProfileSubAssign
// prefix, that the remaining payload is the codec-encoded pb request, and
// that the pb response decodes into the caller's reply.
func TestInvoke_DeviceAssign_CategoryFraming(t *testing.T) {
	respPayload, err := quicapi.EncodePayload(&platformv1.AssignProfileToDeviceResponse{
		Profile: &platformv1.DeviceProfile{
			Id:       300,
			EkSerial: "EK-3003",
			Assigned: true,
		},
	})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}

	sender := &recordingSender{respPayload: respPayload}
	conn := newConnWithSender(t, sender)

	var reply platformv1.AssignProfileToDeviceResponse
	err = conn.Invoke(context.Background(),
		"/platform.v1.DeviceService/AssignProfileToDevice",
		&platformv1.AssignProfileToDeviceRequest{
			ProfileId:  300,
			EkSerial:   "EK-3003",
			MacAddress: "00:25:90:ff:aa:02",
			EkCert:     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		},
		&reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if sender.rawCalls != 1 {
		t.Fatalf("expected 1 SendRequest call, got %d", sender.rawCalls)
	}
	if sender.rawOpcode != quicapi.OpProvisioningCategory {
		t.Errorf("opcode = 0x%02X, want OpProvisioningCategory", sender.rawOpcode)
	}
	if len(sender.rawPayload) < 2 || sender.rawPayload[0] != quicapi.DeviceProfileSubAssign {
		t.Fatalf("payload[0] = 0x%02X, want DeviceProfileSubAssign", sender.rawPayload[0])
	}

	// The remainder must be the codec-encoded pb request.
	var decoded platformv1.AssignProfileToDeviceRequest
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &decoded); err != nil {
		t.Fatalf("decode framed request: %v", err)
	}
	if decoded.GetProfileId() != 300 || decoded.GetEkSerial() != "EK-3003" || decoded.GetEkCert() == "" {
		t.Errorf("framed request = %+v, fields lost on the wire", &decoded)
	}

	if reply.GetProfile().GetId() != 300 || !reply.GetProfile().GetAssigned() {
		t.Errorf("reply = %+v, want assigned profile 300", reply.GetProfile())
	}
}

// TestInvoke_DeviceUnassign_CategoryFraming verifies
// UnassignProfileFromDevice travels under OpProvisioningCategory with the
// DeviceProfileSubUnassign prefix.
func TestInvoke_DeviceUnassign_CategoryFraming(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(),
		"/platform.v1.DeviceService/UnassignProfileFromDevice",
		&platformv1.UnassignProfileFromDeviceRequest{ProfileId: 400},
		nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if sender.rawOpcode != quicapi.OpProvisioningCategory {
		t.Errorf("opcode = 0x%02X, want OpProvisioningCategory", sender.rawOpcode)
	}
	if len(sender.rawPayload) < 2 || sender.rawPayload[0] != quicapi.DeviceProfileSubUnassign {
		t.Fatalf("payload[0] = 0x%02X, want DeviceProfileSubUnassign", sender.rawPayload[0])
	}
	var decoded platformv1.UnassignProfileFromDeviceRequest
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &decoded); err != nil {
		t.Fatalf("decode framed request: %v", err)
	}
	if decoded.GetProfileId() != 400 {
		t.Errorf("ProfileId = %d, want 400", decoded.GetProfileId())
	}
}

// TestInvoke_UpdateProfile_UsesSetProfileOpcode verifies UpdateProfile
// takes the standard (non-category) path on OpDeviceSetProfile.
func TestInvoke_UpdateProfile_UsesSetProfileOpcode(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(),
		"/platform.v1.DeviceService/UpdateProfile",
		&platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{Id: 42}},
		&platformv1.UpdateProfileResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if sender.encCalls != 1 {
		t.Fatalf("expected 1 Send call, got %d (raw calls: %d)", sender.encCalls, sender.rawCalls)
	}
	if sender.encOpcode != quicapi.OpDeviceSetProfile {
		t.Errorf("opcode = 0x%02X, want OpDeviceSetProfile", sender.encOpcode)
	}
}

// TestInvoke_CountDevices_DerivedFromListReply verifies the CountDevices
// reply is projected from the ListDevicesResponse pagination totals.
func TestInvoke_CountDevices_DerivedFromListReply(t *testing.T) {
	respPayload, err := quicapi.EncodePayload(&platformv1.ListDevicesResponse{
		Pagination: &platformv1.PaginationResponse{TotalItems: 9},
	})
	if err != nil {
		t.Fatalf("encode list response: %v", err)
	}

	sender := &recordingSender{respPayload: respPayload}
	conn := newConnWithSender(t, sender)

	var reply platformv1.CountDevicesResponse
	err = conn.Invoke(context.Background(),
		"/platform.v1.DeviceService/CountDevices",
		&platformv1.CountDevicesRequest{},
		&reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if sender.rawCalls != 1 {
		t.Fatalf("expected raw SendRequest path, got Send calls: %d", sender.encCalls)
	}
	if sender.rawOpcode != quicapi.OpDeviceList {
		t.Errorf("opcode = 0x%02X, want OpDeviceList", sender.rawOpcode)
	}
	if reply.GetCount() != 9 {
		t.Errorf("Count = %d, want 9", reply.GetCount())
	}
}

// TestInvoke_CountProfiles_DerivedFromListReply verifies the
// CountProfiles reply is projected from the ListProfilesResponse
// pagination totals.
func TestInvoke_CountProfiles_DerivedFromListReply(t *testing.T) {
	respPayload, err := quicapi.EncodePayload(&platformv1.ListProfilesResponse{
		Pagination: &platformv1.PaginationResponse{TotalItems: 4},
	})
	if err != nil {
		t.Fatalf("encode list response: %v", err)
	}

	sender := &recordingSender{respPayload: respPayload}
	conn := newConnWithSender(t, sender)

	var reply platformv1.CountProfilesResponse
	err = conn.Invoke(context.Background(),
		"/platform.v1.DeviceService/CountProfiles",
		&platformv1.CountProfilesRequest{},
		&reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if reply.GetCount() != 4 {
		t.Errorf("Count = %d, want 4", reply.GetCount())
	}
}

// TestDecodeDeviceCountReply_InvalidReplyType verifies the decoders
// reject a mismatched reply message with a typed error.
func TestDecodeDeviceCountReply_InvalidReplyType(t *testing.T) {
	if err := decodeDeviceCountReply(nil, &platformv1.ListDevicesResponse{}); err == nil {
		t.Error("decodeDeviceCountReply accepted wrong reply type")
	}
	if err := decodeProfileCountReply(nil, &platformv1.ListProfilesResponse{}); err == nil {
		t.Error("decodeProfileCountReply accepted wrong reply type")
	}
}
