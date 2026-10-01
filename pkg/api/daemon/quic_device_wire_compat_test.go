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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the device
// surface between the platform SDK client and the daemon. The canonical
// contract is the platform.v1 protobuf messages themselves: the SDK QUIC
// transport adapter encodes the pb request structs directly and the
// daemon decodes the payload into the same pb types (and vice versa for
// responses). Every message is round-tripped through the payload codec
// (encode SDK-side shape -> decode daemon-side shape) and compared with
// proto.Equal so a codec or field-shape regression on either side fails
// here first.

// roundTripDeviceWire encodes src through the QUIC payload codec and
// decodes it into dst, failing the test on error.
func roundTripDeviceWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quic.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quic.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

// compatTestProfile builds a fully-populated DeviceProfile covering the
// identity (ek_serial, mac_address), prestage (ek_cert), config,
// assignment, enum, timestamp, map, and nested-message fields, plus the
// collector's tls_server_name and the read-only pcr_baseline (#448) so a
// codec regression on either new field fails here.
func compatTestProfile() *platformv1.DeviceProfile {
	return &platformv1.DeviceProfile{
		Id:                    12345,
		TenantId:              "tenant-a",
		Name:                  "node-02",
		Model:                 "X10SDV-TP8F",
		Role:                  platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		EventLog:              []byte{0x01, 0x02, 0x03},
		Zone:                  "control-plane",
		EnrollmentNetwork:     "provisioning",
		PostEnrollmentNetwork: "control-plane",
		FailureNetwork:        "quarantine",
		EkSerial:              "1234567890",
		MacAddress:            "00:25:90:ff:aa:02",
		EkCert:                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		Config:                []byte(`{"hostname":"node-02"}`),
		Assigned:              true,
		AssignedAt:            timestamppb.New(time.Unix(1750000000, 0).UTC()),
		TlsServerName:         "compute.example.internal",
		PcrBaseline: &platformv1.PCRBaseline{
			Values:               map[uint32][]byte{0: {0xaa, 0xbb}, 7: {0x01}},
			Source:               "tofu",
			RecordedAt:           timestamppb.New(time.Unix(1750000100, 0).UTC()),
			RecordedFromDeviceId: 9007199254740993,
		},
		Networks: map[string]*platformv1.NetworkPhaseConfig{
			"provisioning": {
				Vlan:       100,
				StaticIp:   "10.0.100.2",
				Gateway:    "10.0.100.1",
				Dns:        []string{"10.0.100.1"},
				AuthMethod: platformv1.AuthMethod_AUTH_METHOD_NONE,
				Zone:       "provisioning",
				DhcpPool: &platformv1.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.200",
					LeaseTime:  3600,
				},
				Acls: []*platformv1.ACLConfig{
					{Priority: 10, Protocol: "tcp", SrcIp: "0.0.0.0/0", DstIp: "10.0.100.2", DstPort: 443, Action: "allow"},
				},
			},
		},
		PlatformdConfig: &platformv1.PlatformdConfigRef{
			ConfigType: "inline",
			ConfigName: "node-02",
			Version:    "v1",
		},
		MatchRules: &platformv1.ProfileMatchRules{
			MacPrefix:        "00:25:90",
			SerialPrefix:     "SN-",
			Model:            "X10SDV-TP8F",
			TpmVendor:        "IFX",
			CustomAttributes: map[string]string{"rack": "r1"},
		},
		Bmc: &platformv1.BMCConfig{
			Address:  "10.4.6.103",
			Port:     623,
			Username: "admin",
			Protocol: "ipmi",
		},
	}
}

// compatTestDevice builds a fully-populated Device message.
func compatTestDevice() *platformv1.Device {
	return &platformv1.Device{
		Id:            5001,
		AttestPub:     "attest-pub-pem",
		AttestCert:    "-----BEGIN CERTIFICATE-----\nIAK\n-----END CERTIFICATE-----\n",
		EkCert:        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		EventLog:      []byte{0x0a, 0x0b},
		HashAlgoId:    11,
		Model:         "X10SDV-TP8F",
		Serial:        "SN-5001",
		SigningPub:    "signing-pub-pem",
		SwitchName:    "nexus-1",
		SwitchPort:    "Eth1/3",
		NetworkPortId: "tap-node02",
	}
}

// TestQUICDeviceWireCompatCreateDevice round-trips CreateDevice.
func TestQUICDeviceWireCompatCreateDevice(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.CreateDeviceRequest{Device: compatTestDevice()},
		&platformv1.CreateDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.CreateDeviceResponse{
			Status: &platformv1.Status{Success: true, Message: "device created successfully"},
			Device: compatTestDevice(),
		},
		&platformv1.CreateDeviceResponse{})
}

// TestQUICDeviceWireCompatGetDevice round-trips GetDevice and the
// OpDeviceGet union decode shape shared with FindDeviceBySerial.
func TestQUICDeviceWireCompatGetDevice(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.GetDeviceRequest{Id: 5001},
		&platformv1.GetDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.GetDeviceResponse{Device: compatTestDevice()},
		&platformv1.GetDeviceResponse{})

	// Union decode: both request shapes land in deviceGetWireRequest.
	payload, err := quic.EncodePayload(&platformv1.GetDeviceRequest{Id: 42})
	if err != nil {
		t.Fatalf("encode GetDeviceRequest: %v", err)
	}
	var union deviceGetWireRequest
	if err := quic.DecodePayload(payload, &union); err != nil {
		t.Fatalf("decode union: %v", err)
	}
	if union.Id != 42 || union.Serial != "" {
		t.Fatalf("union from GetDeviceRequest = %+v, want Id=42", union)
	}

	payload, err = quic.EncodePayload(&platformv1.FindDeviceBySerialRequest{Serial: "SN-42"})
	if err != nil {
		t.Fatalf("encode FindDeviceBySerialRequest: %v", err)
	}
	union = deviceGetWireRequest{}
	if err := quic.DecodePayload(payload, &union); err != nil {
		t.Fatalf("decode union: %v", err)
	}
	if union.Serial != "SN-42" || union.Id != 0 {
		t.Fatalf("union from FindDeviceBySerialRequest = %+v, want Serial=SN-42", union)
	}

	// GetDeviceResponse decodes into FindDeviceBySerialResponse (both
	// carry the device under the same Device field).
	payload, err = quic.EncodePayload(&platformv1.GetDeviceResponse{Device: compatTestDevice()})
	if err != nil {
		t.Fatalf("encode GetDeviceResponse: %v", err)
	}
	var findReply platformv1.FindDeviceBySerialResponse
	if err := quic.DecodePayload(payload, &findReply); err != nil {
		t.Fatalf("decode FindDeviceBySerialResponse: %v", err)
	}
	if !proto.Equal(compatTestDevice(), findReply.GetDevice()) {
		t.Fatalf("FindDeviceBySerialResponse device mismatch: %+v", findReply.GetDevice())
	}
}

// TestQUICDeviceWireCompatListDevices round-trips ListDevices and the
// CountDevices projection from the pagination totals.
func TestQUICDeviceWireCompatListDevices(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.ListDevicesRequest{
			Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 25, Ascending: true},
		},
		&platformv1.ListDevicesRequest{})

	listResp := &platformv1.ListDevicesResponse{
		Devices: []*platformv1.Device{compatTestDevice()},
		Pagination: &platformv1.PaginationResponse{
			Page: 1, PageSize: 25, TotalPages: 1, TotalItems: 7,
		},
	}
	roundTripDeviceWire(t, listResp, &platformv1.ListDevicesResponse{})

	// CountDevices shares the wire payload; the SDK derives the count
	// from the pagination totals (see sdk/go/transport/quic/device.go).
	payload, err := quic.EncodePayload(listResp)
	if err != nil {
		t.Fatalf("encode ListDevicesResponse: %v", err)
	}
	var decoded platformv1.ListDevicesResponse
	if err := quic.DecodePayload(payload, &decoded); err != nil {
		t.Fatalf("decode ListDevicesResponse: %v", err)
	}
	if decoded.GetPagination().GetTotalItems() != 7 {
		t.Fatalf("TotalItems = %d, want 7", decoded.GetPagination().GetTotalItems())
	}
}

// TestQUICDeviceWireCompatUpdateDevice round-trips UpdateDevice.
func TestQUICDeviceWireCompatUpdateDevice(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.UpdateDeviceRequest{Device: compatTestDevice()},
		&platformv1.UpdateDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.UpdateDeviceResponse{
			Status: &platformv1.Status{Success: true},
			Device: compatTestDevice(),
		},
		&platformv1.UpdateDeviceResponse{})
}

// TestQUICDeviceWireCompatDeleteDevice round-trips DeleteDevice.
func TestQUICDeviceWireCompatDeleteDevice(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.DeleteDeviceRequest{Id: 5001},
		&platformv1.DeleteDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.DeleteDeviceResponse{
			Status: &platformv1.Status{Success: true, Message: "device deleted successfully"},
		},
		&platformv1.DeleteDeviceResponse{})
}

// TestQUICDeviceWireCompatCreateProfile round-trips CreateProfile with a
// fully-populated profile (enums, timestamps, maps, nested messages, and
// the ek_cert / ek_serial / mac_address / config / assigned fields).
func TestQUICDeviceWireCompatCreateProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.CreateProfileRequest{Profile: compatTestProfile()},
		&platformv1.CreateProfileRequest{})
	roundTripDeviceWire(t,
		&platformv1.CreateProfileResponse{
			Status:  &platformv1.Status{Success: true, Message: "profile created successfully"},
			Profile: compatTestProfile(),
		},
		&platformv1.CreateProfileResponse{})
}

// TestQUICDeviceWireCompatGetProfile round-trips GetProfile.
func TestQUICDeviceWireCompatGetProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.GetProfileRequest{Id: 12345},
		&platformv1.GetProfileRequest{})
	roundTripDeviceWire(t,
		&platformv1.GetProfileResponse{Profile: compatTestProfile()},
		&platformv1.GetProfileResponse{})
}

// TestQUICDeviceWireCompatListProfiles round-trips ListProfiles and the
// CountProfiles projection from the pagination totals.
func TestQUICDeviceWireCompatListProfiles(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.ListProfilesRequest{
			Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 50},
		},
		&platformv1.ListProfilesRequest{})
	roundTripDeviceWire(t,
		&platformv1.ListProfilesResponse{
			Profiles: []*platformv1.DeviceProfile{compatTestProfile()},
			Pagination: &platformv1.PaginationResponse{
				Page: 1, PageSize: 50, TotalPages: 1, TotalItems: 3,
			},
		},
		&platformv1.ListProfilesResponse{})
}

// TestQUICDeviceWireCompatUpdateProfile round-trips UpdateProfile, the
// message the SDK sends on OpDeviceSetProfile.
func TestQUICDeviceWireCompatUpdateProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.UpdateProfileRequest{Profile: compatTestProfile()},
		&platformv1.UpdateProfileRequest{})
	roundTripDeviceWire(t,
		&platformv1.UpdateProfileResponse{
			Status:  &platformv1.Status{Success: true},
			Profile: compatTestProfile(),
		},
		&platformv1.UpdateProfileResponse{})
}

// TestQUICDeviceWireCompatDeleteProfile round-trips DeleteProfile.
func TestQUICDeviceWireCompatDeleteProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.DeleteProfileRequest{Id: 12345},
		&platformv1.DeleteProfileRequest{})
	roundTripDeviceWire(t,
		&platformv1.DeleteProfileResponse{
			Status: &platformv1.Status{Success: true, Message: "profile deleted successfully"},
		},
		&platformv1.DeleteProfileResponse{})
}

// TestQUICDeviceWireCompatAssignProfile round-trips the assignment
// request/response carried under the provisioning category sub-opcode.
func TestQUICDeviceWireCompatAssignProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.AssignProfileToDeviceRequest{
			ProfileId:  12345,
			EkSerial:   "1234567890",
			MacAddress: "00:25:90:ff:aa:02",
			EkCert:     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		},
		&platformv1.AssignProfileToDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.AssignProfileToDeviceResponse{Profile: compatTestProfile()},
		&platformv1.AssignProfileToDeviceResponse{})
}

// TestQUICDeviceWireCompatUnassignProfile round-trips the unassignment
// request/response carried under the provisioning category sub-opcode.
func TestQUICDeviceWireCompatUnassignProfile(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.UnassignProfileFromDeviceRequest{ProfileId: 12345},
		&platformv1.UnassignProfileFromDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.UnassignProfileFromDeviceResponse{Profile: compatTestProfile()},
		&platformv1.UnassignProfileFromDeviceResponse{})
}

// TestQUICDeviceWireCompatActivateDevice round-trips ActivateDevice.
func TestQUICDeviceWireCompatActivateDevice(t *testing.T) {
	roundTripDeviceWire(t,
		&platformv1.ActivateDeviceRequest{Serial: "SN-5001", MacAddress: "00:25:90:ff:aa:02"},
		&platformv1.ActivateDeviceRequest{})
	roundTripDeviceWire(t,
		&platformv1.ActivateDeviceResponse{
			Status:           &platformv1.Status{Success: true},
			ActivationStatus: "activated",
			Vlan:             200,
			TransitionedAt:   timestamppb.New(time.Unix(1750000000, 0).UTC()),
		},
		&platformv1.ActivateDeviceResponse{})
}
