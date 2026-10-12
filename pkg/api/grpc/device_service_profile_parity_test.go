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

package grpc

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testTLSServerName = "compute.example.internal"

// TestProfileConversions_CarryTLSServerName pins that this package's
// proto<->entity profile conversions carry tls_server_name both ways and
// never invent one (#430, #448).
func TestProfileConversions_CarryTLSServerName(t *testing.T) {
	entity := protoProfileToEntity(&platformv1.DeviceProfile{Id: 1, TlsServerName: testTLSServerName})
	if entity == nil || entity.TLSServerName != testTLSServerName {
		t.Fatalf("protoProfileToEntity dropped tls_server_name: %+v", entity)
	}
	pb := entityProfileToProto(&entities.DeviceProfile{ID: 1, TLSServerName: testTLSServerName})
	if pb == nil || pb.GetTlsServerName() != testTLSServerName {
		t.Fatalf("entityProfileToProto dropped TLSServerName: %+v", pb)
	}
	if protoProfileToEntity(&platformv1.DeviceProfile{Id: 2}).TLSServerName != "" {
		t.Fatal("an absent tls_server_name must stay absent")
	}
	if entityProfileToProto(&entities.DeviceProfile{ID: 2}).GetTlsServerName() != "" {
		t.Fatal("an absent TLSServerName must stay absent")
	}
}

// TestProfileConversions_PCRBaselineReadOnly pins the asymmetric baseline
// contract: entity -> proto carries the recorded baseline, proto -> entity
// ignores a supplied one (#373, #448). Making protoProfileToEntity copy the
// field must fail this test.
func TestProfileConversions_PCRBaselineReadOnly(t *testing.T) {
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	pb := entityProfileToProto(&entities.DeviceProfile{ID: 1, PCRBaseline: &entities.PCRBaseline{
		Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: recorded, RecordedFromDeviceID: 77,
	}})
	if pb.GetPcrBaseline() == nil || pb.GetPcrBaseline().GetSource() != "tofu" || string(pb.GetPcrBaseline().GetValues()[7]) != "\xbb" {
		t.Fatalf("entityProfileToProto dropped the baseline: %+v", pb.GetPcrBaseline())
	}
	if entityProfileToProto(&entities.DeviceProfile{ID: 2}).GetPcrBaseline() != nil {
		t.Fatal("no baseline must map to an unset field")
	}

	entity := protoProfileToEntity(&platformv1.DeviceProfile{Id: 1, PcrBaseline: &platformv1.PCRBaseline{
		Values: map[uint32][]byte{0: {0x01}}, Source: "signed", RecordedAt: timestamppb.Now(),
	}})
	if entity.PCRBaseline != nil {
		t.Fatal("a caller-supplied pcr_baseline must never reach the entity")
	}
}

// TestDeviceGRPCService_TLSServerName_RoundTrip creates a profile with the
// name, reads it back, and confirms the entity handed to the profile service
// carries it, so the wire shape is right in every direction it is set.
func TestDeviceGRPCService_TLSServerName_RoundTrip(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	created, err := service.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 7, Name: "compute", TlsServerName: testTLSServerName,
	}})
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if created.GetProfile().GetTlsServerName() != testTLSServerName {
		t.Fatal("CreateProfile response dropped tls_server_name")
	}
	if profileMock.profiles[7].TLSServerName != testTLSServerName {
		t.Fatal("the entity handed to the profile service lacks TLSServerName")
	}

	got, err := service.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 7})
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.GetProfile().GetTlsServerName() != testTLSServerName {
		t.Fatal("GetProfile response dropped tls_server_name")
	}
}

// TestDeviceGRPCService_UpdateProfile_ClearTLSServerName pins #462 on the
// gRPC wire: only clear_tls_server_name asks the service to blank the name;
// an update without it must not, so the service still restores the stored
// name on omission.
func TestDeviceGRPCService_UpdateProfile_ClearTLSServerName(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()
	if _, err := service.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 8, Name: "compute", TlsServerName: testTLSServerName,
	}}); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	if _, err := service.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 8, Name: "compute-renamed",
	}}); err != nil {
		t.Fatalf("UpdateProfile without the flag: %v", err)
	}
	if slices.Contains(profileMock.updateOpts, device.ClearTLSServerName) {
		t.Fatal("an update without clear_tls_server_name must not ask for a clear")
	}

	if _, err := service.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{
		Profile:            &platformv1.DeviceProfile{Id: 8, Name: "compute-renamed"},
		ClearTlsServerName: true,
	}); err != nil {
		t.Fatalf("UpdateProfile with the flag: %v", err)
	}
	if !slices.Contains(profileMock.updateOpts, device.ClearTLSServerName) {
		t.Fatal("clear_tls_server_name must reach the service as ClearTLSServerName")
	}
}

// TestDeviceGRPCService_UpdateProfile_ClearConflictIsInvalidArgument pins the
// error mapping: a request that both sets and clears the name is a client
// error, not an internal one.
func TestDeviceGRPCService_UpdateProfile_ClearConflictIsInvalidArgument(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	profileMock.updateErr = &device.WrappedError{Msg: "failed to update profile", Err: device.ErrTLSServerNameClearConflict{}}

	_, err := service.UpdateProfile(context.Background(), &platformv1.UpdateProfileRequest{
		Profile:            &platformv1.DeviceProfile{Id: 9, Name: "compute", TlsServerName: testTLSServerName},
		ClearTlsServerName: true,
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument (err=%v)", got, err)
	}
}

// TestDeviceGRPCService_PCRBaseline_ReadOnlyOnTheWire proves an
// UpdateProfile that names pcr_baseline hands the profile service an entity
// without one, while GetProfile reports the recorded baseline.
func TestDeviceGRPCService_PCRBaseline_ReadOnlyOnTheWire(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()
	profileMock.profiles[9] = &entities.DeviceProfile{ID: 9, Name: "workers", PCRBaseline: &entities.PCRBaseline{
		Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: time.Now().UTC(),
	}}

	got, err := service.GetProfile(ctx, &platformv1.GetProfileRequest{Id: 9})
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.GetProfile().GetPcrBaseline() == nil || got.GetProfile().GetPcrBaseline().GetSource() != "tofu" {
		t.Fatal("GetProfile response dropped the recorded baseline")
	}

	_, err = service.UpdateProfile(ctx, &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{
		Id: 9, Name: "workers-renamed",
		PcrBaseline: &platformv1.PCRBaseline{Values: map[uint32][]byte{0: {0xee}}, Source: "signed", RecordedAt: timestamppb.Now()},
	}})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	// This package's service delegates preservation to the profile service;
	// the mock records what it was handed, and it must carry no baseline.
	if profileMock.profiles[9].PCRBaseline != nil {
		t.Fatal("UpdateProfile handed a caller-supplied baseline to the profile service")
	}
}
