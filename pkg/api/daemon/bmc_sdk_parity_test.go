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
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The BMCService parity drivers below run every SDK transport against the
// daemon the same way: each transport file supplies only how it serves a
// BMCService servicer and connects the SDK's adapter to it.

// bmcSDKProfile is the device profile every BMC call in these tests names.
const bmcSDKProfile = 7

// bmcSDKNow fixes every timestamp the fakes answer with, so two fixtures
// answer alike.
var bmcSDKNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// bmcSDKConnect serves server through one daemon transport and connects the
// SDK's adapter for that transport as a caller holding scopes.
type bmcSDKConnect func(t *testing.T, server platformv1.BMCServiceServer, scopes ...string) grpc.ClientConnInterface

// bmcSDKFixture is a BMCService server over fakes that answer every method
// and record what each call asked for.
type bmcSDKFixture struct {
	bmc       *fakeBMCService
	baremetal *fakeBaremetalService
	enroller  *fakeBMCEnroller
	restorer  *fakeBMCRestorer
	server    *BMCGRPCService
}

// newBMCSDKFixture builds the fixture. enroll and restore are shared between
// fixtures because the ceremony results carry their own clock readings.
func newBMCSDKFixture(enroll *app.BMCEnrollResult, restore *app.BMCRestoreResult) *bmcSDKFixture {
	f := &bmcSDKFixture{
		bmc: &fakeBMCService{
			powerStatus:   bmc.PowerStateOn,
			getBootDevice: bmc.BootDevicePXE,
			vmedia:        &bmc.VirtualMediaInfo{Mounted: true, ImageURL: "https://images.example/install.iso", MediaType: "iso"},
			sensors:       []bmc.SensorReading{{Name: "CPU Temp", Value: 41.5, Units: "C", Status: "ok"}},
			systemInfo: &bmc.SystemInfo{
				Manufacturer: "Dell Inc.", Product: "PowerEdge R650", SerialNumber: "SN-1",
				FirmwareVersion: "7.10", BIOSVersion: "2.1.4", PowerState: bmc.PowerStateOn,
			},
			getCertInfo: &bmc.CertificateInfo{
				Subject: "CN=bmc-01", Issuer: "CN=platform-ca", SerialNumber: "0A",
				NotBefore: bmcSDKNow.Add(-time.Hour), NotAfter: bmcSDKNow.Add(90 * 24 * time.Hour),
				DaysRemaining: 90, SubjectAlternativeNames: []string{"bmc-01.example.com"}, Fingerprint: "ab12",
			},
			listUsers: []bmc.User{{Slot: 2, Username: "ops", Enabled: true, Privilege: bmc.PrivilegeOperator, Channel: 1}},
		},
		baremetal: &fakeBaremetalService{
			provisionResult: &baremetal.ProvisionResult{ProvisionID: "prov-1", Status: baremetal.StatusPending},
			statusResult: &baremetal.ProvisionResult{
				ProvisionID: "prov-1", Status: baremetal.StatusInstalling, Message: "installing",
				StartedAt: bmcSDKNow, UpdatedAt: bmcSDKNow.Add(time.Minute),
			},
		},
		enroller: &fakeBMCEnroller{enrollResult: enroll},
		restorer: &fakeBMCRestorer{restoreResult: restore},
	}
	f.server = newTestService(f.bmc, f.baremetal)
	profiles := fakeDeviceProfileSvcForEnroll(bmcSDKProfile, true)
	f.server.SetEnroller(f.enroller, profiles)
	f.server.SetRestorer(f.restorer, profiles)
	return f
}

// recorded is everything the fakes recorded about the calls they served.
func (f *bmcSDKFixture) recorded() []interface{} {
	return []interface{}{
		*f.bmc, *f.baremetal,
		f.enroller.lastDeviceID, f.enroller.lastBMCCfg, f.enroller.lastOpts,
		f.restorer.lastDeviceID, f.restorer.lastBMCCfg,
	}
}

// invokeBMCServer calls method on server directly, through the generated
// service descriptor, as a gRPC caller reaches it once authorized.
func invokeBMCServer(server platformv1.BMCServiceServer, method string, req proto.Message) (proto.Message, error) {
	for _, desc := range platformv1.BMCService_ServiceDesc.Methods {
		if desc.MethodName != path.Base(method) {
			continue
		}
		decode := func(in interface{}) error {
			proto.Merge(in.(proto.Message), req)
			return nil
		}
		resp, err := desc.Handler(server, context.Background(), decode, nil)
		if err != nil {
			return nil, err
		}
		return resp.(proto.Message), nil
	}
	return nil, status.Errorf(codes.Unimplemented, "%s is not a BMCService method", method)
}

// bmcSDKRequests holds one request for every BMCService method.
func bmcSDKRequests() map[string]proto.Message {
	user := &platformv1.BMCUser{
		Slot: 3, Username: "ops", Enabled: true,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, Channel: 1,
	}
	return map[string]proto.Message{
		platformv1.BMCService_PowerOn_FullMethodName:            &platformv1.BMCPowerRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_PowerOff_FullMethodName:           &platformv1.BMCPowerRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_PowerReset_FullMethodName:         &platformv1.BMCPowerRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_PowerCycle_FullMethodName:         &platformv1.BMCPowerRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_PowerStatus_FullMethodName:        &platformv1.BMCPowerStatusRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_GetBootDevice_FullMethodName:      &platformv1.BMCGetBootDeviceRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_UnmountISO_FullMethodName:         &platformv1.BMCUnmountISORequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_VirtualMediaStatus_FullMethodName: &platformv1.BMCVirtualMediaStatusRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_GetSensors_FullMethodName:         &platformv1.BMCGetSensorsRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_GetSystemInfo_FullMethodName:      &platformv1.BMCGetSystemInfoRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_ProvisionStatus_FullMethodName:    &platformv1.BMCProvisionStatusRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_GetWebCertificate_FullMethodName:  &platformv1.BMCGetWebCertificateRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_RestoreFactoryCert_FullMethodName: &platformv1.BMCRestoreRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_ListUsers_FullMethodName:          &platformv1.BMCListUsersRequest{ProfileId: bmcSDKProfile},
		platformv1.BMCService_SetBootDevice_FullMethodName: &platformv1.BMCSetBootDeviceRequest{
			ProfileId: bmcSDKProfile, Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE, Persistent: true,
		},
		platformv1.BMCService_MountISO_FullMethodName: &platformv1.BMCMountISORequest{
			ProfileId: bmcSDKProfile, IsoUrl: "https://images.example/install.iso",
		},
		platformv1.BMCService_Provision_FullMethodName: &platformv1.BMCProvisionRequest{
			ProfileId: bmcSDKProfile, IsoUrl: "https://images.example/install.iso",
		},
		platformv1.BMCService_ReplaceWebCertificate_FullMethodName: &platformv1.BMCReplaceWebCertificateRequest{
			ProfileId: bmcSDKProfile, CertPem: []byte("-----BEGIN CERTIFICATE-----"), KeyPem: []byte("-----BEGIN EC PRIVATE KEY-----"),
		},
		platformv1.BMCService_EnrollBMC_FullMethodName: &platformv1.BMCEnrollRequest{
			ProfileId: bmcSDKProfile, ReplaceCertificate: proto.Bool(true), DanePublish: proto.Bool(false),
		},
		platformv1.BMCService_CreateUser_FullMethodName: &platformv1.BMCCreateUserRequest{
			ProfileId: bmcSDKProfile, User: user, Password: "initial-secret",
		},
		platformv1.BMCService_DeleteUser_FullMethodName: &platformv1.BMCDeleteUserRequest{ProfileId: bmcSDKProfile, Slot: 3},
		platformv1.BMCService_SetUserPassword_FullMethodName: &platformv1.BMCSetUserPasswordRequest{
			ProfileId: bmcSDKProfile, Slot: 3, Password: "rotated-secret",
		},
		platformv1.BMCService_SetUserPrivilege_FullMethodName: &platformv1.BMCSetUserPrivilegeRequest{
			ProfileId: bmcSDKProfile, Slot: 3, Channel: 1, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
		},
	}
}

// testSDKBMCMethods drives every BMCService method through connect, as a
// caller holding only the scope gRPC requires for it, and checks that the
// reply and the call the BMC service saw are the ones a direct gRPC call
// gives.
func testSDKBMCMethods(t *testing.T, transport string, connect bmcSDKConnect) {
	requests := bmcSDKRequests()
	require.Len(t, requests, len(platformv1.BMCService_ServiceDesc.Methods))
	enroll, restore := goodEnrollResult(), goodRestoreResult()
	untouched := newBMCSDKFixture(enroll, restore).recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newBMCSDKFixture(enroll, restore)
			want, err := invokeBMCServer(direct.server, method, req)
			require.NoError(t, err)

			via := newBMCSDKFixture(enroll, restore)
			got := want.ProtoReflect().New().Interface()
			scope := grpcapi.ScopeForMethod(method)
			require.NotEmpty(t, scope, "gRPC has no scope for %s", method)
			conn := connect(t, via.server, scope)
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			require.True(t, proto.Equal(want, got), "%s reply\n%v\nwant the gRPC reply\n%v", transport, got, want)
			require.NotEqual(t, untouched, via.recorded(), "the BMC service saw no call")
			require.Equal(t, direct.recorded(), via.recorded())
		})
	}
}

// bmcRefusalCase is one method of a permission class, the scopes of a caller
// who lacks that class, and how to make the BMC service miss the profile.
type bmcRefusalCase struct {
	class   string
	method  string
	resp    proto.Message
	scopes  []string
	missing func(f *bmcSDKFixture)
}

// bmcRefusalCases holds one method of each BMC permission class.
func bmcRefusalCases() []bmcRefusalCase {
	notFound := bmc.ErrProfileNotFound{ProfileID: bmcSDKProfile}
	return []bmcRefusalCase{
		{
			class:   "bmc:read",
			method:  platformv1.BMCService_ProvisionStatus_FullMethodName,
			resp:    &platformv1.BMCProvisionStatusResponse{},
			scopes:  []string{"device:read"},
			missing: func(f *bmcSDKFixture) { f.baremetal.statusErr = baremetal.ErrProvisionNotFound{ProvisionID: "prov-1"} },
		},
		{
			class:   "bmc:write",
			method:  platformv1.BMCService_SetBootDevice_FullMethodName,
			resp:    &platformv1.BMCSetBootDeviceResponse{},
			scopes:  []string{"bmc:read"},
			missing: func(f *bmcSDKFixture) { f.bmc.setBootErr = notFound },
		},
		{
			class:   "bmc:power",
			method:  platformv1.BMCService_PowerCycle_FullMethodName,
			resp:    &platformv1.BMCPowerResponse{},
			scopes:  []string{"bmc:read", "bmc:write"},
			missing: func(f *bmcSDKFixture) { f.bmc.powerStatusErr = notFound },
		},
		{
			class:   "bmc:media",
			method:  platformv1.BMCService_MountISO_FullMethodName,
			resp:    &platformv1.BMCMountISOResponse{},
			scopes:  []string{"bmc:read", "bmc:write"},
			missing: func(f *bmcSDKFixture) { f.bmc.mountISOErr = notFound },
		},
		{
			class:  "bmc:admin",
			method: platformv1.BMCService_EnrollBMC_FullMethodName,
			resp:   &platformv1.BMCEnrollResponse{},
			scopes: []string{"bmc:read", "bmc:write", "bmc:power", "bmc:media"},
			// The profile service holds another profile, not bmcSDKProfile.
			missing: func(f *bmcSDKFixture) {
				f.server.SetEnroller(f.enroller, fakeDeviceProfileSvcForEnroll(bmcSDKProfile+1, true))
			},
		},
	}
}

// testSDKBMCRefusesScope checks, for one method of each permission class,
// that a caller without the method's scope reaches the SDK caller as
// PermissionDenied, the code gRPC gives, and reaches no BMC.
func testSDKBMCRefusesScope(t *testing.T, transport string, connect bmcSDKConnect) {
	enroll, restore := goodEnrollResult(), goodRestoreResult()
	for _, tc := range bmcRefusalCases() {
		t.Run(tc.class+" without the scope", func(t *testing.T) {
			f := newBMCSDKFixture(enroll, restore)
			before := f.recorded()
			conn := connect(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, bmcSDKRequests()[tc.method], tc.resp)

			require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", transport, err)
			require.Equal(t, before, f.recorded(), "a refused caller reached the BMC service")
		})
	}
}

// testSDKBMCRefusesNotFound checks, for one method of each permission class,
// that a profile the BMC service cannot find reaches the SDK caller as
// NotFound, the code gRPC gives.
func testSDKBMCRefusesNotFound(t *testing.T, transport string, connect bmcSDKConnect) {
	enroll, restore := goodEnrollResult(), goodRestoreResult()
	for _, tc := range bmcRefusalCases() {
		req := bmcSDKRequests()[tc.method]

		t.Run(tc.class+" of a profile not found", func(t *testing.T) {
			direct := newBMCSDKFixture(enroll, restore)
			tc.missing(direct)
			_, err := invokeBMCServer(direct.server, tc.method, req)
			require.Equal(t, codes.NotFound, status.Code(err), "gRPC: %v", err)

			via := newBMCSDKFixture(enroll, restore)
			tc.missing(via)
			conn := connect(t, via.server, "*:*")
			err = conn.Invoke(context.Background(), tc.method, req, tc.resp)
			require.Equal(t, codes.NotFound, status.Code(err), "%s: %v", transport, err)
		})
	}
}
