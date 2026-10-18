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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bmcMCPProfile is the device profile every BMC call in these tests names.
const bmcMCPProfile = 7

// bmcMCPNow fixes every timestamp the fakes answer with, so two fixtures
// answer alike.
var bmcMCPNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// bmcMCPFixture is a BMCService server over fakes that answer every method
// and record what each call asked for.
type bmcMCPFixture struct {
	bmc       *fakeBMCService
	baremetal *fakeBaremetalService
	enroller  *fakeBMCEnroller
	restorer  *fakeBMCRestorer
	server    *BMCGRPCService
}

// newBMCMCPFixture builds the fixture. enroll and restore are shared between
// fixtures because the ceremony results carry their own clock readings.
func newBMCMCPFixture(enroll *app.BMCEnrollResult, restore *app.BMCRestoreResult) *bmcMCPFixture {
	f := &bmcMCPFixture{
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
				NotBefore: bmcMCPNow.Add(-time.Hour), NotAfter: bmcMCPNow.Add(90 * 24 * time.Hour),
				DaysRemaining: 90, SubjectAlternativeNames: []string{"bmc-01.example.com"}, Fingerprint: "ab12",
			},
			listUsers: []bmc.User{{Slot: 2, Username: "ops", Enabled: true, Privilege: bmc.PrivilegeOperator, Channel: 1}},
		},
		baremetal: &fakeBaremetalService{
			provisionResult: &baremetal.ProvisionResult{ProvisionID: "prov-1", Status: baremetal.StatusPending},
			statusResult: &baremetal.ProvisionResult{
				ProvisionID: "prov-1", Status: baremetal.StatusInstalling, Message: "installing",
				StartedAt: bmcMCPNow, UpdatedAt: bmcMCPNow.Add(time.Minute),
			},
		},
		enroller: &fakeBMCEnroller{enrollResult: enroll},
		restorer: &fakeBMCRestorer{restoreResult: restore},
	}
	f.server = newTestService(f.bmc, f.baremetal)
	profiles := fakeDeviceProfileSvcForEnroll(bmcMCPProfile, true)
	f.server.SetEnroller(f.enroller, profiles)
	f.server.SetRestorer(f.restorer, profiles)
	return f
}

// recorded is everything the fakes recorded about the calls they served.
func (f *bmcMCPFixture) recorded() []interface{} {
	return []interface{}{
		*f.bmc, *f.baremetal,
		f.enroller.lastDeviceID, f.enroller.lastBMCCfg, f.enroller.lastOpts,
		f.restorer.lastDeviceID, f.restorer.lastBMCCfg,
	}
}

// connectBMCMCP serves server through the daemon's MCP server and connects
// the SDK's MCP adapter as a caller holding scopes.
func connectBMCMCP(t *testing.T, server platformv1.BMCServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetBMCServer(server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  scopes,
	}}}
	return serveMCPConfig(t, provider, config).Connection()
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

// bmcMCPRequests holds one request for every BMCService method.
func bmcMCPRequests() map[string]proto.Message {
	user := &platformv1.BMCUser{
		Slot: 3, Username: "ops", Enabled: true,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, Channel: 1,
	}
	return map[string]proto.Message{
		platformv1.BMCService_PowerOn_FullMethodName:            &platformv1.BMCPowerRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_PowerOff_FullMethodName:           &platformv1.BMCPowerRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_PowerReset_FullMethodName:         &platformv1.BMCPowerRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_PowerCycle_FullMethodName:         &platformv1.BMCPowerRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_PowerStatus_FullMethodName:        &platformv1.BMCPowerStatusRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_GetBootDevice_FullMethodName:      &platformv1.BMCGetBootDeviceRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_UnmountISO_FullMethodName:         &platformv1.BMCUnmountISORequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_VirtualMediaStatus_FullMethodName: &platformv1.BMCVirtualMediaStatusRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_GetSensors_FullMethodName:         &platformv1.BMCGetSensorsRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_GetSystemInfo_FullMethodName:      &platformv1.BMCGetSystemInfoRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_ProvisionStatus_FullMethodName:    &platformv1.BMCProvisionStatusRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_GetWebCertificate_FullMethodName:  &platformv1.BMCGetWebCertificateRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_RestoreFactoryCert_FullMethodName: &platformv1.BMCRestoreRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_ListUsers_FullMethodName:          &platformv1.BMCListUsersRequest{ProfileId: bmcMCPProfile},
		platformv1.BMCService_SetBootDevice_FullMethodName: &platformv1.BMCSetBootDeviceRequest{
			ProfileId: bmcMCPProfile, Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE, Persistent: true,
		},
		platformv1.BMCService_MountISO_FullMethodName: &platformv1.BMCMountISORequest{
			ProfileId: bmcMCPProfile, IsoUrl: "https://images.example/install.iso",
		},
		platformv1.BMCService_Provision_FullMethodName: &platformv1.BMCProvisionRequest{
			ProfileId: bmcMCPProfile, IsoUrl: "https://images.example/install.iso",
		},
		platformv1.BMCService_ReplaceWebCertificate_FullMethodName: &platformv1.BMCReplaceWebCertificateRequest{
			ProfileId: bmcMCPProfile, CertPem: []byte("-----BEGIN CERTIFICATE-----"), KeyPem: []byte("-----BEGIN EC PRIVATE KEY-----"),
		},
		platformv1.BMCService_EnrollBMC_FullMethodName: &platformv1.BMCEnrollRequest{
			ProfileId: bmcMCPProfile, ReplaceCertificate: proto.Bool(true), DanePublish: proto.Bool(false),
		},
		platformv1.BMCService_CreateUser_FullMethodName: &platformv1.BMCCreateUserRequest{
			ProfileId: bmcMCPProfile, User: user, Password: "initial-secret",
		},
		platformv1.BMCService_DeleteUser_FullMethodName: &platformv1.BMCDeleteUserRequest{ProfileId: bmcMCPProfile, Slot: 3},
		platformv1.BMCService_SetUserPassword_FullMethodName: &platformv1.BMCSetUserPasswordRequest{
			ProfileId: bmcMCPProfile, Slot: 3, Password: "rotated-secret",
		},
		platformv1.BMCService_SetUserPrivilege_FullMethodName: &platformv1.BMCSetUserPrivilegeRequest{
			ProfileId: bmcMCPProfile, Slot: 3, Channel: 1, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
		},
	}
}

// TestSDKMCP_BMCMethods drives every BMCService method through the SDK's MCP
// adapter and the daemon's MCP server, and checks that the reply and the
// call the BMC service saw are the ones a direct gRPC call gives.
func TestSDKMCP_BMCMethods(t *testing.T) {
	requests := bmcMCPRequests()
	require.Len(t, requests, len(platformv1.BMCService_ServiceDesc.Methods))
	enroll, restore := goodEnrollResult(), goodRestoreResult()
	untouched := newBMCMCPFixture(enroll, restore).recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newBMCMCPFixture(enroll, restore)
			want, err := invokeBMCServer(direct.server, method, req)
			require.NoError(t, err)

			viaMCP := newBMCMCPFixture(enroll, restore)
			got := want.ProtoReflect().New().Interface()
			conn := connectBMCMCP(t, viaMCP.server, "*:*")
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			require.True(t, proto.Equal(want, got), "MCP reply\n%v\nwant the gRPC reply\n%v", got, want)
			require.NotEqual(t, untouched, viaMCP.recorded(), "the BMC service saw no call")
			require.Equal(t, direct.recorded(), viaMCP.recorded())
		})
	}
}

// TestSDKMCP_BMCMethodsRefuse checks, for one method of each permission
// class, that a caller without the method's scope and a profile the BMC
// service cannot find reach the SDK caller as the code gRPC gives, and that
// a refused caller reaches no BMC.
func TestSDKMCP_BMCMethodsRefuse(t *testing.T) {
	notFound := bmc.ErrProfileNotFound{ProfileID: bmcMCPProfile}
	cases := []struct {
		class   string
		method  string
		resp    proto.Message
		scopes  []string
		missing func(f *bmcMCPFixture)
	}{
		{
			class:   "bmc:read",
			method:  platformv1.BMCService_ProvisionStatus_FullMethodName,
			resp:    &platformv1.BMCProvisionStatusResponse{},
			scopes:  []string{"device:read"},
			missing: func(f *bmcMCPFixture) { f.baremetal.statusErr = baremetal.ErrProvisionNotFound{ProvisionID: "prov-1"} },
		},
		{
			class:   "bmc:write",
			method:  platformv1.BMCService_SetBootDevice_FullMethodName,
			resp:    &platformv1.BMCSetBootDeviceResponse{},
			scopes:  []string{"bmc:read"},
			missing: func(f *bmcMCPFixture) { f.bmc.setBootErr = notFound },
		},
		{
			class:   "bmc:power",
			method:  platformv1.BMCService_PowerCycle_FullMethodName,
			resp:    &platformv1.BMCPowerResponse{},
			scopes:  []string{"bmc:read", "bmc:write"},
			missing: func(f *bmcMCPFixture) { f.bmc.powerStatusErr = notFound },
		},
		{
			class:   "bmc:media",
			method:  platformv1.BMCService_MountISO_FullMethodName,
			resp:    &platformv1.BMCMountISOResponse{},
			scopes:  []string{"bmc:read", "bmc:write"},
			missing: func(f *bmcMCPFixture) { f.bmc.mountISOErr = notFound },
		},
		{
			class:  "bmc:admin",
			method: platformv1.BMCService_EnrollBMC_FullMethodName,
			resp:   &platformv1.BMCEnrollResponse{},
			scopes: []string{"bmc:read", "bmc:write", "bmc:power", "bmc:media"},
			// The profile service holds another profile, not bmcMCPProfile.
			missing: func(f *bmcMCPFixture) {
				f.server.SetEnroller(f.enroller, fakeDeviceProfileSvcForEnroll(bmcMCPProfile+1, true))
			},
		},
	}
	enroll, restore := goodEnrollResult(), goodRestoreResult()
	for _, tc := range cases {
		req := bmcMCPRequests()[tc.method]

		t.Run(tc.class+" without the scope", func(t *testing.T) {
			f := newBMCMCPFixture(enroll, restore)
			before := f.recorded()
			conn := connectBMCMCP(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, req, tc.resp)

			// The gRPC scope interceptor refuses with PermissionDenied.
			require.Equal(t, codes.PermissionDenied, status.Code(err), "MCP: %v", err)
			require.Equal(t, before, f.recorded(), "a refused caller reached the BMC service")
		})

		t.Run(tc.class+" of a profile not found", func(t *testing.T) {
			direct := newBMCMCPFixture(enroll, restore)
			tc.missing(direct)
			_, err := invokeBMCServer(direct.server, tc.method, req)
			require.Equal(t, codes.NotFound, status.Code(err), "gRPC: %v", err)

			viaMCP := newBMCMCPFixture(enroll, restore)
			tc.missing(viaMCP)
			conn := connectBMCMCP(t, viaMCP.server, "*:*")
			err = conn.Invoke(context.Background(), tc.method, req, tc.resp)
			require.Equal(t, codes.NotFound, status.Code(err), "MCP: %v", err)
		})
	}
}
