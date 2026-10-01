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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceGRPCService_AssignProfileToDevice_ByDeviceID is the #463 round
// trip over gRPC/Unix/QUIC with the real ProfileService: bind a profile to a
// registered device by id, and the resolver both the collector and the
// verifier use lands on that profile — carrying its tls_server_name — for a
// device whose profile has no match rules.
func TestDeviceGRPCService_AssignProfileToDevice_ByDeviceID(t *testing.T) {
	ctx := context.Background()
	devices := newMockDeviceService()
	profiles := newRealProfileService(t)
	svc := NewDeviceGRPCService(devices, profiles, nil)
	certPEM := newEKCertPEMForTest(t)
	dev := &entities.Device{ID: 970392025956353, Serial: "node-05-compute-01", Model: "SuperMicro X10", EKCert: certPEM}
	devices.devices[dev.ID] = dev
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{
		ID: 3351835265417288672, Name: "node-05", Role: entities.DeviceRoleWorker, TLSServerName: "compute.example.internal",
	}))

	// Before the assign nothing resolves: installer profiles have no rules.
	_, err := profiles.FindProfileForDevice(ctx, dev)
	var none device.ErrNoProfileForDevice
	require.True(t, errors.As(err, &none), "got %v", err)

	resp, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId: 3351835265417288672, DeviceId: dev.ID,
	})
	require.NoError(t, err)
	wantSerial, err := entities.EKSerialFromCertPEM(certPEM)
	require.NoError(t, err)
	assert.Equal(t, wantSerial, resp.GetProfile().GetEkSerial(), "the EK serial is derived on the server from the device's certificate")
	assert.Equal(t, certPEM, resp.GetProfile().GetEkCert(), "the device's certificate is prestaged")
	assert.True(t, resp.GetProfile().GetAssigned())

	resolved, err := profiles.FindProfileForDevice(ctx, dev)
	require.NoError(t, err)
	assert.Equal(t, uint64(3351835265417288672), resolved.ID)
	assert.Equal(t, "compute.example.internal", resolved.TLSServerName)

	// Explicit values win over the derived ones.
	resp, err = svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId: 3351835265417288672, DeviceId: dev.ID, EkSerial: "EXPLICIT", MacAddress: "aa:bb:cc:dd:ee:ff",
	})
	require.NoError(t, err)
	assert.Equal(t, "EXPLICIT", resp.GetProfile().GetEkSerial())
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", resp.GetProfile().GetMacAddress())
}

// TestDeviceGRPCService_AssignProfileToDevice_ByDeviceID_Errors pins the
// failure shapes: an unknown device, a device with no EK certificate and no
// explicit identity, and a request naming no identity at all.
func TestDeviceGRPCService_AssignProfileToDevice_ByDeviceID_Errors(t *testing.T) {
	ctx := context.Background()
	devices := newMockDeviceService()
	profiles := newMockProfileService()
	profiles.profiles[5] = &entities.DeviceProfile{ID: 5, Name: "p"}
	devices.devices[7] = &entities.Device{ID: 7, Serial: "SN-7"}
	svc := NewDeviceGRPCService(devices, profiles, nil)

	_, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 5, DeviceId: 404})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown device: %v", err)

	_, err = svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 5, DeviceId: 7})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "device without EK certificate: %v", err)
	assert.Contains(t, err.Error(), "has no EK certificate")
	assert.False(t, profiles.profiles[5].Assigned, "a rejected binding must not assign")

	// The same device binds when the caller supplies the identity itself.
	resp, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 5, DeviceId: 7, MacAddress: "aa:bb:cc:dd:ee:07"})
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:07", resp.GetProfile().GetMacAddress())

	_, err = svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 5})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "device_id, ek_serial or mac_address is required")
}

// TestDeviceQuoteVerifier_ResolvesTheBoundProfile proves the verifier reaches
// the profile bound to the device's EK identity — no match rules anywhere —
// through the real ProfileService, and records the TOFU baseline on it. This
// is the verifier half of the #463 round trip; the mock-backed fixture
// cannot see a resolver regression, this test can.
func TestDeviceQuoteVerifier_ResolvesTheBoundProfile(t *testing.T) {
	f := newQuoteFixture(t)
	ctx := context.Background()
	profiles := newRealProfileService(t)
	f.device.EKCert = newEKCertPEMForTest(t)
	require.NoError(t, f.devices.Update(ctx, f.device))
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 4631, Name: "node-05", Role: entities.DeviceRoleWorker}))
	ekSerial, err := entities.EKSerialFromCertPEM(f.device.EKCert)
	require.NoError(t, err)
	require.NoError(t, profiles.AssignToDeviceWithEK(ctx, 4631, ekSerial, "", f.device.EKCert))

	v := NewDeviceQuoteVerifier(f.devices, profiles, f.trust, f.sink, nil)
	v.now = func() time.Time { return f.now }
	result, err := v.Verify(ctx, itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)
	assert.True(t, result.Verified, result.Message)
	assert.True(t, result.PCRBaselineCaptured)
	assert.Equal(t, uint64(4631), f.sink.last(t).ProfileID, "the verdict names the bound profile")

	stored, err := profiles.Get(ctx, 4631)
	require.NoError(t, err)
	require.NotNil(t, stored.PCRBaseline, "the baseline is recorded on the bound profile")
	assert.Equal(t, f.device.ID, stored.PCRBaseline.RecordedFromDeviceID)
}

// TestDeviceQuoteVerifier_NoBoundOrMatchingProfileIsAnAbsence pins the
// pre-assign fleet state through the real service: a profile with no rules
// and no binding resolves to nothing, which is an absence, never a pass.
func TestDeviceQuoteVerifier_NoBoundOrMatchingProfileIsAnAbsence(t *testing.T) {
	f := newQuoteFixture(t)
	ctx := context.Background()
	profiles := newRealProfileService(t)
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 4632, Name: "node-05", Role: entities.DeviceRoleWorker}))

	v := NewDeviceQuoteVerifier(f.devices, profiles, f.trust, f.sink, nil)
	v.now = func() time.Time { return f.now }
	result, err := v.Verify(ctx, itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)
	assert.False(t, result.Verified)
	assert.Contains(t, result.Message, "bound to or matches")
	assert.False(t, f.sink.last(t).Cryptographic)
}

// TestMCPServiceProvider_DeviceProfileAssign_ByDeviceID covers the MCP
// provider half of assign-by-device: derivation on the server, the no-EK
// failure, and the identity-only path when no device service is wired.
func TestMCPServiceProvider_DeviceProfileAssign_ByDeviceID(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()
	devices := newMockDeviceService()
	profiles := newMockProfileService()
	p.deviceService = devices
	p.deviceProfileService = profiles
	certPEM := newEKCertPEMForTest(t)
	devices.devices[1] = &entities.Device{ID: 1, EKCert: certPEM}
	devices.devices[2] = &entities.Device{ID: 2}
	profiles.profiles[9] = &entities.DeviceProfile{ID: 9, Name: "p"}

	profile, err := p.DeviceProfileAssign(ctx, 9, 1, "", "", "")
	require.NoError(t, err)
	wantSerial, err := entities.EKSerialFromCertPEM(certPEM)
	require.NoError(t, err)
	assert.Equal(t, wantSerial, profile.EKSerial)
	assert.Equal(t, certPEM, profile.EKCert)

	_, err = p.DeviceProfileAssign(ctx, 9, 2, "", "", "")
	var noCert device.ErrDeviceHasNoEKCert
	assert.True(t, errors.As(err, &noCert), "got %v", err)

	_, err = p.DeviceProfileAssign(ctx, 9, 404, "", "", "")
	assert.Error(t, err, "an unknown device is an error, not an unbound assign")

	p.deviceService = nil
	_, err = p.DeviceProfileAssign(ctx, 9, 1, "", "", "")
	var unavailable ErrServiceNotAvailable
	assert.True(t, errors.As(err, &unavailable), "got %v", err)
	profile, err = p.DeviceProfileAssign(ctx, 9, 0, "EK-9", "", "")
	require.NoError(t, err, "an explicit identity needs no device service")
	assert.Equal(t, "EK-9", profile.EKSerial)
}
