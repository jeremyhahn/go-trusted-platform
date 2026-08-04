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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newEKCertPEMForTest generates a self-signed ECDSA certificate PEM used
// to exercise the profile EK-cert prestage path.
func newEKCertPEMForTest(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestDeviceGRPCService_ProfileEKCert_RoundTrip verifies the prestaged EK
// certificate survives the pb -> entity -> pb round trip, closing the gap
// that previously made EK-cert prestage impossible over the wire.
func TestDeviceGRPCService_ProfileEKCert_RoundTrip(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	certPEM := newEKCertPEMForTest(t)

	entity, err := svc.pbToProfile(&platformv1.DeviceProfile{
		Id:     500,
		Name:   "EKProfile",
		EkCert: certPEM,
	})
	require.NoError(t, err)
	require.NotNil(t, entity)
	assert.Equal(t, certPEM, entity.EKCert)

	// The EK certificate is public material, so reads echo it back.
	roundTrip := svc.profileToPb(entity)
	require.NotNil(t, roundTrip)
	assert.Equal(t, certPEM, roundTrip.EkCert)
}

// TestDeviceGRPCService_pbToProfile_InvalidEKCert verifies an unparseable
// prestaged EK certificate is rejected with the typed entities error.
func TestDeviceGRPCService_pbToProfile_InvalidEKCert(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	t.Run("not PEM", func(t *testing.T) {
		result, err := svc.pbToProfile(&platformv1.DeviceProfile{
			Id:     501,
			Name:   "BadEK",
			EkCert: "not a pem certificate",
		})
		require.Error(t, err)
		assert.Nil(t, result)
		var notPEM entities.ErrEKCertNotPEM
		require.ErrorAs(t, err, &notPEM)
	})

	t.Run("PEM but not a certificate", func(t *testing.T) {
		bogus := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
		result, err := svc.pbToProfile(&platformv1.DeviceProfile{
			Id:     502,
			Name:   "BadEKDER",
			EkCert: bogus,
		})
		require.Error(t, err)
		assert.Nil(t, result)
		var invalid entities.ErrEKCertInvalid
		require.ErrorAs(t, err, &invalid)
	})
}

// TestDeviceGRPCService_CreateProfile_EKCert verifies the create RPC
// persists a valid prestaged EK certificate and echoes it in the response.
func TestDeviceGRPCService_CreateProfile_EKCert(t *testing.T) {
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(newMockDeviceService(), profileSvc, nil)
	certPEM := newEKCertPEMForTest(t)

	resp, err := svc.CreateProfile(context.Background(), &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:     "EKSeeded",
			EkSerial: "EK-SEEDED-CERT",
			EkCert:   certPEM,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, certPEM, resp.GetProfile().GetEkCert())
	assert.Equal(t, "EK-SEEDED-CERT", resp.GetProfile().GetEkSerial())
}

// TestDeviceGRPCService_CreateProfile_InvalidEKCert verifies the create
// RPC maps an unparseable EK certificate to InvalidArgument.
func TestDeviceGRPCService_CreateProfile_InvalidEKCert(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	resp, err := svc.CreateProfile(context.Background(), &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:   "BadEKCert",
			EkCert: "garbage",
		},
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestDeviceGRPCService_UpdateProfile_InvalidEKCert verifies the update
// RPC maps an unparseable EK certificate to InvalidArgument.
func TestDeviceGRPCService_UpdateProfile_InvalidEKCert(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	resp, err := svc.UpdateProfile(context.Background(), &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:     503,
			Name:   "BadEKCert",
			EkCert: "garbage",
		},
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestDeviceGRPCService_AssignProfileToDevice verifies the assignment RPC
// binds the EK identity, prestages the EK certificate, and returns the
// updated profile.
func TestDeviceGRPCService_AssignProfileToDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)
	ctx := context.Background()
	certPEM := newEKCertPEMForTest(t)

	profileSvc.profiles[900] = &entities.DeviceProfile{ID: 900, Name: "assign-me"}

	resp, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId:  900,
		EkSerial:   "EK-9009",
		MacAddress: "00:25:90:11:22:33",
		EkCert:     certPEM,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetProfile())
	assert.True(t, resp.GetProfile().GetAssigned())
	assert.Equal(t, "EK-9009", resp.GetProfile().GetEkSerial())
	assert.Equal(t, "00:25:90:11:22:33", resp.GetProfile().GetMacAddress())
	assert.Equal(t, certPEM, resp.GetProfile().GetEkCert())

	stored := profileSvc.profiles[900]
	assert.True(t, stored.Assigned)
	assert.Equal(t, certPEM, stored.EKCert)
	assert.False(t, stored.AssignedAt.IsZero())
}

// TestDeviceGRPCService_AssignProfileToDevice_Errors verifies the
// boundary validation and service error paths of the assignment RPC.
func TestDeviceGRPCService_AssignProfileToDevice_Errors(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)
	ctx := context.Background()
	profileSvc.profiles[901] = &entities.DeviceProfile{ID: 901}

	t.Run("MissingProfileID", func(t *testing.T) {
		_, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
			EkSerial: "EK-1",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("MissingIdentity", func(t *testing.T) {
		_, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
			ProfileId: 901,
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		_, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
			ProfileId: 901,
			EkSerial:  "EK-1",
			EkCert:    "not-a-pem",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		_, err := svc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
			ProfileId: 987654,
			EkSerial:  "EK-1",
		})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

// TestDeviceGRPCService_UnassignProfileFromDevice verifies the
// unassignment RPC clears the device binding and returns the updated
// profile, plus its error paths.
func TestDeviceGRPCService_UnassignProfileFromDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)
	ctx := context.Background()

	profileSvc.profiles[910] = &entities.DeviceProfile{
		ID:       910,
		EKSerial: "EK-9109",
		EKCert:   newEKCertPEMForTest(t),
		Assigned: true,
	}

	resp, err := svc.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{
		ProfileId: 910,
	})
	require.NoError(t, err)
	assert.False(t, resp.GetProfile().GetAssigned())
	assert.Empty(t, resp.GetProfile().GetEkSerial())
	assert.Empty(t, resp.GetProfile().GetEkCert())

	t.Run("MissingProfileID", func(t *testing.T) {
		_, err := svc.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		_, err := svc.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{
			ProfileId: 777777,
		})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}
