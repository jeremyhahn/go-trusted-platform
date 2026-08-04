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

package device

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileService_FindConfigForDevice_ByEKSerial(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:       5001,
		Name:     "EKSerialProfile",
		Model:    "TPM-EK",
		EKSerial: "EK-SERIAL-ABC-123",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	found, err := service.FindConfigForDevice(ctx, "EK-SERIAL-ABC-123", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, found.ID)
	assert.Equal(t, "EKSerialProfile", found.Name)
}

func TestProfileService_FindConfigForDevice_ByEKSerial_CaseInsensitive(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:       5002,
		Name:     "EKSerialCaseProfile",
		EKSerial: "EK-Serial-Mixed",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	found, err := service.FindConfigForDevice(ctx, "ek-serial-mixed", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, found.ID)
}

func TestProfileService_FindConfigForDevice_ByMAC(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:         5010,
		Name:       "MACProfile",
		Model:      "MAC-Device",
		MACAddress: "aa:bb:cc:dd:ee:ff",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// No EK serial match, falls through to exact MAC match
	found, err := service.FindConfigForDevice(ctx, "NO-MATCH-EK", "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, found.ID)
	assert.Equal(t, "MACProfile", found.Name)
}

func TestProfileService_FindConfigForDevice_ByMAC_CaseInsensitive(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:         5011,
		Name:       "MACCaseProfile",
		MACAddress: "AA:BB:CC:DD:EE:FF",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	found, err := service.FindConfigForDevice(ctx, "", "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, found.ID)
}

func TestProfileService_FindConfigForDevice_ByPrefixMatch(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Profile with match rules only (no EKSerial or MACAddress set)
	profile := &entities.DeviceProfile{
		ID:    5020,
		Name:  "PrefixProfile",
		Model: "Prefix-Device",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Neither exact EK nor exact MAC match, falls through to prefix match
	found, err := service.FindConfigForDevice(ctx, "", "52:54:00:ab:cd:ef")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, found.ID)
	assert.Equal(t, "PrefixProfile", found.Name)
}

func TestProfileService_FindConfigForDevice_NotFound(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create a profile that won't match
	profile := &entities.DeviceProfile{
		ID:       5030,
		Name:     "OtherProfile",
		EKSerial: "SPECIFIC-EK",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	_, err = service.FindConfigForDevice(ctx, "NO-MATCH-EK", "no:ma:tc:hh:er:ee")
	assert.Error(t, err)

	var noMatchErr ErrNoMatchingConfig
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Equal(t, "NO-MATCH-EK", noMatchErr.EKSerial)
	assert.Equal(t, "no:ma:tc:hh:er:ee", noMatchErr.MAC)
}

func TestProfileService_FindConfigForDevice_EmptyIdentifiers(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	_, err = service.FindConfigForDevice(ctx, "", "")
	assert.Error(t, err)

	var identityErr ErrDeviceIdentityRequired
	assert.ErrorAs(t, err, &identityErr)
}

func TestProfileService_FindConfigForDevice_PriorityOrder(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Profile matching by EK serial
	ekProfile := &entities.DeviceProfile{
		ID:       5040,
		Name:     "EKProfile",
		EKSerial: "EK-PRIORITY-001",
	}

	// Profile matching by exact MAC
	macProfile := &entities.DeviceProfile{
		ID:         5041,
		Name:       "MACProfile",
		MACAddress: "52:54:00:11:22:33",
	}

	// Profile matching by MAC prefix
	prefixProfile := &entities.DeviceProfile{
		ID:   5042,
		Name: "PrefixProfile",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, ekProfile)
	require.NoError(t, err)
	err = service.Save(ctx, macProfile)
	require.NoError(t, err)
	err = service.Save(ctx, prefixProfile)
	require.NoError(t, err)

	// EK serial should win even though MAC also matches
	found, err := service.FindConfigForDevice(ctx, "EK-PRIORITY-001", "52:54:00:11:22:33")
	require.NoError(t, err)
	assert.Equal(t, ekProfile.ID, found.ID)
	assert.Equal(t, "EKProfile", found.Name)
}

func TestProfileService_AssignToDevice(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    6001,
		Name:  "AssignableProfile",
		Model: "Assign-Device",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 6001, "EK-ASSIGN-001", "52:54:00:aa:bb:cc")
	require.NoError(t, err)

	// Verify the assignment
	retrieved, err := service.Get(ctx, 6001)
	require.NoError(t, err)
	assert.Equal(t, "EK-ASSIGN-001", retrieved.EKSerial)
	assert.Equal(t, "52:54:00:aa:bb:cc", retrieved.MACAddress)
	assert.True(t, retrieved.Assigned)
	assert.False(t, retrieved.AssignedAt.IsZero())
}

func TestProfileService_AssignToDevice_EKSerialOnly(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   6002,
		Name: "EKOnlyProfile",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 6002, "EK-ONLY-001", "")
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, 6002)
	require.NoError(t, err)
	assert.Equal(t, "EK-ONLY-001", retrieved.EKSerial)
	assert.Equal(t, "", retrieved.MACAddress)
	assert.True(t, retrieved.Assigned)
}

func TestProfileService_AssignToDevice_MACOnly(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   6003,
		Name: "MACOnlyProfile",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 6003, "", "52:54:00:dd:ee:ff")
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, 6003)
	require.NoError(t, err)
	assert.Equal(t, "", retrieved.EKSerial)
	assert.Equal(t, "52:54:00:dd:ee:ff", retrieved.MACAddress)
	assert.True(t, retrieved.Assigned)
}

func TestProfileService_AssignToDevice_InvalidProfile(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 9999, "EK-NONEXIST", "52:54:00:00:00:01")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get profile for assignment")
}

func TestProfileService_AssignToDevice_NoIdentity(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 6004, "", "")
	assert.Error(t, err)

	var identityErr ErrDeviceIdentityRequired
	assert.ErrorAs(t, err, &identityErr)
}

func TestProfileService_AssignToDevice_ZeroID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 0, "EK-001", "52:54:00:00:00:01")
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_AssignToDevice_PreservesExistingFields(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    6005,
		Name:  "PreserveProfile",
		Model: "Preserve-Model",
		Role:  entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	err = service.AssignToDevice(ctx, 6005, "EK-PRESERVE-001", "52:54:00:99:88:77")
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, 6005)
	require.NoError(t, err)

	// New fields set
	assert.Equal(t, "EK-PRESERVE-001", retrieved.EKSerial)
	assert.Equal(t, "52:54:00:99:88:77", retrieved.MACAddress)
	assert.True(t, retrieved.Assigned)

	// Existing fields preserved
	assert.Equal(t, "PreserveProfile", retrieved.Name)
	assert.Equal(t, "Preserve-Model", retrieved.Model)
	assert.Equal(t, entities.DeviceRoleServer, retrieved.Role)
	assert.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, "52:54:00", retrieved.MatchRules.MACPrefix)
}

const testEKCertPEM = `-----BEGIN CERTIFICATE-----
MIIBETCBuKADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAMTBHRlc3QwHhcN
MjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDEwR0ZXN0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXAMPLEekcertplaceholderpublickey
placeholderplaceholderplaceholderplaceholderplACEHOLDERpADAKBggq
hkjOPQQDAgNAADBA
-----END CERTIFICATE-----`

// TestProfileService_AssignToDeviceWithEK_StoresEKCert verifies the EK
// certificate is prestaged on the profile alongside the EK serial and MAC.
func TestProfileService_AssignToDeviceWithEK_StoresEKCert(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   7001,
		Name: "EKCertProfile",
	}
	require.NoError(t, service.Save(ctx, profile))

	err = service.AssignToDeviceWithEK(ctx, 7001, "EK-CERT-001", "52:54:00:ab:cd:ef", testEKCertPEM)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, 7001)
	require.NoError(t, err)
	assert.Equal(t, "EK-CERT-001", retrieved.EKSerial)
	assert.Equal(t, "52:54:00:ab:cd:ef", retrieved.MACAddress)
	assert.Equal(t, testEKCertPEM, retrieved.EKCert)
	assert.True(t, retrieved.Assigned)
	assert.False(t, retrieved.AssignedAt.IsZero())
}

// TestProfileService_AssignToDeviceWithEK_EmptyCertPreservesExisting verifies an
// empty ekCertPEM leaves any previously prestaged EK certificate untouched.
func TestProfileService_AssignToDeviceWithEK_EmptyCertPreservesExisting(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:     7002,
		Name:   "EKCertPreserveProfile",
		EKCert: testEKCertPEM,
	}
	require.NoError(t, service.Save(ctx, profile))

	// Re-assign with an empty cert; the prestaged EKCert must be preserved.
	err = service.AssignToDeviceWithEK(ctx, 7002, "EK-CERT-002", "", "")
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, 7002)
	require.NoError(t, err)
	assert.Equal(t, "EK-CERT-002", retrieved.EKSerial)
	assert.Equal(t, testEKCertPEM, retrieved.EKCert)
}

// TestProfileService_AssignToDevice_LeavesEKCertEmpty verifies the back-compat
// wrapper does not set an EK certificate.
func TestProfileService_AssignToDevice_LeavesEKCertEmpty(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{ID: 7003, Name: "NoEKCertProfile"}
	require.NoError(t, service.Save(ctx, profile))

	require.NoError(t, service.AssignToDevice(ctx, 7003, "EK-CERT-003", "52:54:00:11:22:33"))

	retrieved, err := service.Get(ctx, 7003)
	require.NoError(t, err)
	assert.Equal(t, "EK-CERT-003", retrieved.EKSerial)
	assert.Empty(t, retrieved.EKCert)
}

// TestProfileService_AssignToDeviceWithEK_NoIdentity verifies the EK-aware
// assignment still requires at least an EK serial or MAC address.
func TestProfileService_AssignToDeviceWithEK_NoIdentity(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.AssignToDeviceWithEK(ctx, 7004, "", "", testEKCertPEM)
	assert.Error(t, err)
	var identityErr ErrDeviceIdentityRequired
	assert.ErrorAs(t, err, &identityErr)
}

// TestDeviceProfile_RoundTripsEKCert verifies the EKCert field survives a
// save/get round trip through the datastore.
func TestDeviceProfile_RoundTripsEKCert(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:     7005,
		Name:   "RoundTripProfile",
		EKCert: testEKCertPEM,
	}
	require.NoError(t, service.Save(ctx, profile))

	retrieved, err := service.Get(ctx, 7005)
	require.NoError(t, err)
	assert.Equal(t, testEKCertPEM, retrieved.EKCert)
}

// TestProfileService_UnassignFromDevice verifies UnassignFromDevice
// clears the EK serial, MAC address, prestaged EK certificate, and
// assignment state (the symmetric inverse of AssignToDeviceWithEK).
func TestProfileService_UnassignFromDevice(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   7005,
		Name: "UnassignProfile",
	}
	require.NoError(t, service.Save(ctx, profile))
	require.NoError(t, service.AssignToDeviceWithEK(ctx, 7005, "EK-CERT-005", "52:54:00:ab:cd:05", testEKCertPEM))

	require.NoError(t, service.UnassignFromDevice(ctx, 7005))

	retrieved, err := service.Get(ctx, 7005)
	require.NoError(t, err)
	assert.Empty(t, retrieved.EKSerial)
	assert.Empty(t, retrieved.MACAddress)
	assert.Empty(t, retrieved.EKCert)
	assert.False(t, retrieved.Assigned)
	assert.True(t, retrieved.AssignedAt.IsZero())
}

// TestProfileService_UnassignFromDevice_Errors verifies the invalid-ID
// and unknown-profile error paths.
func TestProfileService_UnassignFromDevice_Errors(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.UnassignFromDevice(ctx, 0)
	assert.ErrorIs(t, err, ErrInvalidProfileID{})

	err = service.UnassignFromDevice(ctx, 999999)
	assert.Error(t, err)
}
