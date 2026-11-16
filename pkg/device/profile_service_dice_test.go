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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const (
	testSvcDICEDeviceID  = "00112233445566778899aabbccddeeff"
	testSvcDICEDeviceID2 = "ffeeddccbbaa99887766554433221100"
	testSvcGoldenFWHash  = "aa00000000000000000000000000000000000000000000000000000000000001"
	testSvcGoldenFWHash2 = "bb00000000000000000000000000000000000000000000000000000000000002"
)

// TestProfileService_DICEFields_SaveRejectsInvalid proves Save runs the DICE
// validation: an invalid DICE device id or golden FWHash is refused with its
// typed error and nothing is stored (#1699).
func TestProfileService_DICEFields_SaveRejectsInvalid(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()
	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.Save(ctx, &entities.DeviceProfile{ID: 16991, Name: "avr", DICEDeviceID: "zz"})
	var badID entities.ErrInvalidDICEDeviceID
	require.ErrorAs(t, err, &badID)
	_, err = service.Get(ctx, 16991)
	assert.Error(t, err, "a refused Save must not store the profile")

	err = service.Save(ctx, &entities.DeviceProfile{ID: 16992, Name: "avr", GoldenFWHash: "aa"})
	var badHash entities.ErrInvalidGoldenFWHash
	require.ErrorAs(t, err, &badHash)
	_, err = service.Get(ctx, 16992)
	assert.Error(t, err, "a refused Save must not store the profile")
}

// TestProfileService_DICEFields_Update proves Update keeps stored DICE
// values when a replacement omits them, persists valid replacements, and
// refuses invalid ones without changing what is stored (#1699).
func TestProfileService_DICEFields_Update(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()
	service, err := NewProfileService(ds)
	require.NoError(t, err)

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 16993, Name: "avr", DICEDeviceID: testSvcDICEDeviceID, GoldenFWHash: testSvcGoldenFWHash,
	}))

	// A replacement that omits both keeps them.
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{ID: 16993, Name: "avr-renamed"}))
	stored, err := service.Get(ctx, 16993)
	require.NoError(t, err)
	assert.Equal(t, "avr-renamed", stored.Name)
	assert.Equal(t, testSvcDICEDeviceID, stored.DICEDeviceID)
	assert.Equal(t, testSvcGoldenFWHash, stored.GoldenFWHash)

	// A valid replacement persists.
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 16993, Name: "avr-renamed", DICEDeviceID: testSvcDICEDeviceID2, GoldenFWHash: testSvcGoldenFWHash2,
	}))
	stored, err = service.Get(ctx, 16993)
	require.NoError(t, err)
	assert.Equal(t, testSvcDICEDeviceID2, stored.DICEDeviceID)
	assert.Equal(t, testSvcGoldenFWHash2, stored.GoldenFWHash)

	// Invalid replacements are refused and leave the stored values alone.
	err = service.Update(ctx, &entities.DeviceProfile{ID: 16993, Name: "avr-renamed", DICEDeviceID: "not-hex"})
	var badID entities.ErrInvalidDICEDeviceID
	require.ErrorAs(t, err, &badID)
	err = service.Update(ctx, &entities.DeviceProfile{ID: 16993, Name: "avr-renamed", GoldenFWHash: "abcd"})
	var badHash entities.ErrInvalidGoldenFWHash
	require.ErrorAs(t, err, &badHash)
	stored, err = service.Get(ctx, 16993)
	require.NoError(t, err)
	assert.Equal(t, testSvcDICEDeviceID2, stored.DICEDeviceID)
	assert.Equal(t, testSvcGoldenFWHash2, stored.GoldenFWHash)
}

// TestProfileService_UnassignFromDevice_ClearsDICEDeviceID proves the DICE
// device id is a device binding: unassigning the profile clears it, so a
// lookup by the former id misses, while the golden FWHash (a property of
// the firmware build, not the device) stays (#1699).
func TestProfileService_UnassignFromDevice_ClearsDICEDeviceID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	profiles, err := ds.ProfileDAO()
	require.NoError(t, err)

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 16994, Name: "avr", DICEDeviceID: testSvcDICEDeviceID, GoldenFWHash: testSvcGoldenFWHash,
	}))
	found, err := profiles.FindByDICEDeviceID(ctx, testSvcDICEDeviceID)
	require.NoError(t, err)
	require.Equal(t, uint64(16994), found.ID)

	require.NoError(t, service.UnassignFromDevice(ctx, 16994))

	stored, err := service.Get(ctx, 16994)
	require.NoError(t, err)
	assert.Empty(t, stored.DICEDeviceID)
	assert.Equal(t, testSvcGoldenFWHash, stored.GoldenFWHash)
	_, err = profiles.FindByDICEDeviceID(ctx, testSvcDICEDeviceID)
	assert.Error(t, err, "a lookup by the former DICE id must miss after unassignment")
}
