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

package dns

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetXKMSAdapter_NilAdapter verifies SetXKMSAdapter with nil adapter.
func TestSetXKMSAdapter_NilAdapter(t *testing.T) {
	origConfig := Configuration
	origAdapter := XKMSAdapter
	origKeyStore := KeyStore
	defer func() {
		Configuration = origConfig
		XKMSAdapter = origAdapter
		KeyStore = origKeyStore
	}()

	Configuration = nil
	err := SetXKMSAdapter(nil)
	require.NoError(t, err)
	assert.Nil(t, XKMSAdapter)
}

// TestSetXKMSAdapter_WithDNSSECDisabled verifies adapter is set but zones not signed.
func TestSetXKMSAdapter_WithDNSSECDisabled(t *testing.T) {
	origConfig := Configuration
	origAdapter := XKMSAdapter
	defer func() {
		Configuration = origConfig
		XKMSAdapter = origAdapter
	}()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{
			Enabled: false,
		},
	}

	err := SetXKMSAdapter(nil)
	require.NoError(t, err)
}

// TestSignUnsignedZones_NilConfig_Coverage verifies nil configuration handling.
func TestSignUnsignedZones_NilConfig_Coverage(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = nil
	err := SignUnsignedZones()
	require.NoError(t, err)
}

// TestSignUnsignedZones_DNSSECDisabled_Coverage verifies disabled DNSSEC handling.
func TestSignUnsignedZones_DNSSECDisabled_Coverage(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: false},
	}
	err := SignUnsignedZones()
	require.NoError(t, err)
}

// TestSignUnsignedZones_NoAdapterOrKeyStore_Coverage verifies behavior without signing.
func TestSignUnsignedZones_NoAdapterOrKeyStore_Coverage(t *testing.T) {
	origConfig := Configuration
	origAdapter := XKMSAdapter
	origKeyStore := KeyStore
	defer func() {
		Configuration = origConfig
		XKMSAdapter = origAdapter
		KeyStore = origKeyStore
	}()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: true},
	}
	XKMSAdapter = nil
	KeyStore = nil

	err := SignUnsignedZones()
	require.NoError(t, err)
}

// TestSignZoneIfEnabled_NilConfig_Coverage verifies nil config handling.
func TestSignZoneIfEnabled_NilConfig_Coverage(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = nil
	err := signZoneIfEnabled(nil)
	require.NoError(t, err)
}

// TestSignZoneIfEnabled_DNSSECDisabled_Coverage verifies disabled DNSSEC handling.
func TestSignZoneIfEnabled_DNSSECDisabled_Coverage(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: false},
	}
	err := signZoneIfEnabled(nil)
	require.NoError(t, err)
}

// TestProcessZone_EmptyName_Coverage verifies error for empty zone name.
func TestProcessZone_EmptyName_Coverage(t *testing.T) {
	zone := entities.Zone{Name: ""}
	err := processZone(zone, nil, "internal")
	assert.ErrorIs(t, err, ErrServerZoneUndefined)
}
