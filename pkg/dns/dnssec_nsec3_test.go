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

//go:build !fips

// NSEC3 zone signing cannot be exercised in a FIPS build, so its test lives
// here rather than being weakened to run in both.
//
// RFC 5155 registers exactly one NSEC3 hash algorithm — 1, SHA-1 — and
// crypto/sha1 PANICS under GODEBUG=fips140=only. There is no approved variant
// to substitute and none can be added without a new RFC, so this is a property
// of the protocol rather than a gap in this implementation (#249).
//
// The FIPS side is covered in config_fips_test.go, which asserts the
// configuration is refused before anything is signed. The same reasoning puts
// the SHA-1 and MD5 known-answer vectors behind !fips in pkg/bmc.

package dns

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignZone_NSEC3Mode tests signing with NSEC3
func TestSignZone_NSEC3Mode(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
		SignatureExpiry: "30d",
		NSECMode:        "nsec3",
		NSEC3Iterations: 0,
		NSEC3Salt:       "aabb",
	}

	store := NewMockKeyStore()
	service := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	zone := createTestZone()

	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify NSEC3 records were created
	assert.Greater(t, len(zone.RecordSet.NSEC3Records), 0, "Should have NSEC3 records")

	// Verify NSEC3PARAM record was created
	assert.GreaterOrEqual(t, len(zone.RecordSet.NSEC3PARAMRecords), 1, "Should have NSEC3PARAM record")

	// Should not have NSEC records
	assert.Equal(t, 0, len(zone.RecordSet.NSECRecords), "Should not have NSEC records when using NSEC3")
}
