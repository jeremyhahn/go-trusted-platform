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

package sdn

import (
	"testing"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNetworkZoneExtensions_Disabled(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns nil", func(t *testing.T) {
		exts, err := BuildNetworkZoneExtensions(nil, "trusted", "SN-001")
		require.NoError(t, err)
		assert.Nil(t, exts)
	})

	t.Run("encode_zone_in_cert false returns nil", func(t *testing.T) {
		cfg := &IdentityConfig{EncodeZoneInCert: false}
		exts, err := BuildNetworkZoneExtensions(cfg, "trusted", "SN-001")
		require.NoError(t, err)
		assert.Nil(t, exts)
	})
}

func TestBuildNetworkZoneExtensions_Enabled(t *testing.T) {
	t.Parallel()

	t.Run("valid zone returns one extension", func(t *testing.T) {
		cfg := &IdentityConfig{EncodeZoneInCert: true}
		exts, err := BuildNetworkZoneExtensions(cfg, "trusted", "SN-001")
		require.NoError(t, err)
		require.Len(t, exts, 1)
		assert.True(t, exts[0].Id.Equal(quicbaasca.OIDTPNetworkZone))
	})

	t.Run("extension round-trips through ParseNetworkZoneExtension", func(t *testing.T) {
		cfg := &IdentityConfig{EncodeZoneInCert: true}
		exts, err := BuildNetworkZoneExtensions(cfg, "production", "SN-002")
		require.NoError(t, err)
		require.Len(t, exts, 1)

		got, err := quicbaasca.ParseNetworkZoneExtension(exts[0])
		require.NoError(t, err)
		assert.Equal(t, "production", got)
	})

	t.Run("empty zone returns ErrEncodeZoneEmpty", func(t *testing.T) {
		cfg := &IdentityConfig{EncodeZoneInCert: true}
		_, err := BuildNetworkZoneExtensions(cfg, "", "SN-003")
		require.Error(t, err)
		var ze ErrEncodeZoneEmpty
		assert.ErrorAs(t, err, &ze)
		assert.Equal(t, "SN-003", ze.Serial)
	})

	t.Run("empty zone empty serial formats without serial", func(t *testing.T) {
		cfg := &IdentityConfig{EncodeZoneInCert: true}
		_, err := BuildNetworkZoneExtensions(cfg, "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encode_zone_in_cert is true")
	})
}

func TestIdentityConfig_ResolvedPlatformZone(t *testing.T) {
	t.Parallel()

	t.Run("nil receiver returns empty string", func(t *testing.T) {
		var cfg *IdentityConfig
		assert.Equal(t, "", cfg.ResolvedPlatformZone())
	})

	t.Run("empty PlatformZone defaults to management", func(t *testing.T) {
		cfg := &IdentityConfig{}
		assert.Equal(t, "management", cfg.ResolvedPlatformZone())
	})

	t.Run("explicit PlatformZone is returned as-is", func(t *testing.T) {
		cfg := &IdentityConfig{PlatformZone: "trusted"}
		assert.Equal(t, "trusted", cfg.ResolvedPlatformZone())
	})
}
