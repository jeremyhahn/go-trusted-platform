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

package vxlan

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithVTEPLogger_ReplacesTheConstructorLogger(t *testing.T) {
	var constructorOut, optionOut bytes.Buffer
	constructorLogger := slog.New(slog.NewTextHandler(&constructorOut, nil))
	optionLogger := slog.New(slog.NewTextHandler(&optionOut, nil))

	m, err := NewVTEPManager(validVTEPConfig(), newFakeOVS(), "br-int", constructorLogger,
		WithVTEPLogger(optionLogger))
	require.NoError(t, err)

	require.NoError(t, m.Start(context.Background()))

	assert.Contains(t, optionOut.String(), "VTEP manager started")
	assert.Contains(t, optionOut.String(), "local_vtep=10.0.0.1")
	assert.Empty(t, constructorOut.String(), "the option logger supersedes the constructor's")
}

func TestVNIMapper_VLANToVNIDefaultMappingBounds(t *testing.T) {
	// A base this close to the 24-bit ceiling leaves room for VLANs 0..10 only.
	mapper := NewVNIMapper(VNIMappingConfig{BaseVNI: MaxVNI - 10, MaxVLAN: 4094})

	tests := map[string]struct {
		vlan    uint16
		want    VNI
		wantErr error
	}{
		"lowest VLAN":            {vlan: 0, want: MaxVNI - 10},
		"lands on the ceiling":   {vlan: 10, want: MaxVNI},
		"one past the ceiling":   {vlan: 11, wantErr: ErrVNIOutOfRange},
		"far past the ceiling":   {vlan: 4094, wantErr: ErrVNIOutOfRange},
		"VLAN above the maximum": {vlan: 4095, wantErr: ErrVLANOutOfRange},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := mapper.VLANToVNI(tc.vlan)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("an explicit mapping overrides an overflowing default", func(t *testing.T) {
		require.NoError(t, mapper.RegisterMapping(11, VNI(5000)))
		got, err := mapper.VLANToVNI(11)
		require.NoError(t, err)
		assert.Equal(t, VNI(5000), got)
	})
}
