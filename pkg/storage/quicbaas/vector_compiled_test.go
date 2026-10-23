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

//go:build vector

package quicbaas

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVector_Compiled_EnabledKeepsClient proves a vector build with the
// service enabled hands back the SDK client untouched.
func TestVector_Compiled_EnabledKeepsClient(t *testing.T) {
	cfg := &Config{Vector: &VectorServiceConfig{Enabled: true}}
	require.NoError(t, cfg.validateVector())
	assert.Empty(t, cfg.vectorUnavailableReason())
	assert.Nil(t, withVectorAvailability(cfg, nil))
}

// TestVector_Compiled_DisabledFailsFast proves a vector build with the
// service off names the disabled setting, not the build.
func TestVector_Compiled_DisabledFailsFast(t *testing.T) {
	client := withVectorAvailability(&Config{}, nil)
	_, err := client.Vector().Upsert(context.Background(), &vector.UpsertRequest{Vector: &vector.VectorEntity{Namespace: "ns", ID: "v1"}})
	var unavailable ErrVectorUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, vectorDisabledReason, unavailable.Reason)
}
