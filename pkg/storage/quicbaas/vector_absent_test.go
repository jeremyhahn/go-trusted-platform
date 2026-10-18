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

//go:build !vector

package quicbaas

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVector_NotCompiled_UpsertFailsFast proves a build without the vector
// service answers Vector calls at once with a typed error naming the
// missing build, instead of an opaque UNIMPLEMENTED from the server.
func TestVector_NotCompiled_UpsertFailsFast(t *testing.T) {
	client := withVectorAvailability(&Config{Vector: &VectorServiceConfig{Enabled: true}}, nil)

	resp, err := client.Vector().Upsert(context.Background(), &vector.UpsertRequest{Vector: &vector.VectorEntity{Namespace: "ns", ID: "v1"}})
	assert.Nil(t, resp)
	var unavailable ErrVectorUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, vectorNotCompiledReason, unavailable.Reason)
	assert.Contains(t, err.Error(), "carries no vector service")

	_, err = client.Vector().SearchSimilar(context.Background(), &vector.SearchSimilarRequest{Namespace: "ns"})
	assert.True(t, errors.As(err, &unavailable))
	_, err = client.Vector().Export(context.Background(), &vector.ExportRequest{Namespace: "ns"})
	assert.True(t, errors.As(err, &unavailable))
}

// TestValidate_VectorEnabledWithoutVectorBuild proves Validate refuses a
// vector section the build cannot serve rather than starting a server that
// silently lacks the service.
func TestValidate_VectorEnabledWithoutVectorBuild(t *testing.T) {
	cfg := &Config{Vector: &VectorServiceConfig{Enabled: true}}
	var invalid ErrInvalidConfig
	require.True(t, errors.As(cfg.validateVector(), &invalid))
	assert.Equal(t, "Vector", invalid.Field)

	assert.NoError(t, (&Config{}).validateVector(), "an absent section is valid in every build")
}
