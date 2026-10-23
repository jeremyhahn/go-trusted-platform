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

//go:build integration

package registry

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLIStatusResponse_ParsesNestedJSON pins the adapter to the JSON
// `platformctl registry status -o json` prints.
func TestCLIStatusResponse_ParsesNestedJSON(t *testing.T) {
	output := []byte(`{"status":{"healthy":true,"version":"1.2.3","uptime_seconds":60,` +
		`"storage":{"backend":"quicbaas","healthy":true,"used_bytes":2048,"image_count":3},` +
		`"attestation":{"enabled":true},"encryption":{"enabled":false}}}`)

	var resp cliStatusResponse
	require.NoError(t, json.Unmarshal(output, &resp))
	result, err := resp.toStatusResult()
	require.NoError(t, err)

	assert.True(t, result.Healthy)
	assert.Equal(t, "running", result.Status)
	assert.Equal(t, "1.2.3", result.Version)
	assert.Equal(t, 60*time.Second, result.Uptime)
	assert.Equal(t, "quicbaas", result.StorageBackend)
	assert.Equal(t, "healthy", result.StorageStatus)
	assert.Equal(t, 3, result.ImageCount)
	assert.Equal(t, int64(2048), result.TotalSize)
	assert.True(t, result.AttestationEnabled)
	assert.False(t, result.EncryptionEnabled)
}

// TestCLIStatusResponse_RejectsFlatJSON: the old flat shape has no
// "status" object and must not parse into an empty, passing result.
func TestCLIStatusResponse_RejectsFlatJSON(t *testing.T) {
	output := []byte(`{"healthy":true,"version":"1.2.3","storage_backend":"quicbaas"}`)

	var resp cliStatusResponse
	require.NoError(t, json.Unmarshal(output, &resp))
	result, err := resp.toStatusResult()

	assert.Nil(t, result)
	var missing ErrMissingField
	require.True(t, errors.As(err, &missing), "want ErrMissingField, got %v", err)
	assert.Equal(t, "status", missing.Field)
}
