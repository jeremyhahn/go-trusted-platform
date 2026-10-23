//go:build integration

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

package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// The CLI prints the SDK's ServiceInfo as is, so its JSON encoding is what
// `service status -o json` writes.
func TestParseServiceStatusJSON_ReadsTheBareServiceObject(t *testing.T) {
	output, err := json.Marshal(&daemonsvc.ServiceInfo{
		Name:          "webservice",
		Type:          daemonsvc.ServiceType("webservice"),
		Status:        daemonsvc.ServiceStatus("running"),
		Health:        daemonsvc.HealthStatus("healthy"),
		UptimeSeconds: 42,
		Version:       "1.2.3",
	})
	require.NoError(t, err)

	result, err := parseServiceStatusJSON(output)
	require.NoError(t, err)
	require.NotNil(t, result.Service, "service status output %s was not read as a service", output)
	assert.Equal(t, ServiceInfo{
		Name:          "webservice",
		Type:          "webservice",
		Status:        "running",
		Health:        "healthy",
		UptimeSeconds: 42,
		Version:       "1.2.3",
	}, *result.Service)
}

func TestParseServiceStatusJSON_NullIsNoService(t *testing.T) {
	result, err := parseServiceStatusJSON([]byte("null"))
	require.NoError(t, err)
	assert.Nil(t, result.Service)
}

func TestParseServiceStatusJSON_RejectsNonJSON(t *testing.T) {
	_, err := parseServiceStatusJSON([]byte("Name: webservice"))
	var callErr ErrCallFailed
	require.ErrorAs(t, err, &callErr)
	assert.Equal(t, "service status", callErr.Method)
}
