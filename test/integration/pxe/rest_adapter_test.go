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

package pxe

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The options themselves are not built here: helpers.TLSConfigOrInsecure
// refuses to run without the suite's mTLS environment.

func TestNewRESTAdapter_KeepsTheEndpointScheme(t *testing.T) {
	t.Setenv(EnvPlatformAPIEndpoint, "https://localhost:8443")

	adapter := NewRESTAdapter()

	assert.Equal(t, "REST", adapter.Name())
	assert.Equal(t, "https://localhost:8443", adapter.endpoint, "the scheme the runner exports is not prefixed again")
}

func TestNewRESTAdapter_DefaultCarriesScheme(t *testing.T) {
	t.Setenv(EnvPlatformAPIEndpoint, "")

	assert.Equal(t, DefaultPlatformAPIEndpoint, NewRESTAdapter().endpoint)
	assert.True(t, strings.HasPrefix(DefaultPlatformAPIEndpoint, "https://"), "REST is served over TLS only")
}
