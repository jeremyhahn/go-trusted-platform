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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCorefile(t *testing.T) {
	port := 8053
	result := NewCorefile(port)

	assert.Contains(t, result, ".:8053")
	assert.Contains(t, result, "trustedPlatform")
	assert.Contains(t, result, "log")
	assert.Contains(t, result, "chaos")
	assert.NotContains(t, result, "forward")
}

func TestNewCorefileWithForwarders(t *testing.T) {
	port := 9053
	forwarders := []string{"8.8.8.8", "1.1.1.1"}
	result := NewCorefileWithForwarders(port, forwarders)

	assert.Contains(t, result, ".:9053")
	assert.Contains(t, result, "trustedPlatform")
	assert.Contains(t, result, "log")
	assert.Contains(t, result, "chaos")
	assert.Contains(t, result, "forward . 8.8.8.8 1.1.1.1")
}

func TestNewCorefileWithForwarders_EmptyList(t *testing.T) {
	port := 5353
	forwarders := []string{}
	result := NewCorefileWithForwarders(port, forwarders)

	assert.Contains(t, result, ".:5353")
	// Empty forwarders list should result in "forward . " with no servers
	assert.True(t, strings.Contains(result, "forward ."))
}

func TestNewCorefileWithForwarders_SingleForwarder(t *testing.T) {
	port := 53
	forwarders := []string{"192.168.1.1"}
	result := NewCorefileWithForwarders(port, forwarders)

	assert.Contains(t, result, ".:53")
	assert.Contains(t, result, "forward . 192.168.1.1")
}
