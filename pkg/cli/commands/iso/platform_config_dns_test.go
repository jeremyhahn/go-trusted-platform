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

package iso

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDNSServerFromConfig_Priority(t *testing.T) {
	both := []byte(`
dns:
  resolver:
    servers:
      - address: "10.4.200.1"
        port: 8053
trust:
  bootstrap:
    dane:
      dns-server: "10.0.0.53:53"
`)
	assert.Equal(t, "10.4.200.1:8053", extractDNSServerFromConfig(both),
		"dns.resolver is the platform-wide default and wins")

	bootstrapOnly := []byte(`
trust:
  bootstrap:
    dane:
      dns-server: "10.0.0.53:53"
`)
	assert.Equal(t, "10.0.0.53:53", extractDNSServerFromConfig(bootstrapOnly),
		"the bootstrap class's DANE server is the fallback")
}

// TestExtractDNSServerFromConfig_NothingUsable covers the empty answers: no
// DNS configuration, a config still carrying the retired trust.default class
// (renamed trust.bootstrap), and YAML that does not parse.
func TestExtractDNSServerFromConfig_NothingUsable(t *testing.T) {
	assert.Empty(t, extractDNSServerFromConfig([]byte("domain: example.com\n")))

	retired := []byte(`
trust:
  default:
    dane:
      dns-server: "10.0.0.53:53"
`)
	assert.Empty(t, extractDNSServerFromConfig(retired), "trust.default is retired and is not read")

	assert.Empty(t, extractDNSServerFromConfig([]byte("trust: [unclosed")))
}
