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

package app

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
)

// integrationConfig is the platformd config run-integration-tests.sh starts
// the shared daemon on.
const integrationConfig = "../../test/integration/config.yaml"

// TestIntegrationConfig_LoadsWithDNSServer loads the integration config the
// way platformd does (strict network/sdn check, full decode) and checks the
// dns section strictly too: every key decodes, and it configures a server,
// so StartDNS and newDNSService give the daemon a DNS backend.
func TestIntegrationConfig_LoadsWithDNSServer(t *testing.T) {
	a := loadTemplate(t, integrationConfig)

	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	require.NoError(t, config.CheckViperSection(v, "dns", &dns.Config{}))

	require.NotNil(t, a.DNSConfig, "dns section")
	assert.True(t, a.DNSConfig.HasServer(), "dns section configures a server")
	require.NotNil(t, a.DNSConfig.InternalServer)
	assert.Equal(t, "integration.internal.", a.DNSConfig.InternalServer.Zone.Name)
	assert.Equal(t, uint32(300), a.DNSConfig.InternalServer.Zone.RecordSet.SOARecord.MinimumTTL,
		"the SOA minimum TTL decodes (its key is min_ttl)")
	assert.Nil(t, a.DNSConfig.DNSSEC, "DNSSEC stays off")
}

// TestIntegrationConfig_DNSTypoRefused proves the dns check above can fail:
// the shipped-example spelling minimum_ttl is not a key the SOA decodes.
func TestIntegrationConfig_DNSTypoRefused(t *testing.T) {
	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	typo := bytes.Replace(raw, []byte("min_ttl:"), []byte("minimum_ttl:"), 1)
	require.NotEqual(t, raw, typo, "the config carries an SOA min_ttl")

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(typo)))
	err = config.CheckViperSection(v, "dns", &dns.Config{})

	var unknown *config.ErrUnknownConfigKeys
	require.True(t, errors.As(err, &unknown), "got %v", err)
	assert.Equal(t, "dns", unknown.Section)
}
