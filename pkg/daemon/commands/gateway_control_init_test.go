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

package commands

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// sourceFor builds a desired-config source over a private viper tree, so
// the test never touches the daemon's global instance.
func sourceFor(t *testing.T, doc string) *viperDesiredConfigSource {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(doc)))
	return &viperDesiredConfigSource{v: v}
}

func TestViperDesiredConfigSource_DecodesTheDesiredBlock(t *testing.T) {
	src := sourceFor(t, `
gateway:
  desired:
    version: rev-4
    load-balancer:
      vips:
        - address: 10.0.200.10
          port: 443
          protocol: tcp
          backends:
            - address: 10.0.100.11
              port: 8443
              weight: 2
    nat:
      snat-internal-cidr: 10.0.100.0/24
      dnat:
        - protocol: tcp
          external: 203.0.113.10:2222
          internal: 10.0.100.5:22
`)
	cfg, err := src.DesiredConfig("node-01-gateway")
	require.NoError(t, err)
	assert.Equal(t, "node-01-gateway", cfg.GatewayID)
	assert.Equal(t, "rev-4", cfg.Version)
	require.NotNil(t, cfg.LoadBalancer)
	require.Len(t, cfg.LoadBalancer.VIPs, 1)
	assert.Equal(t, uint16(2), cfg.LoadBalancer.VIPs[0].Backends[0].Weight)
	require.NotNil(t, cfg.NAT)
	assert.Equal(t, "tcp/203.0.113.10:2222", cfg.NAT.DNAT[0].Key())
}

func TestViperDesiredConfigSource_AbsentBlockIsEmpty(t *testing.T) {
	cfg, err := sourceFor(t, "sdn:\n  enabled: true\n").DesiredConfig("gw-1")
	require.NoError(t, err)
	assert.Equal(t, &gwstate.DesiredConfig{GatewayID: "gw-1"}, cfg)
}

func TestViperDesiredConfigSource_RefusesAnInvalidBlock(t *testing.T) {
	_, err := sourceFor(t, "gateway:\n  desired:\n    nat:\n      snat-internal-cidr: not-a-prefix\n").DesiredConfig("gw-1")
	require.True(t, gwstate.IsDesiredConfigRejection(err), "got %v", err)

	_, err = sourceFor(t, "gateway:\n  desired:\n    load-balancer:\n      vips: nope\n").DesiredConfig("gw-1")
	var decodeErr *ErrDesiredConfigDecode
	require.True(t, errors.As(err, &decodeErr), "got %v", err)
	assert.Contains(t, err.Error(), desiredConfigKey)
}

func TestViperDesiredConfigSource_NilTreeUsesTheGlobal(t *testing.T) {
	cfg, err := (&viperDesiredConfigSource{}).DesiredConfig("gw-1")
	require.NoError(t, err)
	assert.Equal(t, "gw-1", cfg.GatewayID)
}
