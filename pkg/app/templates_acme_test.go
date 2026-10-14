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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// TestShippedTemplates_ACMEPrivateTargetsOptIn pins which ACME server
// listeners let the http-01 and enroll-01 verifiers reach private addresses
// (acme.allow-private-targets, #755), across the templates and the cluster
// and standalone configs. Only an internal listener its nodes enroll through
// from private addresses opts in: a dedicated control plane's (its gateway
// and compute nodes, the Raspberry Pi compute included, sit in the private
// zones of the reference network), the cluster servers' (the clients enroll
// from 10.0.2.0/24 through https://10.0.1.1:9443, the servers themselves
// through their *.example.internal names) and the standalone server's (the
// gateway and client enroll from 10.99.99.0/24). Public listeners, the
// gateways' own ACME servers and the single-node profiles keep the SSRF guard.
func TestShippedTemplates_ACMEPrivateTargetsOptIn(t *testing.T) {
	want := []string{
		"platform/templates/dedicated/dell/r640/control-plane.yaml:internal",
		"platform/templates/dedicated/supermicro/x10/control-plane.yaml:internal",
		"platform/cluster/server1.example.com.yaml:internal",
		"platform/cluster/server2.example.com.yaml:internal",
		"platform/cluster/server3.example.com.yaml:internal",
		"platform/standalone/qemu.server.example.com.yaml:internal",
	}
	var got []string
	for _, root := range []string{templateRoot, clusterRoot, standaloneRoot} {
		for _, path := range platformConfigsUnder(t, root) {
			rel, err := filepath.Rel(configRoot, path)
			require.NoError(t, err)
			if composeManifests[filepath.ToSlash(rel)] {
				continue
			}
			for _, ws := range shippedWebServices(t, path) {
				if ws == nil || ws.ACME == nil || !ws.ACME.AllowPrivateTargets {
					continue
				}
				require.True(t, ws.ACME.Enabled, "%s:%s: allow-private-targets on a disabled ACME server", rel, ws.Name)
				require.NotEqual(t, "public", ws.Name, "%s: a public listener keeps the SSRF guard", rel)
				got = append(got, filepath.ToSlash(rel)+":"+ws.Name)
			}
		}
	}
	require.ElementsMatch(t, want, got)
}

// shippedWebServices decodes only the webservice listeners of a shipped
// platform config, the singular `webservice:` key first. The cluster and
// standalone configs do not load whole through initConfig today (stale
// network keys, integer key passwords), and the ACME pin needs no other part
// of the file.
func shippedWebServices(t *testing.T, path string) []*v1.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)), path)
	var listeners struct {
		WebService  *v1.Config   `mapstructure:"webservice"`
		WebServices []*v1.Config `mapstructure:"webservices"`
	}
	require.NoError(t, v.Unmarshal(&listeners, config.DecodeHook()), path)
	return append([]*v1.Config{listeners.WebService}, listeners.WebServices...)
}
