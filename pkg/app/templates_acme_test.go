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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// TestShippedTemplates_ACMEPrivateTargetsOptIn pins which ACME server
// listeners let the http-01 and enroll-01 verifiers reach private addresses
// (acme.allow-private-targets, #755). Only the internal listener of a
// dedicated control plane opts in: its gateway and compute nodes, the
// Raspberry Pi compute included, enroll from the private zones of the
// reference network. Public listeners, the gateways' own ACME servers and the
// single-node profiles keep the SSRF guard.
func TestShippedTemplates_ACMEPrivateTargetsOptIn(t *testing.T) {
	want := []string{
		"dedicated/dell/r640/control-plane.yaml:internal",
		"dedicated/supermicro/x10/control-plane.yaml:internal",
	}
	var got []string
	for _, path := range shippedPlatformTemplates(t) {
		a := loadTemplate(t, path)
		rel, err := filepath.Rel(templateRoot, path)
		require.NoError(t, err)
		for _, ws := range append([]*v1.Config{a.WebServiceConfig}, a.WebServices...) {
			if ws == nil || ws.ACME == nil || !ws.ACME.AllowPrivateTargets {
				continue
			}
			require.True(t, ws.ACME.Enabled, "%s:%s: allow-private-targets on a disabled ACME server", rel, ws.Name)
			got = append(got, rel+":"+ws.Name)
		}
	}
	require.ElementsMatch(t, want, got)
}
