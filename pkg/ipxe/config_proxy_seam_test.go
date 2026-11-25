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

package ipxe

import (
	"reflect"
	"testing"
)

// TestServerConfig_NoExportedPrivateDestinationOverride: the /proxy/
// private-destination restriction has no public configuration switch; the
// override is an internal test seam only (#1896).
func TestServerConfig_NoExportedPrivateDestinationOverride(t *testing.T) {
	if _, ok := reflect.TypeOf(ServerConfig{}).FieldByName("ProxyAllowPrivateDestinations"); ok {
		t.Fatal("ServerConfig exports ProxyAllowPrivateDestinations, a public override of the private-destination restriction")
	}
}
