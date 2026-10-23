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

package operations

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/operations"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"MigrateDataRequest", reflect.TypeFor[MigrateDataRequest](), reflect.TypeFor[upstream.MigrateDataRequest]()},
		{"MigrateDataResponse", reflect.TypeFor[MigrateDataResponse](), reflect.TypeFor[upstream.MigrateDataResponse]()},
		{"GetMigrationProgressRequest", reflect.TypeFor[GetMigrationProgressRequest](), reflect.TypeFor[upstream.GetMigrationProgressRequest]()},
		{"GetMigrationProgressResponse", reflect.TypeFor[GetMigrationProgressResponse](), reflect.TypeFor[upstream.GetMigrationProgressResponse]()},
		{"ReplaceNodeRequest", reflect.TypeFor[ReplaceNodeRequest](), reflect.TypeFor[upstream.ReplaceNodeRequest]()},
		{"ReplaceNodeResponse", reflect.TypeFor[ReplaceNodeResponse](), reflect.TypeFor[upstream.ReplaceNodeResponse]()},
		{"UpgradeNodeRequest", reflect.TypeFor[UpgradeNodeRequest](), reflect.TypeFor[upstream.UpgradeNodeRequest]()},
		{"UpgradeNodeResponse", reflect.TypeFor[UpgradeNodeResponse](), reflect.TypeFor[upstream.UpgradeNodeResponse]()},
		{"GetUpgradeStatusRequest", reflect.TypeFor[GetUpgradeStatusRequest](), reflect.TypeFor[upstream.GetUpgradeStatusRequest]()},
		{"GetUpgradeStatusResponse", reflect.TypeFor[GetUpgradeStatusResponse](), reflect.TypeFor[upstream.GetUpgradeStatusResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}
