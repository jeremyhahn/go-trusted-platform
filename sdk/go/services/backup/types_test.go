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

package backup

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/backup"
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
		{"BackupInfo", reflect.TypeFor[BackupInfo](), reflect.TypeFor[upstream.BackupInfo]()},
		{"BackupRequest", reflect.TypeFor[BackupRequest](), reflect.TypeFor[upstream.BackupRequest]()},
		{"BackupResponse", reflect.TypeFor[BackupResponse](), reflect.TypeFor[upstream.BackupResponse]()},
		{"RestoreRequest", reflect.TypeFor[RestoreRequest](), reflect.TypeFor[upstream.RestoreRequest]()},
		{"RestoreResponse", reflect.TypeFor[RestoreResponse](), reflect.TypeFor[upstream.RestoreResponse]()},
		{"ListBackupsResponse", reflect.TypeFor[ListBackupsResponse](), reflect.TypeFor[upstream.ListBackupsResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}
