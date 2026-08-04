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

package rest

import (
	"net/http"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestLDevIDRESTMapping verifies the LDevID create RPC maps to the daemon REST
// route POST /api/v1/idevid/ldevid.
func TestLDevIDRESTMapping(t *testing.T) {
	entry, ok := grpcMethodToRESTMap[platformv1.IDevIDService_CreateLDevID_FullMethodName]
	if !ok {
		t.Fatalf("CreateLDevID not mapped to a REST route")
	}
	if entry.path != "/api/v1/idevid/ldevid" {
		t.Fatalf("CreateLDevID path = %q, want /api/v1/idevid/ldevid", entry.path)
	}
	if entry.method != http.MethodPost {
		t.Fatalf("CreateLDevID method = %q, want POST", entry.method)
	}
}
