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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// init registers the LDevID (IEEE 802.1AR) create RPC on the REST transport.
// The pb CreateLDevIDRequest / CreateLDevIDResponse JSON encodings are
// wire-symmetric with the daemon REST handler at POST /api/v1/idevid/ldevid.
func init() {
	grpcMethodToRESTMap[platformv1.IDevIDService_CreateLDevID_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/idevid/ldevid", http.MethodPost}
}
