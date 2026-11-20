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

package daemon

import (
	"net/http"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// DaemonRouteTableWithKMS exists for the daemon_test package: it returns the
// router of the daemon's full REST route table (daemonRouteTableWithKMS) with
// kms behind the webservice KMS router.
func DaemonRouteTableWithKMS(t *testing.T, kms kmsclient.Client) http.Handler {
	s, _ := daemonRouteTableWithKMS(t, restapi.NewScopeGuard(nil, nil, nil), kms)
	return s.Router()
}
