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

package v1

// PrivilegedDaemonMethodRoutes exposes the per-method gate table to the
// external route tests, which classify every replayed daemon endpoint
// against it.
var PrivilegedDaemonMethodRoutes = privilegedDaemonMethodRoutes

// CallerCheckedDaemonMethodRoutes exposes the login-checked route table to
// the external route tests.
var CallerCheckedDaemonMethodRoutes = callerCheckedDaemonMethodRoutes

// The gates ClassifyDaemonRoute names; an unclassified method is "".
const (
	DaemonRouteOperator    = "operator"
	DaemonRouteSession     = "session"
	DaemonRouteCertificate = "certificate"
)

var daemonRouteKindNames = map[daemonRouteKind]string{
	daemonRouteOperator:    DaemonRouteOperator,
	daemonRouteSession:     DaemonRouteSession,
	daemonRouteCertificate: DaemonRouteCertificate,
}

// ClassifyDaemonRoute exposes the production classification of a replayed
// daemon route method to the external route tests: the gate it takes and,
// for an operator route, its scope.
func ClassifyDaemonRoute(method, template string) (gate, scope string) {
	access := classifyDaemonRoute(method, template)
	return daemonRouteKindNames[access.kind], access.scope
}
