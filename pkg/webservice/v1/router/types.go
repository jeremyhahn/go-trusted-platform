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

package router

import (
	"github.com/gorilla/mux"
)

type WebServiceRouter interface {
	RegisterRoutes(router *mux.Router)
}

// RootRouter is a WebServiceRouter that also mounts surfaces at the host
// root — outside the versioned API prefix — because a protocol fixes their
// path there. RegisterRootRoutes returns an error rather than mounting
// less than it was asked for: a root surface that cannot be gated must not
// be served.
type RootRouter interface {
	WebServiceRouter
	RegisterRootRoutes(root *mux.Router) error
	// RegisterEdgeRoutes mounts only what a public edge listener may carry
	// from the API (the ACME group under baseURI) and reports whether it
	// mounted anything.
	RegisterEdgeRoutes(root *mux.Router, baseURI string) bool
	// RegisterProvisioningRoutes mounts only the boot-time config fetch
	// (GET baseURI/devices/config) a provisioning listener carries, and
	// reports whether it mounted it (#177).
	RegisterProvisioningRoutes(root *mux.Router, baseURI string) bool
}
