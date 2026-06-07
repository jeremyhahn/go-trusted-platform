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

// Package registry implements the REST surface for /api/v1/compute/images.
//
// All handlers delegate to a grpcapi.RegistryService (the same
// concrete adapter wrapping pkg/registry.Registry that the gRPC and
// MCP transports speak to). REST is a thin transcoding layer — it
// never reaches into pkg/registry directly.
package registry

import (
	"github.com/gorilla/mux"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	// basePath is mounted under the parent /api/v1 subrouter so the
	// fully-qualified routes resolve to /api/v1/compute/images/...
	basePath = "/compute/images"
)

// Router wires REST endpoints onto a RegistryService.
type Router struct {
	handlers *Handlers
}

// NewRouter constructs a router. service may be nil — when nil, every
// route returns 503 with a structured "not configured" envelope per
// the Phase 0.3 loud-failure pattern, so callers can tell the
// surface apart from a real registry error.
func NewRouter(logger *logging.Logger, service grpcapi.RegistryService, respWriter response.HttpWriter) *Router {
	return &Router{handlers: NewHandlers(logger, service, respWriter)}
}

// RegisterRoutes attaches all registry REST routes under the parent
// /api/v1 subrouter.
//
//	GET    /api/v1/compute/images                       - ListImages
//	POST   /api/v1/compute/images                       - PushImage (JSON envelope)
//	GET    /api/v1/compute/images/status                - Registry status
//	GET    /api/v1/compute/images/{repository:.+}       - InspectImage / PullImage
//	DELETE /api/v1/compute/images/{repository:.+}       - DeleteImage
//
// The {repository:.+} catch-all is required because OCI references
// include slashes (e.g. registry.example/library/alpine:3.20). The
// matched path includes any trailing :tag — the handler splits it.
//
// On GET /{repository:.+} the response shape is controlled by the
// Accept header: application/json (default) returns the inspect
// envelope used by the WebUI; application/vnd.oci.image.layer.v1.tar
// or application/x-trusted-platform-image returns the JSON pull
// envelope (manifest + base64 layers) so platformctl can stream the
// image bytes back.
func (r *Router) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("", r.handlers.ListImages).Methods("GET")
	sr.HandleFunc("/", r.handlers.ListImages).Methods("GET")
	sr.HandleFunc("", r.handlers.PushImage).Methods("POST")
	sr.HandleFunc("/", r.handlers.PushImage).Methods("POST")
	sr.HandleFunc("/status", r.handlers.Status).Methods("GET")
	sr.HandleFunc("/{repository:.+}", r.handlers.GetImage).Methods("GET")
	sr.HandleFunc("/{repository:.+}", r.handlers.DeleteImage).Methods("DELETE")
}
