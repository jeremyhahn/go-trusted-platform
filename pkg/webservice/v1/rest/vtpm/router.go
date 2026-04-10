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

package vtpm

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const (
	basePath = "/api/v1/vtpm"
)

// VTPMRouter provides REST routing for vTPM operations.
type VTPMRouter struct {
	handlers *VTPMHandlers
	router.WebServiceRouter
}

// NewVTPMRouter creates a new VTPMRouter instance.
func NewVTPMRouter(
	logger *logging.Logger,
	service vtpm.VTPMService,
	respWriter response.HttpWriter,
) *VTPMRouter {
	return &VTPMRouter{
		handlers: NewVTPMHandlers(logger, service, respWriter),
	}
}

// RegisterRoutes registers all vTPM REST routes on the provided router.
func (r *VTPMRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for vTPM endpoints
	vtpmRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerBundleRoutes(vtpmRouter)
	r.registerTemplateRoutes(vtpmRouter)
}

// registerBundleRoutes registers bundle management endpoints.
// POST   /api/v1/vtpm/bundles                  - Create bundle
// GET    /api/v1/vtpm/bundles                  - List bundles
// GET    /api/v1/vtpm/bundles/{id}             - Get bundle
// DELETE /api/v1/vtpm/bundles/{id}             - Delete bundle
// GET    /api/v1/vtpm/bundles/{id}/export      - Export bundle as tar.gz
// POST   /api/v1/vtpm/bundles/import           - Import bundle from tar.gz
// POST   /api/v1/vtpm/bundles/{id}/validate    - Validate bundle integrity
// GET    /api/v1/vtpm/bundles/{id}/path        - Get bundle filesystem path
// GET    /api/v1/vtpm/bundles/{id}/tpm-socket  - Get TPM socket path
// GET    /api/v1/vtpm/bundles/{id}/nvram       - Get NVRAM path
func (r *VTPMRouter) registerBundleRoutes(router *mux.Router) {
	// Bundle import route (must be before {id} routes to avoid conflicts)
	router.HandleFunc("/bundles/import", r.handlers.ImportBundle).Methods("POST")

	// Bundle collection routes
	router.HandleFunc("/bundles", r.handlers.CreateBundle).Methods("POST")
	router.HandleFunc("/bundles", r.handlers.ListBundles).Methods("GET")

	// Bundle instance routes
	router.HandleFunc("/bundles/{id}", r.handlers.GetBundle).Methods("GET")
	router.HandleFunc("/bundles/{id}", r.handlers.DeleteBundle).Methods("DELETE")

	// Bundle operation routes
	router.HandleFunc("/bundles/{id}/export", r.handlers.ExportBundle).Methods("GET")
	router.HandleFunc("/bundles/{id}/validate", r.handlers.ValidateBundle).Methods("POST")

	// Bundle path getter routes
	router.HandleFunc("/bundles/{id}/path", r.handlers.GetBundlePath).Methods("GET")
	router.HandleFunc("/bundles/{id}/tpm-socket", r.handlers.GetTPMSocketPath).Methods("GET")
	router.HandleFunc("/bundles/{id}/nvram", r.handlers.GetNVRAMPath).Methods("GET")
}

// registerTemplateRoutes registers template management endpoints.
// POST   /api/v1/vtpm/templates                - Create template
// GET    /api/v1/vtpm/templates                - List templates
// GET    /api/v1/vtpm/templates/{id}           - Get template
// DELETE /api/v1/vtpm/templates/{id}           - Delete template
// POST   /api/v1/vtpm/templates/{id}/clone     - Clone template to create bundle
func (r *VTPMRouter) registerTemplateRoutes(router *mux.Router) {
	// Template collection routes
	router.HandleFunc("/templates", r.handlers.CreateTemplate).Methods("POST")
	router.HandleFunc("/templates", r.handlers.ListTemplates).Methods("GET")

	// Template instance routes
	router.HandleFunc("/templates/{id}", r.handlers.GetTemplate).Methods("GET")
	router.HandleFunc("/templates/{id}", r.handlers.DeleteTemplate).Methods("DELETE")

	// Template clone route
	router.HandleFunc("/templates/{id}/clone", r.handlers.CloneTemplate).Methods("POST")
}
