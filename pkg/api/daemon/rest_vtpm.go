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
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// SetVTPMService sets the vTPM service for REST handlers.
// This allows vTPM bundle management operations via REST API.
func (s *RESTServer) SetVTPMService(svc vtpm.VTPMService) {
	s.vtpmService = svc
	if svc != nil {
		// Create vTPM REST handlers and register routes on the existing router.
		// The vtpm.VTPMService interface satisfies rest.VTPMServiceInterface.
		vtpmHandlers := rest.NewVTPMHandlers(svc, s.logger)
		vtpmHandlers.RegisterRoutes(s.router)
		s.logger.Info("vTPM REST routes registered")
	}
}
