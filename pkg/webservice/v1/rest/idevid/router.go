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

// Package idevid implements REST endpoints under /api/v1/idevid.
package idevid

import (
	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const basePath = "/idevid"

// IDevIDRouter wires REST endpoints onto an IDevIDServiceServer.
type IDevIDRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewIDevIDRouter creates a new router.
func NewIDevIDRouter(
	logger *logging.Logger,
	server platformv1.IDevIDServiceServer,
	respWriter response.HttpWriter,
) *IDevIDRouter {
	return &IDevIDRouter{handlers: NewHandlers(logger, server, respWriter)}
}

// RegisterRoutes attaches IDevID REST routes on the parent router.
//
//	GET    /api/v1/idevid                          - GetIDevIDInfo
//	POST   /api/v1/idevid/generate                 - GenerateIDevID
//	GET    /api/v1/idevid/exists                   - HasIDevID
//	DELETE /api/v1/idevid                          - DeleteIDevID
//	POST   /api/v1/idevid/csr                      - CreateIDevIDCSR
//	GET    /api/v1/idevid/certificate              - GetIDevIDCertificate
//	POST   /api/v1/idevid/certificate              - InstallIDevIDCertificate
//	DELETE /api/v1/idevid/certificate              - DeleteIDevIDCertificate
//	GET    /api/v1/idevid/iak                      - GetIAKInfo
//	POST   /api/v1/idevid/iak/generate             - GenerateIAK
//	GET    /api/v1/idevid/iak/exists               - HasIAK
//	DELETE /api/v1/idevid/iak                      - DeleteIAK
//	POST   /api/v1/idevid/iak/csr                  - CreateIAKCSR
//	GET    /api/v1/idevid/iak/certificate          - GetIAKCertificate
//	POST   /api/v1/idevid/iak/certificate          - InstallIAKCertificate
//	DELETE /api/v1/idevid/iak/certificate          - DeleteIAKCertificate
//	GET    /api/v1/idevid/attributes               - GetDeviceAttributes
//	POST   /api/v1/idevid/flush                    - FlushTransientContexts
//	POST   /api/v1/idevid/activate-credential      - ActivateCredential
func (r *IDevIDRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("", r.handlers.GetIDevIDInfo).Methods("GET")
	// /info alias matches the sdk/javascript client which calls
	// `${basePath}/info` rather than the bare collection URL. Both forms
	// dispatch to the same handler so REST and SDK callers agree.
	sr.HandleFunc("/info", r.handlers.GetIDevIDInfo).Methods("GET")
	sr.HandleFunc("/generate", r.handlers.GenerateIDevID).Methods("POST")
	sr.HandleFunc("/exists", r.handlers.HasIDevID).Methods("GET")
	// /expiring is consumed by the IDevID dashboard page to render a
	// banner when issued certificates are within the renewal window.
	// Backed by GetExpiringCertificates on the same handler.
	sr.HandleFunc("/expiring", r.handlers.GetExpiringIDevIDs).Methods("GET")
	sr.HandleFunc("", r.handlers.DeleteIDevID).Methods("DELETE")
	sr.HandleFunc("/csr", r.handlers.CreateIDevIDCSR).Methods("POST")
	sr.HandleFunc("/certificate", r.handlers.GetIDevIDCertificate).Methods("GET")
	sr.HandleFunc("/certificate", r.handlers.InstallIDevIDCertificate).Methods("POST")
	sr.HandleFunc("/certificate", r.handlers.DeleteIDevIDCertificate).Methods("DELETE")
	sr.HandleFunc("/iak", r.handlers.GetIAKInfo).Methods("GET")
	sr.HandleFunc("/iak/generate", r.handlers.GenerateIAK).Methods("POST")
	sr.HandleFunc("/iak/exists", r.handlers.HasIAK).Methods("GET")
	sr.HandleFunc("/iak", r.handlers.DeleteIAK).Methods("DELETE")
	sr.HandleFunc("/iak/csr", r.handlers.CreateIAKCSR).Methods("POST")
	sr.HandleFunc("/iak/certificate", r.handlers.GetIAKCertificate).Methods("GET")
	sr.HandleFunc("/iak/certificate", r.handlers.InstallIAKCertificate).Methods("POST")
	sr.HandleFunc("/iak/certificate", r.handlers.DeleteIAKCertificate).Methods("DELETE")
	sr.HandleFunc("/attributes", r.handlers.GetDeviceAttributes).Methods("GET")
	sr.HandleFunc("/flush", r.handlers.FlushTransientContexts).Methods("POST")
	sr.HandleFunc("/activate-credential", r.handlers.ActivateCredential).Methods("POST")
}
