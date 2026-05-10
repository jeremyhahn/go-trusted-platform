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

// Package tpm implements REST endpoints under /api/v1/tpm. Handlers
// delegate to the in-process platformv1.TPMServiceServer used by
// sdk/go/services/tpm.
package tpm

import (
	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const basePath = "/tpm"

// TPMRouter wires REST endpoints onto a TPMServiceServer.
type TPMRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewTPMRouter creates a new TPM REST router.
func NewTPMRouter(
	logger *logging.Logger,
	server platformv1.TPMServiceServer,
	respWriter response.HttpWriter,
) *TPMRouter {
	return &TPMRouter{handlers: NewHandlers(logger, server, respWriter)}
}

// RegisterRoutes attaches all TPM REST routes on the parent router.
//
//	GET    /api/v1/tpm/info
//	POST   /api/v1/tpm/provision
//	POST   /api/v1/tpm/clear
//	GET    /api/v1/tpm/ek
//	POST   /api/v1/tpm/ek
//	DELETE /api/v1/tpm/ek
//	GET    /api/v1/tpm/ek/certificate
//	POST   /api/v1/tpm/ek/certificate           (import)
//	GET    /api/v1/tpm/srk
//	POST   /api/v1/tpm/srk
//	DELETE /api/v1/tpm/srk
//	GET    /api/v1/tpm/ak
//	POST   /api/v1/tpm/ak
//	DELETE /api/v1/tpm/ak
//	POST   /api/v1/tpm/seal
//	POST   /api/v1/tpm/unseal
//	POST   /api/v1/tpm/quote
//	POST   /api/v1/tpm/quote/verify
//	GET    /api/v1/tpm/eventlog
//	GET    /api/v1/tpm/pcrs
//	POST   /api/v1/tpm/nvram                     (define)
//	GET    /api/v1/tpm/nvram/{index}             (read)
//	PUT    /api/v1/tpm/nvram/{index}             (write)
//	DELETE /api/v1/tpm/nvram/{index}             (undefine)
//	POST   /api/v1/tpm/random
func (r *TPMRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/info", r.handlers.Info).Methods("GET")
	sr.HandleFunc("/provision", r.handlers.Provision).Methods("POST")
	sr.HandleFunc("/clear", r.handlers.Clear).Methods("POST")
	sr.HandleFunc("/ek", r.handlers.GetEK).Methods("GET")
	sr.HandleFunc("/ek", r.handlers.CreateEK).Methods("POST")
	sr.HandleFunc("/ek", r.handlers.DeleteEK).Methods("DELETE")
	sr.HandleFunc("/ek/certificate", r.handlers.GetEKCertificate).Methods("GET")
	sr.HandleFunc("/ek/certificate", r.handlers.ImportEKCertificate).Methods("POST")
	sr.HandleFunc("/srk", r.handlers.GetSRK).Methods("GET")
	sr.HandleFunc("/srk", r.handlers.CreateSRK).Methods("POST")
	sr.HandleFunc("/srk", r.handlers.DeleteSRK).Methods("DELETE")
	sr.HandleFunc("/ak", r.handlers.GetAK).Methods("GET")
	sr.HandleFunc("/ak", r.handlers.CreateAK).Methods("POST")
	sr.HandleFunc("/ak", r.handlers.DeleteAK).Methods("DELETE")
	sr.HandleFunc("/seal", r.handlers.Seal).Methods("POST")
	sr.HandleFunc("/unseal", r.handlers.Unseal).Methods("POST")
	sr.HandleFunc("/quote", r.handlers.Quote).Methods("POST")
	sr.HandleFunc("/quote/verify", r.handlers.VerifyQuote).Methods("POST")
	sr.HandleFunc("/eventlog", r.handlers.GetEventLog).Methods("GET")
	sr.HandleFunc("/pcrs", r.handlers.GetPCRs).Methods("GET")
	// SDK alias: the JS SDK posts to /pcrs with a request body
	// containing PCR indices + bank selection. Both forms dispatch to
	// the same handler so REST and SDK callers agree.
	sr.HandleFunc("/pcrs", r.handlers.GetPCRs).Methods("POST")
	sr.HandleFunc("/nvram", r.handlers.DefineNVRAM).Methods("POST")
	sr.HandleFunc("/nvram/{index}", r.handlers.ReadNVRAM).Methods("GET")
	sr.HandleFunc("/nvram/{index}", r.handlers.WriteNVRAM).Methods("PUT")
	sr.HandleFunc("/nvram/{index}", r.handlers.UndefineNVRAM).Methods("DELETE")
	sr.HandleFunc("/random", r.handlers.GetRandom).Methods("POST")
}
