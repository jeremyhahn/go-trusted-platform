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

package system

import (
	"errors"
	"net/http"
	"runtime"
	"strconv"

	"github.com/gorilla/mux"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/system"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

type RestHandler interface {
	CABundleHandler(w http.ResponseWriter, r *http.Request)
	Config(w http.ResponseWriter, r *http.Request)
	Certificate(w http.ResponseWriter, r *http.Request)
	// Endpoints(w http.ResponseWriter, r *http.Request)
	EventsPage(w http.ResponseWriter, r *http.Request)
	PublicKey(w http.ResponseWriter, r *http.Request)
	Status(w http.ResponseWriter, r *http.Request)
}

type Handler struct {
	ca                  trustedca.CACertificateAuthority
	caConfig            *trustedca.CAConfig
	httpWriter          response.HttpWriter
	logger              *logging.Logger
	serverKeyAttributes *xkmssdk.KeyAttributes
	tpm                 xkmssdk.TrustedPlatformModule
	RestHandler
}

func NewHandler(
	certAuth trustedca.CACertificateAuthority,
	caConfig *trustedca.CAConfig,
	serverKeyAttributes *xkmssdk.KeyAttributes,
	httpWriter response.HttpWriter,
	logger *logging.Logger,
	tpm xkmssdk.TrustedPlatformModule) RestHandler {

	return &Handler{
		ca:                  certAuth,
		caConfig:            caConfig,
		httpWriter:          httpWriter,
		logger:              logger,
		serverKeyAttributes: serverKeyAttributes,
		tpm:                 tpm,
	}
}

// Writes the web server public key in PEM form
func (restService *Handler) PublicKey(w http.ResponseWriter, r *http.Request) {
	cert, err := restService.ca.Certificate(restService.serverKeyAttributes)
	if err != nil {
		if errors.Is(err, xkmssdk.ErrCertNotFound) || errors.Is(err, trustedca.ErrNotFound) {
			restService.httpWriter.Error404(w, r, err)
			return
		}
		restService.httpWriter.Error500(w, r, err)
		return
	}
	pubPEM, err := xkmssdk.EncodePubKeyPEM(cert.PublicKey)
	if err != nil {
		restService.httpWriter.Error500(w, r, err)
		return
	}
	restService.httpWriter.Write(w, r, http.StatusOK, string(pubPEM))
}

// Writes the web server x509 certificate in PEM form
func (restService *Handler) Certificate(w http.ResponseWriter, r *http.Request) {
	keyAttrs := restService.serverKeyAttributes
	cert, err := restService.ca.PEM(keyAttrs)
	if err != nil {
		if errors.Is(err, xkmssdk.ErrCertNotFound) || errors.Is(err, trustedca.ErrNotFound) {
			restService.httpWriter.Error404(w, r, err)
			return
		}
		restService.httpWriter.Error500(w, r, err)
		return
	}
	restService.httpWriter.Write(w, r, http.StatusOK, string(cert))
}

// Writes the CA certificate bundle in PEM form. Passes empty strings
// for storeType and algorithm so the bundler emits ALL active CA
// certificates (root + intermediate(s), every key algorithm). Filtering
// is available via explicit path parameters on the /acme/ca-bundle/...
// variants — this unfiltered endpoint is the default and intended
// surface for client trust-bundle fetches.
func (restService *Handler) CABundleHandler(w http.ResponseWriter, r *http.Request) {
	// Unfiltered: returns full CA chain (root + active intermediates),
	// all key algorithms. The /acme/ca-bundle/{storeType}/{keyAlgo}
	// variants handle filtered views.
	defaultBundle, err := restService.ca.CABundle()
	if err != nil {
		restService.httpWriter.Write(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(defaultBundle)
}

// Writes the application configuration
func (restService *Handler) Config(w http.ResponseWriter, r *http.Request) {
	// restService.httpWriter.Success200(w, r, restService.app)
}

// Writes the current system status and metrics
func (restService *Handler) Status(w http.ResponseWriter, r *http.Request) {
	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)
	systemStatus, err := system.SystemInfo()
	if err != nil {
		restService.httpWriter.Error500(w, r, err)
		return
	}

	// Add TPM status
	if restService.tpm != nil {
		systemStatus.TPM = system.TPMInfo(restService.tpm)
	}

	// Add CA status
	if restService.caConfig != nil {
		systemStatus.CA = system.CAInfoFromConfig(restService.caConfig)
	}

	// Add OS info
	systemStatus.OS = system.OSInfoDetails()

	// Add network info
	systemStatus.Network = system.NetworkInfoDetails()

	restService.httpWriter.Success200(w, r, systemStatus)
}

// Writes a page of system event log entries
func (restService *Handler) EventsPage(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)
	page := params["page"]

	p, err := strconv.Atoi(page)
	if err != nil {
		restService.httpWriter.Error400(w, r, err)
		return
	}

	restService.logger.Debugf("EventsPage: page %s requested", page)

	restService.httpWriter.Success200(w, r, p)
}
