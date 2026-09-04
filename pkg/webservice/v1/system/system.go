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
	"strconv"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
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
	// startTime is when this handler was constructed, which is as close to
	// "when the webservice began serving" as this package can observe.
	startTime time.Time
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
		startTime:           time.Now(),
	}
}

// Writes the web server public key in PEM form
func (restService *Handler) PublicKey(w http.ResponseWriter, r *http.Request) {
	cert, err := restService.ca.Certificate(r.Context(), restService.serverKeyAttributes)
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
	cert, err := restService.ca.PEM(r.Context(), keyAttrs)
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
}

// LivenessStatus is the body GET /api/v1/status returns.
//
// It is deliberately small. This route is UNAUTHENTICATED — and must stay so,
// because its callers reach it before any credential exists: the bootstrap
// orchestrator's health checker probes it to decide a node has finished
// booting from a machine that may not yet trust the node's CA
// (pkg/bootstrap/orchestrator.go), `platformctl bootstrap status` probes it
// across every node, and the ISO test client uses it to confirm platformd is
// up. Gating it would break node bootstrap, which is why #236 is a shape
// question and not a gate question.
//
// So the shape is exactly what answers "is this node up", and nothing else.
type LivenessStatus struct {
	// Status is the liveness verdict. It is "ready" whenever the webservice
	// is serving; per-component health lives at /api/v1/platform/health,
	// which requires an authenticated admin (#165).
	Status string `yaml:"status" json:"status"`

	// Uptime is how long this process has been serving. It is the one
	// diagnostic worth volunteering: a node that answers with seconds of
	// uptime is a node that just restarted, which is the single most useful
	// thing a bootstrap probe can learn beyond "it answered".
	Uptime string `yaml:"uptime" json:"uptime,omitempty"`

	// Timestamp is the server's clock at the time of the answer. A probe that
	// finds a wildly skewed clock has learned something real: on this
	// platform a wrong clock fails attestation, ACME issuance and token
	// validation without naming itself (docs/ntp/user.md).
	Timestamp string `yaml:"timestamp" json:"timestamp"`
}

// Status writes the unauthenticated liveness answer.
//
// WHAT THIS DELIBERATELY NO LONGER RETURNS, and why (#236): it used to answer
// with the full entities.System — SMBIOS product, board and chassis INCLUDING
// SERIAL NUMBERS, the kernel version, the hostname, every active network
// interface with its IPv4 and IPv6 addresses, CPU model, TPM status and CA
// configuration — to any caller that could open a TCP connection.
//
// None of that answers "is this node up", and no caller read it. All three
// in-repo consumers grade on the status code alone (the fourth, this repo's
// own `bootstrap status` probe, additionally checks the body opens as JSON);
// the console never calls this route. So the disclosure was volunteered to
// everyone and consumed by nobody — kernel version is exploit-selection
// input, serial numbers are asset identity and IDevID-adjacent on this
// platform, and interface addresses are internal topology.
//
// The full inventory is not relocated here. It has no HTTP consumer to
// relocate it for, and inventing an authenticated route on the strength of a
// hypothetical one would be scope this issue does not have. If it is wanted,
// /api/v1/platform/** is already gated on admin and is where it belongs.
func (restService *Handler) Status(w http.ResponseWriter, r *http.Request) {
	restService.httpWriter.Success200(w, r, LivenessStatus{
		Status:    "ready",
		Uptime:    restService.uptime(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// uptime reports how long this handler has been serving, or the empty string
// when the start time was never recorded — an absent field beats a fabricated
// duration.
func (restService *Handler) uptime() string {
	if restService.startTime.IsZero() {
		return ""
	}
	return time.Since(restService.startTime).Truncate(time.Second).String()
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
