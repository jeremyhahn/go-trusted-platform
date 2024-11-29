package system

import (
	"net/http"
	"runtime"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/system"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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
	ca                  ca.CertificateAuthority
	endpointList        *[]string
	httpWriter          response.HttpWriter
	logger              *logging.Logger
	serverKeyAttributes *keystore.KeyAttributes
	RestHandler
}

func NewHandler(
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes,
	httpWriter response.HttpWriter,
	logger *logging.Logger) RestHandler {

	return &Handler{
		ca:                  ca,
		httpWriter:          httpWriter,
		logger:              logger,
		serverKeyAttributes: serverKeyAttributes}
}

// Writes the web server public key in PEM form
func (restService *Handler) PublicKey(w http.ResponseWriter, r *http.Request) {
	cert, err := restService.ca.Certificate(restService.serverKeyAttributes)
	if err != nil {
		if err == certstore.ErrCertNotFound {
			restService.httpWriter.Error404(w, r, err)
			return
		}
		restService.httpWriter.Error500(w, r, err)
		return
	}
	pubPEM, err := keystore.EncodePubKeyPEM(cert.PublicKey)
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
		if err == certstore.ErrCertNotFound {
			restService.httpWriter.Error404(w, r, err)
			return
		}
		restService.httpWriter.Error500(w, r, err)
		return
	}
	restService.httpWriter.Write(w, r, http.StatusOK, string(cert))
}

// Writes the CA certificate bundle in PEM form
func (restService *Handler) CABundleHandler(w http.ResponseWriter, r *http.Request) {
	defaultBundle, err := restService.ca.CABundle(nil, nil)
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
