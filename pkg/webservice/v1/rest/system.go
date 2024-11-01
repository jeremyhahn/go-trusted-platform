package rest

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

type SystemRestServicer interface {
	Config(w http.ResponseWriter, r *http.Request)
	Certificate(w http.ResponseWriter, r *http.Request)
	// Endpoints(w http.ResponseWriter, r *http.Request)
	EventsPage(w http.ResponseWriter, r *http.Request)
	PublicKey(w http.ResponseWriter, r *http.Request)
	Status(w http.ResponseWriter, r *http.Request)
}

type SystemRestService struct {
	ca                  ca.CertificateAuthority
	endpointList        *[]string
	httpWriter          response.HttpWriter
	logger              *logging.Logger
	serverKeyAttributes *keystore.KeyAttributes
	SystemRestServicer
}

func NewSystemRestService(
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes,
	httpWriter response.HttpWriter,
	logger *logging.Logger) SystemRestServicer {

	return &SystemRestService{
		ca:                  ca,
		httpWriter:          httpWriter,
		logger:              logger,
		serverKeyAttributes: serverKeyAttributes}
}

// Writes the web server public key in PEM form
func (restService *SystemRestService) PublicKey(w http.ResponseWriter, r *http.Request) {
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
func (restService *SystemRestService) Certificate(w http.ResponseWriter, r *http.Request) {
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

// Writes the application configuration
func (restService *SystemRestService) Config(w http.ResponseWriter, r *http.Request) {
	// restService.httpWriter.Success200(w, r, restService.app)
}

// Writes the current system status and metrics
func (restService *SystemRestService) Status(w http.ResponseWriter, r *http.Request) {
	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)
	systemStatus, err := system.SystemInfo()
	if err != nil {
		restService.httpWriter.Error500(w, r, err)
		return
	}
	// systemStatus := &model.SystemStruct{
	// 	Version: app.GetVersion(),
	// 	Runtime: &model.SystemRuntime{
	// 		Version:     runtime.Version(),
	// 		Cpus:        runtime.NumCPU(),
	// 		Cgo:         runtime.NumCgoCall(),
	// 		Goroutines:  runtime.NumGoroutine(),
	// 		HeapSize:    memstats.HeapAlloc, // essentially what the profiler is giving you (active heap memory)
	// 		Alloc:       memstats.Alloc,     // similar to HeapAlloc, but for all go managed memory
	// 		Sys:         memstats.Sys,       // the total amount of memory (address space) requested from the OS
	// 		Mallocs:     memstats.Mallocs,
	// 		Frees:       memstats.Frees,
	// 		NumGC:       memstats.NumGC,
	// 		NumForcedGC: memstats.NumForcedGC}}

	restService.httpWriter.Success200(w, r, systemStatus)
}

// Writes a page of system event log entries
func (restService *SystemRestService) EventsPage(w http.ResponseWriter, r *http.Request) {

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
