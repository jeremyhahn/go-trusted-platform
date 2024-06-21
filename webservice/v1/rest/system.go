package rest

import (
	"net/http"
	"runtime"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/model"
	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/response"
)

type SystemRestServicer interface {
	Endpoints(w http.ResponseWriter, r *http.Request)
	Status(w http.ResponseWriter, r *http.Request)
	RSAPublicKey(w http.ResponseWriter, r *http.Request)
	Config(w http.ResponseWriter, r *http.Request)
	EventsPage(w http.ResponseWriter, r *http.Request)
}

type SystemRestService struct {
	app          *app.App
	httpWriter   response.HttpWriter
	endpointList *[]string
	SystemRestServicer
}

func NewSystemRestService(
	app *app.App,
	httpWriter response.HttpWriter,
	endpointList *[]string) SystemRestServicer {

	return &SystemRestService{
		app:          app,
		httpWriter:   httpWriter,
		endpointList: endpointList}
}

// Writes a list of webservice REST and WebSocket endpoints
func (restService *SystemRestService) Endpoints(w http.ResponseWriter, r *http.Request) {
	//restService.server.WalkRoutes() // TODO remove
	restService.httpWriter.Write(w, r, http.StatusOK, restService.endpointList)
}

// Writes the web servers RSA public key
func (restService *SystemRestService) RSAPublicKey(w http.ResponseWriter, r *http.Request) {
	cert, err := restService.app.CA.PEM(restService.app.Domain)
	if err == ca.ErrCertNotFound {
		restService.httpWriter.Error404(w, r, err)
		return
	}
	restService.httpWriter.Write(w, r, http.StatusOK, string(cert))
}

// Writes the application configuration
func (restService *SystemRestService) Config(w http.ResponseWriter, r *http.Request) {
	restService.httpWriter.Success200(w, r, restService.app)
}

// Writes the current system status and metrics
func (restService *SystemRestService) Status(w http.ResponseWriter, r *http.Request) {
	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)
	systemStatus := &model.SystemStruct{
		Version: app.GetVersion(),
		Runtime: &model.SystemRuntime{
			Version:     runtime.Version(),
			Cpus:        runtime.NumCPU(),
			Cgo:         runtime.NumCgoCall(),
			Goroutines:  runtime.NumGoroutine(),
			HeapSize:    memstats.HeapAlloc, // essentially what the profiler is giving you (active heap memory)
			Alloc:       memstats.Alloc,     // similar to HeapAlloc, but for all go managed memory
			Sys:         memstats.Sys,       // the total amount of memory (address space) requested from the OS
			Mallocs:     memstats.Mallocs,
			Frees:       memstats.Frees,
			NumGC:       memstats.NumGC,
			NumForcedGC: memstats.NumForcedGC}}

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

	restService.app.Logger.Debugf("EventsPage: page %s requested", page)

	restService.httpWriter.Success200(w, r, p)
}
