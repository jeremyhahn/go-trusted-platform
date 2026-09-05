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

package attestation

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ReportsRouter serves the reporting service's cached verdicts and the
// operator "attest now" trigger, and describes the node's caller policy.
//
//	GET  /api/v1/attestation/reports                     - every cached report, with age
//	GET  /api/v1/attestation/reports/{device_id}         - one device's report, with age
//	POST /api/v1/attestation/reports/{device_id}/refresh - enqueue collection (202)
//
// None of these reaches a device: the router holds a reporting.Viewer and a
// reporting.Refresher, and neither type can (pkg/attestation/reporting).
type ReportsRouter struct {
	logger     *logging.Logger
	reporting  *Reporting
	respWriter response.HttpWriter
}

// NewReportsRouter builds the router. A nil Reporting registers routes that
// answer 503, so an operator can tell "not configured here" from a typo.
func NewReportsRouter(logger *logging.Logger, rep *Reporting, respWriter response.HttpWriter) *ReportsRouter {
	return &ReportsRouter{logger: logger, reporting: rep, respWriter: respWriter}
}

// RegisterRoutes mounts the routes. Mount on the admin gate: a report is a
// security verdict about a machine and the trigger spends TPM time.
func (r *ReportsRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/reports", r.listReports).Methods(http.MethodGet)
	sr.HandleFunc("/reports/{device_id}", r.getReport).Methods(http.MethodGet)
	sr.HandleFunc("/reports/{device_id}/refresh", r.refreshReport).Methods(http.MethodPost)
}

// ReportsResponse is the list payload.
type ReportsResponse struct {
	Reports []reporting.View `json:"reports"`
	Count   int              `json:"count"`
}

// RefreshResponse is the trigger's payload. Enqueued is always true on 202:
// the collector applies its own TTL and coalescing, and the caller learns
// the outcome by reading the report later. There is no synchronous quote.
type RefreshResponse struct {
	DeviceID string `json:"device_id"`
	Enqueued bool   `json:"enqueued"`
	Note     string `json:"note"`
}

func (r *ReportsRouter) listReports(w http.ResponseWriter, req *http.Request) {
	if r.reporting == nil || r.reporting.Reports == nil {
		r.respWriter.Write(w, req, http.StatusServiceUnavailable, response.WebServiceResponse{
			Code: http.StatusServiceUnavailable, Error: ErrReportingNotConfigured{}.Error()})
		return
	}
	views := r.reporting.Reports.Views()
	r.respWriter.Success200(w, req, ReportsResponse{Reports: views, Count: len(views)})
}

func (r *ReportsRouter) getReport(w http.ResponseWriter, req *http.Request) {
	if r.reporting == nil || r.reporting.Reports == nil {
		r.respWriter.Write(w, req, http.StatusServiceUnavailable, response.WebServiceResponse{
			Code: http.StatusServiceUnavailable, Error: ErrReportingNotConfigured{}.Error()})
		return
	}
	id := mux.Vars(req)["device_id"]
	view, ok := r.reporting.Reports.View(id)
	if !ok {
		// Never collected is a 404 with a reason, never a synthesised
		// failed verdict and never a fresh collection.
		r.respWriter.Error404(w, req, ErrNoReport{DeviceID: id})
		return
	}
	r.respWriter.Success200(w, req, view)
}

func (r *ReportsRouter) refreshReport(w http.ResponseWriter, req *http.Request) {
	if r.reporting == nil || r.reporting.Refresher == nil {
		r.respWriter.Write(w, req, http.StatusServiceUnavailable, response.WebServiceResponse{
			Code: http.StatusServiceUnavailable, Error: ErrReportingNotConfigured{}.Error()})
		return
	}
	id := mux.Vars(req)["device_id"]
	if err := r.reporting.Refresher.Refresh(id); err != nil {
		var stopped reporting.ErrCollectorStopped
		if errorAs(err, &stopped) {
			r.respWriter.Write(w, req, http.StatusServiceUnavailable, response.WebServiceResponse{
				Code: http.StatusServiceUnavailable, Error: err.Error()})
			return
		}
		r.respWriter.Error400(w, req, err)
		return
	}
	r.respWriter.Write(w, req, http.StatusAccepted, response.WebServiceResponse{
		Code: http.StatusAccepted, Success: true,
		Payload: RefreshResponse{
			DeviceID: id, Enqueued: true,
			Note: "collection enqueued with the collector; read the report for the verdict and its age",
		},
	})
}

// ErrReportingNotConfigured reports a node with no reporting service.
type ErrReportingNotConfigured struct{}

func (ErrReportingNotConfigured) Error() string {
	return "attestation: the reporting service is not configured on this node"
}

// ErrNoReport reports a device that has never been collected.
type ErrNoReport struct {
	DeviceID string
}

func (e ErrNoReport) Error() string {
	return "attestation: no report has been collected for device " + e.DeviceID
}

func errorAs(err error, target any) bool {
	return errors.As(err, target)
}
