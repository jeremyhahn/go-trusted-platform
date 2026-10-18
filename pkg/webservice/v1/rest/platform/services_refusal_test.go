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

package platform_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// failingServices answers every lifecycle verb with err.
type failingServices struct{ err error }

func (f failingServices) ListServices(context.Context, *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error) {
	return nil, f.err
}

func (f failingServices) GetServiceStatus(context.Context, *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error) {
	return nil, f.err
}

func (f failingServices) StartService(context.Context, *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error) {
	return nil, f.err
}

func (f failingServices) StopService(context.Context, *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error) {
	return nil, f.err
}

func (f failingServices) RestartService(context.Context, *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error) {
	return nil, f.err
}

func serviceAction(t *testing.T, err error, verb string) *httptest.ResponseRecorder {
	t.Helper()
	logger := logging.DefaultLogger()
	handlers := platform.NewPlatformHandlers(logger, response.NewResponseWriter(logger, nil))
	handlers.SetServicesManager(failingServices{err: err})

	actions := map[string]http.HandlerFunc{
		"start":   handlers.StartService,
		"stop":    handlers.StopService,
		"restart": handlers.RestartService,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform/services/tpm/"+verb, nil)
	req = mux.SetURLVars(req, map[string]string{"service": "tpm"})
	rec := httptest.NewRecorder()
	actions[verb](rec, req)
	return rec
}

// The daemon's refusal is a FailedPrecondition, which the REST mapper sends as
// 400 with the refusal's own message, the same answer the daemon REST server
// gives.
func TestServiceAction_RefusalIsBadRequest(t *testing.T) {
	refusal := daemon.ErrServiceNotControllable{ServiceName: "tpm", Reason: "owned by the process"}
	for _, verb := range []string{"start", "stop", "restart"} {
		rec := serviceAction(t, refusal, verb)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want %d", verb, rec.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rec.Body.String(), "cannot be started or stopped at runtime") {
			t.Errorf("%s: body %q does not carry the refusal", verb, rec.Body.String())
		}
	}
}

// A failure the daemon did not classify stays a server error.
func TestServiceAction_UnclassifiedFailureIsServerError(t *testing.T) {
	failures := map[string]error{
		"plain":    errors.New("boom"),
		"internal": status.Error(codes.Internal, "boom"),
	}
	for name, err := range failures {
		for _, verb := range []string{"start", "stop", "restart"} {
			if rec := serviceAction(t, err, verb); rec.Code != http.StatusInternalServerError {
				t.Errorf("%s %s: status %d, want %d", name, verb, rec.Code, http.StatusInternalServerError)
			}
		}
	}
}
