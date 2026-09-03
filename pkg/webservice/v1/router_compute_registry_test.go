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

package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeComputeRegistry satisfies RestHandlerRegistry for the compute and
// registry accessors only; the embedded nil interface panics on any
// other accessor, which would indicate the routes under test reached
// beyond their declared dependencies.
type fakeComputeRegistry struct {
	RestHandlerRegistry
	compute  platformv1.ComputeServiceServer
	registry grpcapi.RegistryService
}

func (f *fakeComputeRegistry) ComputeServiceServer() platformv1.ComputeServiceServer {
	return f.compute
}

func (f *fakeComputeRegistry) RegistryService() grpcapi.RegistryService {
	return f.registry
}

// fakeRegistryService answers List so GET /compute/images can execute
// end-to-end; every other method falls through to the embedded nil
// interface and panics if invoked.
type fakeRegistryService struct {
	grpcapi.RegistryService
}

func (f *fakeRegistryService) List(ctx context.Context, req *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	return &grpcapi.RegistryListResponse{}, nil
}

// newComputeTestRouter builds a Router wired with the fake handler
// registry and registers the compute + images routes in the production
// order (images first, then compute).
func newComputeTestRouter(t *testing.T, compute platformv1.ComputeServiceServer, registry grpcapi.RegistryService) *mux.Router {
	t.Helper()
	logger := testLogger()
	writer := response.NewResponseWriter(logger, nil)
	mr := mux.NewRouter()
	v1Router := &Router{
		logger:         logger,
		responseWriter: writer,
		router:         mr,
		restHandlerRegistry: &fakeComputeRegistry{
			compute:  compute,
			registry: registry,
		},
		serviceRegistry: NewServiceRegistry(logger, writer),
	}
	v1Router.computeImagesRoutes()
	v1Router.computeRoutes()
	return mr
}

func TestComputeRoutes_UnconfiguredAnswers503NotFound404(t *testing.T) {
	mr := newComputeTestRouter(t, nil, &fakeRegistryService{})

	for _, path := range []string{"/compute/vms", "/compute/containers", "/compute/vms/abc/snapshots"} {
		rec := httptest.NewRecorder()
		mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503", path, rec.Code)
		}
		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decode 503 body: %v", path, err)
		}
		if got, _ := body["service"].(string); got != "compute" {
			t.Fatalf("%s: service in body = %q, want %q", path, got, "compute")
		}
		// The WebUI branches on this discriminator, never on the prose.
		if got, _ := body["reason"].(string); got != ReasonServiceNotConfigured {
			t.Fatalf("%s: reason in body = %q, want %q", path, got, ReasonServiceNotConfigured)
		}
	}
}

func TestComputeRoutes_StubDoesNotShadowComputeImages(t *testing.T) {
	mr := newComputeTestRouter(t, nil, &fakeRegistryService{})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/compute/images", nil))
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("/compute/images answered 503 — the compute stub shadowed the registry surface: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("/compute/images: status = %d, want 200", rec.Code)
	}
}

func TestComputeRoutes_UnsupportedMethodOnImagesNotMisattributed(t *testing.T) {
	// mux keeps scanning after a method mismatch, so without the
	// /compute/images carve-out an unsupported method on the live
	// registry surface would fall through to the dark-compute stub and
	// be misattributed as "compute not configured".
	mr := newComputeTestRouter(t, nil, &fakeRegistryService{})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/compute/images", nil))
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("PATCH /compute/images fell through to the compute 503 stub: %s", rec.Body.String())
	}
	// 404 or 405 are both the registry surface's own answer; the point
	// is the request is never claimed by the dark compute service.
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("PATCH /compute/images: status = %d, want 404/405", rec.Code)
	}
}

func TestComputeRoutes_ConfiguredRegistersRealRoutes(t *testing.T) {
	// UnimplementedComputeServiceServer is a valid non-nil server; the
	// routes must register and dispatch to it rather than the 503 stub.
	mr := newComputeTestRouter(t, &platformv1.UnimplementedComputeServiceServer{}, &fakeRegistryService{})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/compute/vms", nil))
	if rec.Code == http.StatusServiceUnavailable || rec.Code == http.StatusNotFound {
		t.Fatalf("/compute/vms with configured compute: status = %d, want a real handler response", rec.Code)
	}
}
