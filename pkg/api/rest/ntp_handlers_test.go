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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newNTPRouter mounts the handlers on a fresh router.
func newNTPRouter(server platformv1.NTPServiceServer) *mux.Router {
	router := mux.NewRouter()
	NewNTPHandlers(server, operatorGuard(), nil).RegisterRoutes(router)
	return router
}

// scriptedNTPServer implements the generated server interface.
type scriptedNTPServer struct {
	platformv1.UnimplementedNTPServiceServer

	status    *platformv1.NTPStatus
	sources   []*platformv1.NTPSource
	statusErr error
	stepErr   error
	stepCalls int
}

// GetStatus returns the scripted status.
func (s *scriptedNTPServer) GetStatus(_ context.Context, _ *platformv1.GetNTPStatusRequest) (*platformv1.GetNTPStatusResponse, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return &platformv1.GetNTPStatusResponse{Status: s.status}, nil
}

// ListSources returns the scripted sources.
func (s *scriptedNTPServer) ListSources(_ context.Context, _ *platformv1.ListNTPSourcesRequest) (*platformv1.ListNTPSourcesResponse, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return &platformv1.ListNTPSourcesResponse{Sources: s.sources}, nil
}

// Step records the call and returns the scripted result.
func (s *scriptedNTPServer) Step(_ context.Context, _ *platformv1.StepNTPClockRequest) (*platformv1.StepNTPClockResponse, error) {
	s.stepCalls++
	if s.stepErr != nil {
		return nil, s.stepErr
	}
	return &platformv1.StepNTPClockResponse{Status: s.status}, nil
}

func TestNTPRESTHandlersServeStatusSourcesAndStep(t *testing.T) {
	server := &scriptedNTPServer{
		status: &platformv1.NTPStatus{
			Synced:           true,
			Stratum:          3,
			LeapStatus:       "Normal",
			Mode:             "both",
			ReferenceName:    "10.4.200.1",
			SourcesReachable: 1,
			SourcesTotal:     2,
		},
		sources: []*platformv1.NTPSource{
			{Address: "10.4.200.1", State: "selected", Reachable: true, Reach: 377},
		},
	}
	router := newNTPRouter(server)

	t.Run("status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, operatorRequest(http.MethodGet, "/api/v1/ntp/status", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
		}
		var body struct {
			Status struct {
				Synced  bool   `json:"synced"`
				Stratum uint32 `json:"stratum"`
				Mode    string `json:"mode"`
			} `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v", rec.Body, err)
		}
		if !body.Status.Synced || body.Status.Stratum != 3 || body.Status.Mode != "both" {
			t.Fatalf("body = %+v, want synced stratum 3 mode both", body.Status)
		}
	})

	t.Run("sources", func(t *testing.T) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, operatorRequest(http.MethodGet, "/api/v1/ntp/sources", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
		}
		var body struct {
			Sources []struct {
				Address   string `json:"address"`
				Reachable bool   `json:"reachable"`
			} `json:"sources"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v", rec.Body, err)
		}
		if len(body.Sources) != 1 || body.Sources[0].Address != "10.4.200.1" {
			t.Fatalf("sources = %+v", body.Sources)
		}
	})

	t.Run("step", func(t *testing.T) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, operatorRequest(http.MethodPost, "/api/v1/ntp/step", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
		}
		if server.stepCalls != 1 {
			t.Fatalf("step calls = %d, want 1", server.stepCalls)
		}
	})
}

func TestNTPRESTHandlersMapServiceFailuresToHTTPStatus(t *testing.T) {
	cases := map[string]struct {
		err  error
		path string
		verb string
		want int
	}{
		"no reachable source is 409": {
			err:  status.Error(codes.Aborted, "ntp: no reachable time source (2 configured)"),
			path: "/api/v1/ntp/step",
			verb: http.MethodPost,
			want: http.StatusConflict,
		},
		"control socket down is 503": {
			err:  status.Error(codes.Unavailable, "ntp: chrony control command failed"),
			path: "/api/v1/ntp/status",
			verb: http.MethodGet,
			want: http.StatusServiceUnavailable,
		},
		"malformed output is 500": {
			err:  status.Error(codes.Internal, "ntp: malformed tracking output"),
			path: "/api/v1/ntp/status",
			verb: http.MethodGet,
			want: http.StatusInternalServerError,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router := newNTPRouter(&scriptedNTPServer{statusErr: tc.err, stepErr: tc.err})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, operatorRequest(tc.verb, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("code = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			var body ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if body.Code != tc.want || body.Error == "" {
				t.Fatalf("error envelope = %+v", body)
			}
		})
	}
}

func TestNTPRESTHandlersReport503WithoutAService(t *testing.T) {
	router := newNTPRouter(nil)

	for _, probe := range []struct {
		verb string
		path string
	}{
		{http.MethodGet, "/api/v1/ntp/status"},
		{http.MethodGet, "/api/v1/ntp/sources"},
		{http.MethodPost, "/api/v1/ntp/step"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, operatorRequest(probe.verb, probe.path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s code = %d, want 503", probe.verb, probe.path, rec.Code)
		}
	}

	if (ErrNTPUnavailable{}).Error() == "" {
		t.Fatal("ErrNTPUnavailable must carry a message")
	}
}
