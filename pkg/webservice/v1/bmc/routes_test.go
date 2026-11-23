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

package bmc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// recordingGuard records the scope a request was checked against, then
// lets it through.
type recordingGuard struct {
	scopes []string
}

func (g *recordingGuard) Require(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.scopes = append(g.scopes, scope)
		next(w, r)
	}
}

// powerStub counts PowerAction calls and keeps the body it saw; every other
// method panics through the nil embedded interface.
type powerStub struct {
	RestHandler
	calls int
	body  string
}

func (s *powerStub) PowerAction(w http.ResponseWriter, r *http.Request) {
	s.calls++
	b, _ := io.ReadAll(r.Body)
	s.body = string(b)
	w.WriteHeader(http.StatusOK)
}

// TestRegisterRoutes_PowerScopes pins that PowerOn needs bmc:write while
// off, reset and cycle need bmc:power, and that the handler still reads the
// whole body.
func TestRegisterRoutes_PowerScopes(t *testing.T) {
	cases := map[string]string{
		"on":    ScopeWrite,
		"off":   ScopePower,
		"reset": ScopePower,
		"cycle": ScopePower,
	}
	for action, want := range cases {
		t.Run(action, func(t *testing.T) {
			guard := &recordingGuard{}
			stub := &powerStub{}
			router := mux.NewRouter()
			RegisterRoutes(router, stub, guard)

			body := `{"action":"` + action + `"}`
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/bmc/7/power", strings.NewReader(body)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if len(guard.scopes) != 1 || guard.scopes[0] != want {
				t.Fatalf("scopes = %v, want [%s]", guard.scopes, want)
			}
			if stub.calls != 1 {
				t.Fatalf("PowerAction calls = %d, want 1", stub.calls)
			}
			if stub.body != body {
				t.Fatalf("handler body = %q, want %q", stub.body, body)
			}
		})
	}
}
