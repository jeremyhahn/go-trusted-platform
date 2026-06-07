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

package platform

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
)

type fakeQuerier struct {
	result   jsonfile.QueryResult
	services []string
	err      error
}

func (f *fakeQuerier) Query(filter jsonfile.Filter) (jsonfile.QueryResult, error) {
	return f.result, f.err
}
func (f *fakeQuerier) ListServices() ([]string, error) { return f.services, f.err }
func (f *fakeQuerier) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte)
	close(ch)
	return ch, func() {}
}

func TestQueryLogs_Unconfigured(t *testing.T) {
	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	h.QueryLogs(rec, req)
	if rec.Code < 500 {
		t.Errorf("expected 5xx when log querier unset, got %d", rec.Code)
	}
}

func TestQueryLogs_ReturnsEntries(t *testing.T) {
	h := newTestHandlers(t)
	h.SetLogQuerier(&fakeQuerier{
		result: jsonfile.QueryResult{
			Entries: []jsonfile.Entry{{
				Time:    time.Now().UTC(),
				Level:   "INFO",
				Msg:     "first record",
				Service: "ca",
			}},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/logs?level=info&limit=10", nil)
	rec := httptest.NewRecorder()
	h.QueryLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "first record") {
		t.Errorf("expected entry in body, got %s", rec.Body.String())
	}
}

func TestQueryLogs_BadSince(t *testing.T) {
	h := newTestHandlers(t)
	h.SetLogQuerier(&fakeQuerier{})
	req := httptest.NewRequest(http.MethodGet, "/logs?since=not-a-date", nil)
	rec := httptest.NewRecorder()
	h.QueryLogs(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestQueryLogs_QuerierError(t *testing.T) {
	h := newTestHandlers(t)
	h.SetLogQuerier(&fakeQuerier{err: errors.New("disk gone")})
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	h.QueryLogs(rec, req)
	if rec.Code < 500 {
		t.Errorf("expected 5xx, got %d", rec.Code)
	}
}

func TestListLogServices(t *testing.T) {
	h := newTestHandlers(t)
	h.SetLogQuerier(&fakeQuerier{services: []string{"ca", "tpm", "sdn"}})
	req := httptest.NewRequest(http.MethodGet, "/logs/services", nil)
	rec := httptest.NewRecorder()
	h.ListLogServices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, s := range []string{`"ca"`, `"tpm"`, `"sdn"`} {
		if !strings.Contains(rec.Body.String(), s) {
			t.Errorf("expected service %s in body, got %s", s, rec.Body.String())
		}
	}
}

func TestParseLogFilter_LimitClamp(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/logs?limit=99999", nil)
	f, err := parseLogFilter(req)
	if err != nil {
		t.Fatalf("parseLogFilter: %v", err)
	}
	if f.Limit != 5000 {
		t.Errorf("limit = %d, want clamp to 5000", f.Limit)
	}
}

func TestParseLogFilter_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	f, err := parseLogFilter(req)
	if err != nil {
		t.Fatalf("parseLogFilter: %v", err)
	}
	if f.MinLevel != "" {
		t.Errorf("MinLevel = %q, want empty", f.MinLevel)
	}
}
