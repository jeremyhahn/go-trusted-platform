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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
)

type stubRefresher struct {
	ids []string
	err error
}

func (s *stubRefresher) Refresh(id string) error {
	s.ids = append(s.ids, id)
	return s.err
}

func seededCache(t *testing.T) *reporting.Cache {
	t.Helper()
	c := reporting.NewCache(time.Hour)
	c.Store(&reporting.Report{DeviceID: "42", Serial: "SN-42", Verified: true, Status: "verified", CollectedAt: time.Now().Add(-time.Minute)})
	c.Store(&reporting.Report{DeviceID: "7", Verified: false, Cryptographic: true, Status: "failed", Message: "bad signature", CollectedAt: time.Now().Add(-3 * time.Hour)})
	return c
}

func mountReports(rep *Reporting) *mux.Router {
	root := mux.NewRouter()
	NewReportsRouter(testLoggerFor(), rep, testWriter()).RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func TestReportsRouter_ListRendersVerdictWithAge(t *testing.T) {
	router := mountReports(&Reporting{Reports: seededCache(t)})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	env := decodeEnvelope(t, w)
	payload := env["payload"].(map[string]any)
	assert.Equal(t, float64(2), payload["count"])
	reports := payload["reports"].([]any)
	first := reports[0].(map[string]any)
	assert.Equal(t, "42", first["device_id"])
	assert.Equal(t, true, first["verified"])
	assert.Equal(t, true, first["fresh"])
	assert.Contains(t, first, "age_seconds")
	assert.Contains(t, first, "collected_at")
	second := reports[1].(map[string]any)
	assert.Equal(t, "7", second["device_id"])
	assert.Equal(t, false, second["fresh"])
	assert.Equal(t, true, second["cryptographic_failure"])
}

func TestReportsRouter_GetDistinguishesNeverCollectedFromFailed(t *testing.T) {
	router := mountReports(&Reporting{Reports: seededCache(t)})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/7", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, false, payload["verified"])
	assert.Equal(t, "bad signature", payload["message"])

	req = httptest.NewRequest(http.MethodGet, "/api/v1/attestation/reports/999", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no report has been collected")
}

func TestReportsRouter_RefreshEnqueuesAndNeverQuotes(t *testing.T) {
	refresher := &stubRefresher{}
	router := mountReports(&Reporting{Reports: seededCache(t), Refresher: refresher})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/reports/42/refresh", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, true, payload["enqueued"])
	assert.Equal(t, "42", payload["device_id"])
	assert.Equal(t, []string{"42"}, refresher.ids)
}

func TestReportsRouter_RefreshErrors(t *testing.T) {
	stopped := &stubRefresher{err: reporting.ErrCollectorStopped{}}
	router := mountReports(&Reporting{Refresher: stopped})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/reports/42/refresh", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	bad := &stubRefresher{err: reporting.ErrDeviceIDRequired{}}
	router = mountReports(&Reporting{Refresher: bad})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/attestation/reports/42/refresh", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportsRouter_NotConfiguredAnswers503NotSilence(t *testing.T) {
	for _, rep := range []*Reporting{nil, {}} {
		router := mountReports(rep)
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/attestation/reports"},
			{http.MethodGet, "/api/v1/attestation/reports/1"},
			{http.MethodPost, "/api/v1/attestation/reports/1/refresh"},
		} {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, tc.path)
			assert.Contains(t, w.Body.String(), "not configured")
		}
	}
}
