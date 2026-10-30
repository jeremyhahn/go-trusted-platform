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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Codex review 8545: the manifest list route must hand its query filters to
// the service, not an empty request.
func TestAttestationServerRouter_ListManifestsPassesFilters(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)
	tests := []struct {
		name  string
		query string
		want  *platformv1.ListManifestsRequest
	}{
		{
			name:  "no parameters is an empty request",
			query: "",
			want:  &platformv1.ListManifestsRequest{},
		},
		{
			name:  "every filter",
			query: "?host_id=node-a&limit=10&offset=5&start_time=2026-10-01T00:00:00Z&end_time=2026-10-02T12:30:00Z",
			want: &platformv1.ListManifestsRequest{
				HostId:    "node-a",
				StartTime: timestamppb.New(start),
				EndTime:   timestamppb.New(end),
				Limit:     10,
				Offset:    5,
			},
		},
		{
			name:  "host only",
			query: "?host_id=node-b",
			want:  &platformv1.ListManifestsRequest{HostId: "node-b"},
		},
		{
			name:  "open-ended start",
			query: "?start_time=2026-10-01T00:00:00Z",
			want:  &platformv1.ListManifestsRequest{StartTime: timestamppb.New(start)},
		},
		{
			name:  "equal start and end",
			query: "?start_time=2026-10-01T00:00:00Z&end_time=2026-10-01T00:00:00Z",
			want: &platformv1.ListManifestsRequest{
				StartTime: timestamppb.New(start),
				EndTime:   timestamppb.New(start),
			},
		},
		{
			name:  "largest uint32 limit",
			query: "?limit=4294967295",
			want:  &platformv1.ListManifestsRequest{Limit: 4294967295},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &recordingAttestationServer{}
			rec := serveListManifests(server, tt.query)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			got, ok := server.req.(*platformv1.ListManifestsRequest)
			require.True(t, ok, "the server receives a ListManifestsRequest")
			assert.True(t, proto.Equal(tt.want, got), "want %v, got %v", tt.want, got)
		})
	}
}

func TestAttestationServerRouter_ListManifestsMalformedFilterIs400(t *testing.T) {
	tests := map[string]string{
		"limit not a number":     "?limit=ten",
		"negative limit":         "?limit=-1",
		"limit over uint32":      "?limit=4294967296",
		"offset not a number":    "?offset=five",
		"offset over uint32":     "?offset=4294967296",
		"start_time not RFC3339": "?start_time=2026-10-01",
		"end_time not RFC3339":   "?end_time=yesterday",
		"start_time after end":   "?start_time=2026-10-02T00:00:00Z&end_time=2026-10-01T00:00:00Z",
	}
	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			server := &recordingAttestationServer{}
			rec := serveListManifests(server, query)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, server.req, "the server is not called with a rejected filter")
		})
	}
}

func TestParseListManifestsRequest_TimeRangeError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/?start_time=2026-10-02T00:00:00Z&end_time=2026-10-01T00:00:00Z", nil)
	_, err := parseListManifestsRequest(req.URL.Query())
	var rangeErr ErrManifestTimeRange
	require.ErrorAs(t, err, &rangeErr)
	assert.Equal(t, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), rangeErr.Start)
	assert.Contains(t, err.Error(), "is after end_time")
}

func serveListManifests(server *recordingAttestationServer, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifests"+query, nil)
	rec := httptest.NewRecorder()
	mountAllAttestationRoutes(server).ServeHTTP(rec, req)
	return rec
}
