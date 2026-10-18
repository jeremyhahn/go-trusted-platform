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

package testutil

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func noopHandler(http.ResponseWriter, *http.Request) {}

func TestWalkRoutes(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/eab/credentials/{id:[0-9]+}", noopHandler).Methods(http.MethodGet, http.MethodDelete)
	router.HandleFunc("/api/v1/eab/credentials", noopHandler)

	require.Equal(t, []string{
		"DELETE /api/v1/eab/credentials/{id:[0-9]+}",
		"GET /api/v1/eab/credentials",
		"GET /api/v1/eab/credentials/{id:[0-9]+}",
	}, WalkRoutes(t, router), "a route without a method matcher is listed as GET")
}

func TestWalkRoutes_EmptyRouter(t *testing.T) {
	require.Empty(t, WalkRoutes(t, mux.NewRouter()))
}

func TestClaimPrefix(t *testing.T) {
	require.Equal(t, "bmc", ClaimPrefix("/api/v1/bmc/{profileID}/power"))
	require.Equal(t, "version", ClaimPrefix("/api/v1/version"))
	require.Equal(t, "", ClaimPrefix("/api/v1/"), "an empty remainder has no prefix")
}

func TestDaemonOnlyPrefixOf(t *testing.T) {
	cases := []struct {
		name, path, want string
		ok               bool
	}{
		{"bare prefix", "/api/v1/version", "version", true},
		{"under a prefix", "/api/v1/bmc/{profileID}/power", "bmc", true},
		{"multi-segment prefix", "/api/v1/sdn/gateway/nat64/status", "sdn/gateway/nat64", true},
		{"sibling of a multi-segment prefix", "/api/v1/sdn/gateway/ipam/pools", "", false},
		{"prefix is only a word prefix", "/api/v1/versions", "", false},
		{"shared prefix", "/api/v1/tpm/info", "", false},
		{"outside /api/v1", "/bmc/1/power", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DaemonOnlyPrefixOf(tc.path)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestMatchClaim(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/eab/credentials/{id:[0-9]+}", noopHandler).Methods(http.MethodGet)
	built := WalkRoutes(t, router)

	route, ok := MatchClaim(router, http.MethodGet, "/api/v1/eab/credentials/{cid}", built)
	require.True(t, ok, "a claim's {cid} facing {id:[0-9]+} must be sent as a value the pattern accepts")
	template, err := route.GetPathTemplate()
	require.NoError(t, err)
	require.Equal(t, "/api/v1/eab/credentials/{id:[0-9]+}", template)

	_, ok = MatchClaim(router, http.MethodPost, "/api/v1/eab/credentials/{cid}", built)
	require.False(t, ok, "a method the route does not serve must not match")
	require.False(t, ClaimResolves(router, http.MethodGet, "/api/v1/eab/missing", built))
}

func TestClaimAlignsWith(t *testing.T) {
	cases := []struct {
		name         string
		claim, route string
		want         bool
	}{
		{"pattern placeholder faces plain one", "GET /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}", true},
		{"placeholders differ only in name", "POST /api/v1/eab/credentials/{cid}/revoke", "POST /api/v1/eab/credentials/{id:[0-9]+}/revoke", true},
		{"identical literal route", "POST /api/v1/eab/credentials/validate", "POST /api/v1/eab/credentials/validate", true},
		{"different literal segment", "POST /api/v1/eab/credentials/{id}/revoke", "POST /api/v1/eab/credentials/{id:[0-9]+}/used", false},
		{"different method", "DELETE /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}", false},
		{"different segment count", "GET /api/v1/eab/credentials/{id}", "GET /api/v1/eab/credentials/{id:[0-9]+}/url", false},
		{"placeholder faces literal", "POST /api/v1/eab/credentials/{id}", "POST /api/v1/eab/credentials/validate", false},
		{"literal faces placeholder", "GET /api/v1/eab/credentials/abc", "GET /api/v1/eab/credentials/{id:[0-9]+}", false},
		{"claim without method", "/api/v1/eab/credentials", "GET /api/v1/eab/credentials", false},
		{"route without method", "GET /api/v1/eab/credentials", "/api/v1/eab/credentials", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ClaimAlignsWith(tc.claim, tc.route))
		})
	}
}

func TestConcreteClaim(t *testing.T) {
	built := []string{
		"GET /api/v1/eab/credentials/key/{key}",
		"GET /api/v1/eab/credentials/{id:[0-9]+}",
	}

	require.Equal(t, "/api/v1/eab/credentials/1",
		ConcreteClaim("GET", "/api/v1/eab/credentials/{id}", built),
		"an aligned server route's pattern must pick the value")
	require.Equal(t, "/api/v1/eab/credentials/x",
		ConcreteClaim("DELETE", "/api/v1/eab/credentials/{id}", built),
		"with no aligned route the claim's own template is made concrete")
	require.Equal(t, "/api/v1/eab/credentials/key/x",
		ConcreteClaim("GET", "/api/v1/eab/credentials/key/{key}", built))
}

func TestNormalisePlaceholders(t *testing.T) {
	require.Equal(t, "/api/v1/devices/{}/disable", NormalisePlaceholders("/api/v1/devices/{id:[0-9]+}/disable"))
	require.Equal(t, NormalisePlaceholders("/a/{x}/b/{y}"), NormalisePlaceholders("/a/{id}/b/{port:[0-9]+}"))
	require.NotEqual(t, NormalisePlaceholders("/a/{x}/b"), NormalisePlaceholders("/a/{x}/c"),
		"literal segments must still differ")
}
