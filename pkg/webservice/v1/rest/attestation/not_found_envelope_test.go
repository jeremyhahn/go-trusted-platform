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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A client tells a missing manifest from a missing route by the body of the
// 404: the router renders the server's NotFound in the JSON error envelope,
// while a path no route matches gets the mux's plain-text 404 (#546).

func TestAttestationServerRouter_NotFoundCarriesTheErrorEnvelope(t *testing.T) {
	routes := []attestationRoute{
		{name: "get manifest", method: http.MethodGet, path: "/api/v1/attestation/manifests/absent"},
		{name: "verify manifest", method: http.MethodPost, path: "/api/v1/attestation/manifests/verify", body: `{}`},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			server := &recordingAttestationServer{err: status.Error(codes.NotFound, "manifest not found")}
			rec := serveAttestationRoute(mountAllAttestationRoutes(server), rt, rt.body)

			require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			env := decodeEnvelope(t, rec)
			assert.Equal(t, false, env["success"])
			assert.Contains(t, env["error"], "manifest not found")
		})
	}
}

func TestAttestationServerRouter_UnregisteredPathIsAPlain404(t *testing.T) {
	server := &recordingAttestationServer{}
	rt := attestationRoute{method: http.MethodGet, path: "/api/v1/attestation/no-such-route/x/y"}
	rec := serveAttestationRoute(mountAllAttestationRoutes(server), rt, "")

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Nil(t, server.req, "an unregistered path reached the server")
	var env map[string]any
	assert.Error(t, json.Unmarshal(rec.Body.Bytes(), &env), "an unregistered path rendered a JSON envelope: %s", rec.Body.String())
}
