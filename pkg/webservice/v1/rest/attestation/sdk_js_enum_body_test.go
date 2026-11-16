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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestBuildManifest_JavaScriptSDKBody feeds the body the JavaScript SDK's
// buildManifest sends (sdk/javascript/src/services/attestation-service.ts):
// the decoder is protojson, so the hash algorithm must be its full enum name.
func TestBuildManifest_JavaScriptSDKBody(t *testing.T) {
	server := &recordingAttestationServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/manifests/build", strings.NewReader(
		`{"config":{"hostId":"h1","hashAlgorithm":"ATTESTATION_HASH_ALGORITHM_SHA384"},"sign":true}`))
	rec := httptest.NewRecorder()
	mountAllAttestationRoutes(server).ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	build, ok := server.req.(*platformv1.BuildManifestRequest)
	require.True(t, ok, "the router dispatched %T, want BuildManifestRequest", server.req)
	assert.Equal(t, "h1", build.GetConfig().GetHostId())
	assert.Equal(t, platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384, build.GetConfig().GetHashAlgorithm())
}

// TestGetQuote_ShortHashAlgorithmIsLost pins why the SDK maps names: the
// short hash algorithm it used to send is discarded by protojson.
func TestGetQuote_ShortHashAlgorithmIsLost(t *testing.T) {
	server := &recordingAttestationServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/quote", strings.NewReader(
		`{"config":{"akHandle":1,"hashAlgorithm":"SHA384"},"nonce":"AQID"}`))
	rec := httptest.NewRecorder()
	mountAllAttestationRoutes(server).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	quote, ok := server.req.(*platformv1.GetAttestationQuoteRequest)
	require.True(t, ok, "the router dispatched %T, want GetAttestationQuoteRequest", server.req)
	assert.Equal(t, uint32(1), quote.GetConfig().GetAkHandle())
	assert.Equal(t, platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED, quote.GetConfig().GetHashAlgorithm())
}
