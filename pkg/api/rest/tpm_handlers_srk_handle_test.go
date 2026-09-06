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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/tpm/srk used to read tpm.SSRKAttributes() and ignore the
// request entirely, so it answered every call with the SSRK and a 200.
// Issue #475.
//
// The pre-existing TestTPMHandleGetSRK asks for the default SRK and
// asserts handle 0x81000001. That input cannot reach the defect: ignoring
// the handle and defaulting to the SSRK give the same answer. These cases
// use inputs that can, and assert on WHICH key came back.

func getSRK(t *testing.T, query string) *http.Response {
	t.Helper()
	tpm := newMockTPMService()
	_, router := setupTPMTestHandler(tpm)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/srk"+query, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Result()
}

// TestGetSRKResolvesThePlatformHandle is the regression: asking for the
// platform SRK must return the platform key, not the SSRK.
func TestGetSRKResolvesThePlatformHandle(t *testing.T) {
	resp := getSRK(t, "?handle=0x81000002")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var keyResp TPMKeyResponse
	decodeTPMResponse(t, resp, &keyResp)

	assert.Equal(t, uint32(0x81000002), keyResp.Handle,
		"a request for the PlatformSRK must not be answered with the SSRK")
	assert.Equal(t, "ECDSA", keyResp.Algorithm,
		"the algorithm must come from the platform key, not the SSRK's RSA")
}

// TestGetSRKAcceptsDecimalHandle covers the same resolution through the
// decimal spelling, since query strings carry no type.
func TestGetSRKAcceptsDecimalHandle(t *testing.T) {
	resp := getSRK(t, "?handle=2164260866") // 0x81000002
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var keyResp TPMKeyResponse
	decodeTPMResponse(t, resp, &keyResp)
	assert.Equal(t, uint32(0x81000002), keyResp.Handle)
}

// TestGetSRKRejectsUnknownHandle is the other half. An unknown handle
// must be a 404, never a fall-through to a key the caller did not name.
func TestGetSRKRejectsUnknownHandle(t *testing.T) {
	resp := getSRK(t, "?handle=0x81000099")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"an unknown SRK handle must 404 rather than return a key")
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

// TestGetSRKRejectsMalformedHandle keeps a typo from silently becoming
// the default: "cafe" parses as nothing, and defaulting it to 0 would
// answer with the SSRK.
func TestGetSRKRejectsMalformedHandle(t *testing.T) {
	resp := getSRK(t, "?handle=cafe")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a malformed handle must be rejected, not defaulted to the SSRK")
}

// TestGetSRKWithoutHandleStillReturnsSSRK pins the compatibility the
// change must preserve: the parameter is optional and its absence means
// what it always meant.
func TestGetSRKWithoutHandleStillReturnsSSRK(t *testing.T) {
	for _, q := range []string{"", "?handle=0", "?handle=0x81000001"} {
		resp := getSRK(t, q)
		require.Equal(t, http.StatusOK, resp.StatusCode, "query %q", q)

		var keyResp TPMKeyResponse
		decodeTPMResponse(t, resp, &keyResp)
		assert.Equal(t, uint32(0x81000001), keyResp.Handle, "query %q", q)
	}
}
