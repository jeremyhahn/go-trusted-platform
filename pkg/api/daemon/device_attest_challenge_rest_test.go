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

package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// TestRESTDeviceAttest_Challenge_RoundTrip drives the pkg/api/rest device
// surface against the real DeviceGRPCService with the challenge required: a
// challenge issued over REST verifies once over REST, and the single-use,
// tenant and required checks answer as HTTP statuses, not 500.
func TestRESTDeviceAttest_Challenge_RoundTrip(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())

	handlers := restapi.NewDeviceHandlers(nil, nil, slog.Default(),
		restapi.WithDeviceAttestService(svc))
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)

	deviceID := itoa(f.device.ID)
	tenantA := tokenCallerContext("tenant-a")

	issue := func(t *testing.T, ctx context.Context) restapi.DeviceAttestChallengeResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+deviceID+"/attest/challenge", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var ch restapi.DeviceAttestChallengeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ch))
		require.NotEmpty(t, ch.ChallengeID)
		require.Len(t, ch.Nonce, 32)
		return ch
	}

	attest := func(t *testing.T, ctx context.Context, body restapi.DeviceAttestRequest) (int, map[string]any) {
		t.Helper()
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+deviceID+"/attest",
			strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var decoded map[string]any
		if w.Body.Len() > 0 {
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
		}
		return w.Code, decoded
	}

	t.Run("challenge then attest verifies, reuse is 409", func(t *testing.T) {
		ch := issue(t, tenantA)
		body := restapi.DeviceAttestRequest{
			Evidence:    f.evidence(t, ch.Nonce, goldenPCRs()),
			ChallengeID: ch.ChallengeID,
		}

		code, verdict := attest(t, tenantA, body)
		require.Equal(t, http.StatusOK, code, verdict)
		assert.Equal(t, true, verdict["verified"])
		assert.Equal(t, true, verdict["nonce_valid"])
		assert.Equal(t, true, verdict["signature_valid"])

		code, _ = attest(t, tenantA, body)
		assert.Equal(t, http.StatusConflict, code, "a used challenge must not verify again")
	})

	t.Run("another tenant's challenge is 403", func(t *testing.T) {
		ch := issue(t, tenantA)
		code, body := attest(t, tokenCallerContext("tenant-b"), restapi.DeviceAttestRequest{
			Evidence:    f.evidence(t, ch.Nonce, goldenPCRs()),
			ChallengeID: ch.ChallengeID,
		})
		assert.Equal(t, http.StatusForbidden, code, body)
	})

	t.Run("an unknown device is 404 and gets no challenge", func(t *testing.T) {
		unknown := itoa(f.device.ID + 1000)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+unknown+"/attest/challenge", nil)
		req = req.WithContext(tenantA)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), "challenge_id")
		assert.NotContains(t, w.Body.String(), "nonce")
	})

	t.Run("missing challenge while required is 400", func(t *testing.T) {
		code, body := attest(t, tenantA, restapi.DeviceAttestRequest{
			Evidence: f.evidence(t, []byte("caller-chosen-nonce"), goldenPCRs()),
		})
		assert.Equal(t, http.StatusBadRequest, code, body)
	})
}
