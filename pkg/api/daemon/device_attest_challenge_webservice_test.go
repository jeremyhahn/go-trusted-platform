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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	mwiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// TestWebserviceDeviceAttest_Challenge_RoundTrip drives the
// pkg/webservice/v1/device attest handlers against the real
// DeviceGRPCService with the challenge required. The caller's tenant comes
// from the webservice authenticators' own context keys (a platform token's
// AuthorizedContext or an IAM session), and every challenge refusal answers
// as a 4xx, not 500 (#2142 Codex round 1).
func TestWebserviceDeviceAttest_Challenge_RoundTrip(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())

	h := wsdevice.NewAttestHandler(logging.DefaultLogger(),
		response.NewResponseWriter(logging.DefaultLogger(), nil), svc)
	require.NotNil(t, h)
	ch, ok := h.(wsdevice.AttestChallengeHandler)
	require.True(t, ok, "the attest handler serves the challenge route")

	deviceID := itoa(f.device.ID)
	tokenCtx := func(tenant string) context.Context {
		return mwiam.SetAuthorizedContext(context.Background(),
			&platformtoken.AuthorizedContext{TenantID: tenant})
	}
	sessionCtx := func(tenant string) context.Context {
		return mwiam.SetSessionInContext(context.Background(),
			mwiam.NewIAMSession(&iamsdk.User{TenantID: tenant}))
	}
	tenantA := tokenCtx("tenant-a")

	type envelope struct {
		Code    int             `json:"code"`
		Success bool            `json:"success"`
		Payload json.RawMessage `json:"payload"`
		Error   string          `json:"error"`
	}

	issueFor := func(t *testing.T, ctx context.Context, id string) wsdevice.AttestChallengeResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+id+"/attest/challenge", nil)
		req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"id": id})
		w := httptest.NewRecorder()
		ch.HandleIssueAttestationChallenge(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var env envelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		var resp wsdevice.AttestChallengeResponse
		require.NoError(t, json.Unmarshal(env.Payload, &resp), w.Body.String())
		require.NotEmpty(t, resp.ChallengeID)
		require.Len(t, resp.Nonce, 32)
		return resp
	}
	issue := func(t *testing.T, ctx context.Context) wsdevice.AttestChallengeResponse {
		t.Helper()
		return issueFor(t, ctx, deviceID)
	}

	attest := func(t *testing.T, ctx context.Context, body wsdevice.AttestRequest) (int, envelope) {
		t.Helper()
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+deviceID+"/attest",
			strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"id": deviceID})
		w := httptest.NewRecorder()
		h.HandleAttestDevice(w, req)
		var env envelope
		if w.Body.Len() > 0 {
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
		}
		return w.Code, env
	}

	t.Run("challenge then attest verifies, reuse is 409", func(t *testing.T) {
		c := issue(t, tenantA)
		body := wsdevice.AttestRequest{
			Evidence:    f.evidence(t, c.Nonce, goldenPCRs()),
			ChallengeID: c.ChallengeID,
		}
		code, env := attest(t, tenantA, body)
		require.Equal(t, http.StatusOK, code, env)
		var verdict wsdevice.AttestResponse
		require.NoError(t, json.Unmarshal(env.Payload, &verdict))
		assert.True(t, verdict.Verified)
		assert.True(t, verdict.NonceValid)

		code, env = attest(t, tenantA, body)
		assert.Equal(t, http.StatusConflict, code, "a used challenge must not verify again: %v", env)
	})

	t.Run("another tenant's challenge is 403 (token)", func(t *testing.T) {
		c := issue(t, tenantA)
		code, env := attest(t, tokenCtx("tenant-b"), wsdevice.AttestRequest{
			Evidence:    f.evidence(t, c.Nonce, goldenPCRs()),
			ChallengeID: c.ChallengeID,
		})
		assert.Equal(t, http.StatusForbidden, code, env)
	})

	t.Run("another tenant's challenge is 403 (session)", func(t *testing.T) {
		c := issue(t, tenantA)
		code, env := attest(t, sessionCtx("tenant-b"), wsdevice.AttestRequest{
			Evidence:    f.evidence(t, c.Nonce, goldenPCRs()),
			ChallengeID: c.ChallengeID,
		})
		assert.Equal(t, http.StatusForbidden, code, env)
	})

	t.Run("expired challenge is 409", func(t *testing.T) {
		c := issue(t, tenantA)
		clock = f.now.Add(5*time.Minute + time.Second)
		defer func() { clock = f.now }()
		code, env := attest(t, tenantA, wsdevice.AttestRequest{
			Evidence:    f.evidence(t, c.Nonce, goldenPCRs()),
			ChallengeID: c.ChallengeID,
		})
		assert.Equal(t, http.StatusConflict, code, env)
	})

	t.Run("another device's challenge is 409", func(t *testing.T) {
		c := issueFor(t, tenantA, createOtherDevice(t, f))
		code, env := attest(t, tenantA, wsdevice.AttestRequest{
			Evidence:    f.evidence(t, c.Nonce, goldenPCRs()),
			ChallengeID: c.ChallengeID,
		})
		assert.Equal(t, http.StatusConflict, code, env)
	})

	t.Run("an unknown device is 404 and gets no challenge", func(t *testing.T) {
		unknown := itoa(f.device.ID + 1000)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+unknown+"/attest/challenge", nil)
		req = mux.SetURLVars(req.WithContext(tenantA), map[string]string{"id": unknown})
		w := httptest.NewRecorder()
		ch.HandleIssueAttestationChallenge(w, req)
		require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		var env envelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
		assert.False(t, env.Success)
		assert.True(t, len(env.Payload) == 0 || string(env.Payload) == "null", "no challenge in the body: %s", w.Body.String())
	})

	t.Run("nonce mismatch is 409", func(t *testing.T) {
		c := issue(t, tenantA)
		code, env := attest(t, tenantA, wsdevice.AttestRequest{
			Evidence:    f.evidence(t, []byte("not-the-challenge-nonce-32-bytes"), goldenPCRs()),
			ChallengeID: c.ChallengeID,
		})
		assert.Equal(t, http.StatusConflict, code, env)
	})

	t.Run("missing challenge while required is 400", func(t *testing.T) {
		code, env := attest(t, tenantA, wsdevice.AttestRequest{
			Evidence: f.evidence(t, []byte("caller-chosen-nonce"), goldenPCRs()),
		})
		assert.Equal(t, http.StatusBadRequest, code, env)
	})
}
