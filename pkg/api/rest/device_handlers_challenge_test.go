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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// challengeStubService adds IssueAttestationChallenge to stubAttestService and
// records the challenge_id AttestDevice receives.
type challengeStubService struct {
	stubAttestService
	gotIssueDeviceID string
	gotChallengeID   string
	issueCalled      bool
	issueResp        *platformv1.IssueAttestationChallengeResponse
	issueErr         error
}

func (s *challengeStubService) IssueAttestationChallenge(
	_ context.Context,
	req *platformv1.IssueAttestationChallengeRequest,
) (*platformv1.IssueAttestationChallengeResponse, error) {
	s.issueCalled = true
	s.gotIssueDeviceID = req.GetDeviceId()
	if s.issueErr != nil {
		return nil, s.issueErr
	}
	return s.issueResp, nil
}

func (s *challengeStubService) AttestDevice(
	ctx context.Context,
	req *platformv1.AttestDeviceRequest,
) (*platformv1.AttestDeviceResponse, error) {
	s.gotChallengeID = req.GetChallengeId()
	return s.stubAttestService.AttestDevice(ctx, req)
}

func postChallengeRoute(router *mux.Router, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestDeviceHandlers_AttestChallenge(t *testing.T) {
	const challengePath = "/api/v1/devices/42/attest/challenge"
	const attestPath = "/api/v1/devices/42/attest"

	t.Run("issues a challenge", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0x01}, 32)
		expires := time.Unix(1757000300, 0).UTC()
		svc := &challengeStubService{issueResp: &platformv1.IssueAttestationChallengeResponse{
			ChallengeId: "ch-1",
			Nonce:       nonce,
			ExpiresAt:   timestamppb.New(expires),
		}}

		w := postChallengeRoute(setupAttestRouter(svc), challengePath, "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "42", svc.gotIssueDeviceID)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
		for _, key := range []string{"challenge_id", "nonce", "expires_at"} {
			assert.Contains(t, raw, key)
		}

		var resp DeviceAttestChallengeResponse
		decodeDeviceResponse(t, w.Body, &resp)
		assert.Equal(t, "ch-1", resp.ChallengeID)
		assert.Equal(t, nonce, resp.Nonce)
		assert.True(t, expires.Equal(resp.ExpiresAt), "expires_at %v", resp.ExpiresAt)
	})

	t.Run("challenge errors by code", func(t *testing.T) {
		cases := []struct {
			code codes.Code
			want int
		}{
			{codes.PermissionDenied, http.StatusForbidden},
			{codes.NotFound, http.StatusNotFound},
			{codes.InvalidArgument, http.StatusBadRequest},
			{codes.Internal, http.StatusInternalServerError},
			{codes.Unimplemented, http.StatusNotImplemented},
		}
		for _, tc := range cases {
			t.Run(tc.code.String(), func(t *testing.T) {
				msg := "challenge refused: " + tc.code.String()
				svc := &challengeStubService{issueErr: status.Error(tc.code, msg)}

				w := postChallengeRoute(setupAttestRouter(svc), challengePath, "")
				require.Equal(t, tc.want, w.Code, w.Body.String())

				var errResp ErrorResponse
				decodeDeviceResponse(t, w.Body, &errResp)
				assert.Contains(t, errResp.Error, msg)
			})
		}
	})

	t.Run("attest carries challenge_id", func(t *testing.T) {
		svc := &challengeStubService{stubAttestService: stubAttestService{
			resp: &platformv1.AttestDeviceResponse{DeviceId: 42, Verified: true},
		}}
		w := postChallengeRoute(setupAttestRouter(svc), attestPath,
			`{"evidence":"e30=","challenge_id":"ch-1"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "ch-1", svc.gotChallengeID)
	})

	t.Run("attest without challenge_id", func(t *testing.T) {
		svc := &challengeStubService{stubAttestService: stubAttestService{
			resp: &platformv1.AttestDeviceResponse{DeviceId: 42, Verified: true},
		}}
		w := postChallengeRoute(setupAttestRouter(svc), attestPath, `{"evidence":"e30="}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "", svc.gotChallengeID)
	})

	t.Run("attest challenge errors", func(t *testing.T) {
		cases := []struct {
			err  error
			want int
		}{
			{status.Error(codes.PermissionDenied, "attestation challenge was issued to another tenant"), http.StatusForbidden},
			{status.Error(codes.FailedPrecondition, "attestation challenge is unknown or already used"), http.StatusConflict},
		}
		for _, tc := range cases {
			svc := &challengeStubService{stubAttestService: stubAttestService{err: tc.err}}
			w := postChallengeRoute(setupAttestRouter(svc), attestPath,
				`{"evidence":"e30=","challenge_id":"ch-1"}`)
			assert.Equal(t, tc.want, w.Code, w.Body.String())
		}
	})

	t.Run("no route without a verifier", func(t *testing.T) {
		handlers := NewDeviceHandlers(newMockDeviceService(), newMockProfileService(), slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		w := postChallengeRoute(router, challengePath, "")
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("empty id", func(t *testing.T) {
		svc := &challengeStubService{}
		h := NewDeviceHandlers(newMockDeviceService(), newMockProfileService(), slog.Default(),
			WithDeviceAttestService(svc))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices//attest/challenge", nil)
		req = mux.SetURLVars(req, map[string]string{"id": ""})
		w := httptest.NewRecorder()
		h.handleIssueAttestationChallenge(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.False(t, svc.issueCalled)
	})
}
