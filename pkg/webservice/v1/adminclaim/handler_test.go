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

package adminclaim

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// restHarness wires the handler onto a real router with the real
// response writer, so a test measures the wire behaviour an operator and
// the console actually see.
type restHarness struct {
	*harness
	router *mux.Router
}

func newRESTHarness(t *testing.T) *restHarness {
	t.Helper()
	h := newHarness(t)
	handler, err := NewRestHandler(testLogger(),
		response.NewResponseWriter(testLogger(), nil), h.svc)
	require.NoError(t, err)

	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return &restHarness{harness: h, router: router}
}

func (r *restHarness) do(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(encoded))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	return rec
}

// payload extracts the platform envelope's payload.
func payload(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	var env struct {
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	require.NoError(t, json.Unmarshal(env.Payload, out))
}

func TestNewRestHandler_RejectsMissingDependencies(t *testing.T) {
	h := newHarness(t)
	writer := response.NewResponseWriter(testLogger(), nil)

	tests := []struct {
		name    string
		logger  bool
		writer  bool
		service bool
		missing string
	}{
		{"no logger", false, true, true, "logger"},
		{"no writer", true, false, true, "response writer"},
		{"no service", true, true, false, "claim service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := testLogger()
			if !tt.logger {
				l = nil
			}
			w := writer
			if !tt.writer {
				w = nil
			}
			s := h.svc
			if !tt.service {
				s = nil
			}
			handler, err := NewRestHandler(l, w, s)
			assert.Nil(t, handler)
			var missing ErrDependencyRequired
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, tt.missing, missing.Name)
		})
	}
}

func TestStatus(t *testing.T) {
	h := newRESTHarness(t)

	rec := h.do(t, http.MethodGet, "/api/v1/admin/claim/status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var status StatusResponse
	payload(t, rec, &status)
	assert.False(t, status.Claimed)
	assert.Equal(t, "admin", status.Username)
	assert.Equal(t, testTenantID, status.TenantID)

	h.factors.resp = &quicbaassdk.AuthFactorListResponse{
		Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "fido2"}},
	}
	rec = h.do(t, http.MethodGet, "/api/v1/admin/claim/status", nil, nil)
	payload(t, rec, &status)
	assert.True(t, status.Claimed)
}

// TestStatus_FailsClosedOnSDKError is the important one: a node whose SDK
// is unreachable must not report itself claimable.
func TestStatus_FailsClosedOnSDKError(t *testing.T) {
	h := newRESTHarness(t)
	h.factors.err = errors.New("transport down")

	rec := h.do(t, http.MethodGet, "/api/v1/admin/claim/status", nil, nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestChallengeAndVerify(t *testing.T) {
	h := newRESTHarness(t)

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/challenge", struct{}{}, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var challenge ChallengeResponse
	payload(t, rec, &challenge)
	require.NotEmpty(t, challenge.Challenge)

	_, certPEM, signer := h.pki.adminLeaf(t)
	rec = h.do(t, http.MethodPost, "/api/v1/admin/claim/verify", ProveRequest{
		Challenge:      challenge.Challenge,
		CertificatePEM: string(certPEM),
		Signature:      signChallenge(t, signer, challenge.Challenge),
	}, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var verified VerifyResponse
	payload(t, rec, &verified)
	assert.NotEmpty(t, verified.ClaimToken)
}

func TestVerify_RejectionIsUninformative(t *testing.T) {
	h := newRESTHarness(t)
	other := newPKI(t)
	_, certPEM, signer := other.adminLeaf(t)

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/verify", ProveRequest{
		Challenge:      "whatever",
		CertificatePEM: string(certPEM),
		Signature:      signChallenge(t, signer, "whatever"),
	}, nil)
	require.Equal(t, http.StatusForbidden, rec.Code)
	// The body must not disclose WHICH check failed.
	body := rec.Body.String()
	assert.Contains(t, body, "proof rejected")
	assert.NotContains(t, body, "trust anchor")
	assert.NotContains(t, body, "challenge is unknown")
}

func TestVerify_RejectsMalformedBody(t *testing.T) {
	h := newRESTHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claim/verify",
		strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerify_AcceptsMTLSPeerCertificate(t *testing.T) {
	h := newRESTHarness(t)
	cert, _, _ := h.pki.adminLeaf(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claim/verify",
		strings.NewReader("{}"))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var verified VerifyResponse
	payload(t, rec, &verified)
	assert.NotEmpty(t, verified.ClaimToken)
}

func TestPasskeyCeremony(t *testing.T) {
	h := newRESTHarness(t)
	token := h.claimTo(t)

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/passkey/begin", nil,
		map[string]string{ClaimTokenHeader: token})
	require.Equal(t, http.StatusOK, rec.Code)
	var creation map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &creation))
	assert.Equal(t, "sess-1", creation["session_id"])
	assert.Contains(t, creation, "publicKey")

	rec = h.do(t, http.MethodPost, "/api/v1/admin/claim/passkey/finish",
		map[string]string{"id": "cred"},
		map[string]string{ClaimTokenHeader: token, SessionIDHeader: "sess-1"})
	require.Equal(t, http.StatusOK, rec.Code)
	var finished FinishResponse
	payload(t, rec, &finished)
	assert.Equal(t, "console-jwt", finished.Token)
	assert.Equal(t, testTenantID, finished.TenantID)
}

func TestPasskeyBegin_RejectsMissingClaimToken(t *testing.T) {
	h := newRESTHarness(t)
	h.claimTo(t)

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/passkey/begin", nil, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPasskeyBegin_SurfacesUnparseableSDKOptions(t *testing.T) {
	h := newRESTHarness(t)
	token := h.claimTo(t)
	h.ceremony.beginResp = &quicbaassdk.FIDO2BeginRegistrationResponse{
		SessionID: "s", OptionsJSON: "not json",
	}

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/passkey/begin", nil,
		map[string]string{ClaimTokenHeader: token})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPasskeyFinish_RejectsUnverifiedAttestation(t *testing.T) {
	h := newRESTHarness(t)
	token := h.claimTo(t)
	h.ceremony.finishResp = &quicbaassdk.FIDO2FinishRegistrationResponse{Success: false}

	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/passkey/finish",
		map[string]string{"id": "cred"}, map[string]string{ClaimTokenHeader: token})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestChallenge_RefusedOnceClaimed(t *testing.T) {
	h := newRESTHarness(t)
	h.factors.resp = &quicbaassdk.AuthFactorListResponse{
		Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "fido2"}},
	}
	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/challenge", struct{}{}, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "already been claimed")
}

func TestChallenge_RateLimitedByStoreCapacity(t *testing.T) {
	h := newRESTHarness(t)
	for i := 0; i < maxOutstanding; i++ {
		rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/challenge", struct{}{}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	rec := h.do(t, http.MethodPost, "/api/v1/admin/claim/challenge", struct{}{}, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// TestVerify_AcceptsAnEmptyBodyOverMTLS pins the documented mTLS proof
// path. The contract says the body MAY be empty when the handshake already
// presented the admin certificate, because the handshake is the proof
// (docs/auth/api.md). The handler required a body, so the request died on
// EOF with a 400 before Service.Prove could look at the peer certificate at
// all — an advertised path that could not succeed.
//
// TestVerify_AcceptsMTLSPeerCertificate did not catch it because it sends
// "{}", which decodes fine. Only a genuinely empty body reaches the bug.
func TestVerify_AcceptsAnEmptyBodyOverMTLS(t *testing.T) {
	h := newRESTHarness(t)
	cert, _, _ := h.pki.adminLeaf(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claim/verify",
		strings.NewReader(""))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the handshake IS the proof; no body is required")
	var verified VerifyResponse
	payload(t, rec, &verified)
	assert.NotEmpty(t, verified.ClaimToken)
}

// TestVerify_EmptyBodyWithoutMTLSStillFails is the security control for the
// test above: tolerating an absent body must not turn /verify into an
// unauthenticated claim. With no peer certificate there is no proof, and
// the zero-value request carries no challenge to redeem.
func TestVerify_EmptyBodyWithoutMTLSStillFails(t *testing.T) {
	h := newRESTHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claim/verify",
		strings.NewReader(""))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), "claim_token")
}

// TestVerify_TruncatedBodyIsStillRejected pins the line the tolerance draws:
// "said nothing" is allowed, "said something broken" is not. json.Decoder
// reports the first as io.EOF and the second as io.ErrUnexpectedEOF, which
// is what makes the distinction reliable rather than a guess at length.
func TestVerify_TruncatedBodyIsStillRejected(t *testing.T) {
	h := newRESTHarness(t)
	cert, _, _ := h.pki.adminLeaf(t)

	for name, body := range map[string]string{
		"truncated object": `{"challenge":`,
		"garbage":          "{not json",
		"bare token":       "nul",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claim/verify",
				strings.NewReader(body))
			// Even WITH a valid handshake: a corrupt body is a corrupt
			// request, and quietly ignoring it would hide a client bug.
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			rec := httptest.NewRecorder()
			h.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

// TestWriteClaimError_MultiInstanceIsNotImplementedNot500 pins the status
// for a deployment shape this build deliberately does not serve. A 501 says
// "this server does not implement that here" and carries the typed reason
// and its issue pointer; the 500 it used to answer told operators to hunt
// for a bug in a refusal that was working exactly as designed.
func TestWriteClaimError_MultiInstanceIsNotImplementedNot500(t *testing.T) {
	h := newRESTHarness(t)
	h.svc.refuseMultiInstance = true

	for name, path := range map[string]string{
		"challenge": "/api/v1/admin/claim/challenge",
		"verify":    "/api/v1/admin/claim/verify",
	} {
		t.Run(name, func(t *testing.T) {
			rec := h.do(t, http.MethodPost, path, ProveRequest{}, nil)
			require.Equal(t, http.StatusNotImplemented, rec.Code)
			assert.Contains(t, rec.Body.String(), "multi-instance deployment",
				"the refusal must explain itself")
			assert.Contains(t, rec.Body.String(), "#172",
				"and point at what would lift it")
		})
	}
}

// TestStatus_StaysReadableOnAMultiInstanceDeployment pins the deliberate
// asymmetry: the four MUTATING ceremony paths refuse, but status does not.
// The console has to be able to tell a clustered node from a broken one,
// and status mutates nothing — so refusing it would remove a signal without
// removing any risk. Recorded in docs/auth/architecture.md §6b.5.
func TestStatus_StaysReadableOnAMultiInstanceDeployment(t *testing.T) {
	h := newRESTHarness(t)
	h.svc.refuseMultiInstance = true

	rec := h.do(t, http.MethodGet, "/api/v1/admin/claim/status", nil, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	var status StatusResponse
	payload(t, rec, &status)
	assert.False(t, status.Claimed)
}
