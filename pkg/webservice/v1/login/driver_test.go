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

package login

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login/logintest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// fakeClient records what the driver asked the backbone for and returns
// scripted answers, so a test asserts on the ceremony arguments rather
// than only on the HTTP status.
type fakeClient struct {
	beginReq  quicbaas.BeginLoginRequest
	finishReq quicbaas.FinishLoginRequest

	begin    *quicbaas.BeginLoginResponse
	beginErr error

	finish    *quicbaas.FinishLoginResponse
	finishErr error

	beginCalls  int
	finishCalls int
}

func (c *fakeClient) BeginLogin(_ context.Context, req quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error) {
	c.beginCalls++
	c.beginReq = req
	return c.begin, c.beginErr
}

func (c *fakeClient) FinishLogin(_ context.Context, req quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error) {
	c.finishCalls++
	c.finishReq = req
	return c.finish, c.finishErr
}

// fakeIssuer stands in for the platform's JWT signer. It records the
// identity it was asked to mint for, so a test can assert that the
// credential handed to the client was minted from the identity the
// BACKBONE resolved and from nothing the client supplied.
type fakeIssuer struct {
	identity  *quicbaas.Identity
	calls     int
	bearer    string
	expiresAt time.Time
	err       error
}

func (i *fakeIssuer) IssueSession(identity *quicbaas.Identity) (string, time.Time, error) {
	i.calls++
	i.identity = identity
	if i.err != nil {
		return "", time.Time{}, i.err
	}
	return i.bearer, i.expiresAt, nil
}

// newTestIssuer returns an issuer that mints a recognisable credential, so
// a test can tell the platform's session apart from the backbone's bearer
// by inspecting the response body alone.
func newTestIssuer() *fakeIssuer {
	return &fakeIssuer{
		bearer:    "platform.session.token",
		expiresAt: time.Unix(1700003600, 0).UTC(),
	}
}

func testDeps() (*logging.Logger, response.HttpWriter) {
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	return logger, response.NewResponseWriter(logger, nil)
}

func newTestDriver(t *testing.T, client UnifiedLoginClient, bound ...Binder) *Driver {
	t.Helper()
	return newTestDriverWithIssuer(t, client, newTestIssuer(), bound...)
}

func newTestDriverWithIssuer(
	t *testing.T, client UnifiedLoginClient, issuer SessionIssuer, bound ...Binder) *Driver {

	t.Helper()
	logger, writer := testDeps()
	driver, err := NewDriver(DriverParams{
		Client:         client,
		Binders:        bound,
		SessionIssuer:  issuer,
		Logger:         logger,
		ResponseWriter: writer,
	})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	return driver
}

// assertionBody is a minimal browser PublicKeyCredential: the driver only
// needs the credential id, and the backbone verifies the rest.
func assertionBody(credentialID string) string {
	return `{"id":"` + credentialID + `","type":"public-key","response":{}}`
}

func fido2BeginResponse(t *testing.T, sessionID string) *quicbaas.BeginLoginResponse {
	t.Helper()
	options, err := json.Marshal(map[string]any{
		"publicKey": map[string]any{"challenge": "Y2hhbGxlbmdl"},
	})
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	return &quicbaas.BeginLoginResponse{
		SessionID:         sessionID,
		ChallengeMetadata: map[string]string{challengeOptionsKey: string(options)},
	}
}

func TestNewDriverRequiresItsReportingDependencies(t *testing.T) {
	logger, writer := testDeps()
	issuer := newTestIssuer()
	if _, err := NewDriver(DriverParams{ResponseWriter: writer, SessionIssuer: issuer}); err == nil {
		t.Fatal("expected a missing-logger error")
	}
	if _, err := NewDriver(DriverParams{Logger: logger, SessionIssuer: issuer}); err == nil {
		t.Fatal("expected a missing-writer error")
	}
}

// TestNewDriverRequiresASessionIssuer pins the ordering rule that the
// blocking defect on #646 broke: a driver with no issuer can only answer a
// successful login with the backbone's bearer, which this server's own
// inbound seam rejects. It must not be constructible.
func TestNewDriverRequiresASessionIssuer(t *testing.T) {
	logger, writer := testDeps()

	_, err := NewDriver(DriverParams{
		Logger:         logger,
		ResponseWriter: writer,
		Binders:        []Binder{NewMTLSBinder()},
	})
	var config *DriverConfigError
	if !errors.As(err, &config) {
		t.Fatalf("expected a DriverConfigError, got %v", err)
	}
	if config.Field != "SessionIssuer" {
		t.Fatalf("expected the issuer named on the error, got %q", config.Field)
	}
}

func TestNewDriverRejectsDuplicateAndNilBinders(t *testing.T) {
	logger, writer := testDeps()

	_, err := NewDriver(DriverParams{
		Logger: logger, ResponseWriter: writer, SessionIssuer: newTestIssuer(),
		Binders: []Binder{NewMTLSBinder(), NewMTLSBinder()},
	})
	var duplicate *DuplicateBinderError
	if !errors.As(err, &duplicate) {
		t.Fatalf("expected DuplicateBinderError, got %v", err)
	}
	if duplicate.Type != quicbaas.FactorTypeMTLS {
		t.Fatalf("expected the mtls type on the error, got %q", duplicate.Type)
	}

	_, err = NewDriver(DriverParams{
		Logger: logger, ResponseWriter: writer, SessionIssuer: newTestIssuer(),
		Binders: []Binder{nil},
	})
	if err == nil {
		t.Fatal("expected a nil-binder error")
	}
}

func TestDriverSupportsOnlyRegisteredFactors(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	driver := newTestDriver(t, &fakeClient{}, fido2)

	if !driver.Supports(quicbaas.FactorTypeFIDO2) {
		t.Fatal("expected the registered fido2 factor to be supported")
	}
	if driver.Supports(quicbaas.FactorTypeMTLS) {
		t.Fatal("expected an unregistered factor to be unsupported")
	}
}

func TestDriverBeginFIDO2IssuesAUsernamelessChallenge(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	client := &fakeClient{begin: fido2BeginResponse(t, "sess-1")}
	driver := newTestDriver(t, client, fido2)

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login/begin", nil), quicbaas.FactorTypeFIDO2)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	// The ceremony must be usernameless and tenant-scoped: a hint would
	// reintroduce the directory lookup this design removes.
	if client.beginReq.Hint != "" {
		t.Fatalf("expected no hint, got %q", client.beginReq.Hint)
	}
	if client.beginReq.TenantID != "tenant-a" {
		t.Fatalf("expected the ceremony tenant, got %q", client.beginReq.TenantID)
	}
	if client.finishCalls != 0 {
		t.Fatal("a challenge factor must not finish inside begin")
	}

	// The challenge is written unwrapped: the browser passes publicKey
	// straight to navigator.credentials.get().
	var challenge map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if challenge["session_id"] != "sess-1" {
		t.Fatalf("expected the ceremony session in the challenge, got %v", challenge["session_id"])
	}
	if _, ok := challenge["publicKey"]; !ok {
		t.Fatalf("expected publicKey at the top level, got %v", challenge)
	}
}

func TestDriverBeginFIDO2FailsWhenTheChallengeIsIncomplete(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	// A begin response with no options is the backbone promising a
	// challenge and not delivering one: a platform-side 500, not a 400.
	client := &fakeClient{begin: &quicbaas.BeginLoginResponse{SessionID: "sess-1"}}
	driver := newTestDriver(t, client, fido2)

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login/begin", nil), quicbaas.FactorTypeFIDO2)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDriverFinishFIDO2SubmitsTheCredentialIDAsTheLookupKey(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	client := &fakeClient{finish: finishResponse(t, "bearer-xyz", "refresh-xyz")}
	driver := newTestDriver(t, client, fido2)

	const credentialID = "Q1JFRC1JRA"
	request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(assertionBody(credentialID)))
	request.Header.Set(SessionIDHeader, "sess-1")

	recorder := httptest.NewRecorder()
	driver.Finish(recorder, request, quicbaas.FactorTypeFIDO2)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := string(client.finishReq.LookupKey); got != credentialID {
		t.Fatalf("expected the credential id as the lookup key, got %q", got)
	}
	if client.finishReq.SessionID != "sess-1" {
		t.Fatalf("expected the echoed ceremony session, got %q", client.finishReq.SessionID)
	}
	if len(client.finishReq.Signature) == 0 {
		t.Fatal("expected the assertion to ride in Signature as the proof")
	}
	// The client receives the PLATFORM's session credential. Handing back
	// "bearer-xyz" — the backbone's OIDC bearer — would return a token the
	// inbound seam on this same server rejects.
	body := recorder.Body.String()
	if !strings.Contains(body, "platform.session.token") {
		t.Fatalf("expected the platform session credential in the response, got %s", body)
	}
	if strings.Contains(body, "bearer-xyz") {
		t.Fatalf("the backbone bearer must not reach the client, got %s", body)
	}
}

func TestDriverFinishFIDO2RejectsAProofWithNoSessionOrCredentialID(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	client := &fakeClient{finish: finishResponse(t, "bearer-xyz", "refresh-xyz")}
	driver := newTestDriver(t, client, fido2)

	// No session header: the finish cannot be correlated with a begin.
	noSession := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(assertionBody("Q1JFRA")))
	recorder := httptest.NewRecorder()
	driver.Finish(recorder, noSession, quicbaas.FactorTypeFIDO2)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing session, got %d", recorder.Code)
	}

	// A well-formed JSON body that is not a credential carries no id to
	// resolve, so the ceremony must never be opened.
	noCredential := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(`{"type":"public-key"}`))
	noCredential.Header.Set(SessionIDHeader, "sess-1")
	recorder = httptest.NewRecorder()
	driver.Finish(recorder, noCredential, quicbaas.FactorTypeFIDO2)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing credential id, got %d", recorder.Code)
	}
	if client.finishCalls != 0 {
		t.Fatal("an unusable proof must not reach the backbone")
	}
}

func TestDriverFinishFIDO2RejectsAnOversizedProof(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a")
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	client := &fakeClient{}
	driver := newTestDriver(t, client, fido2)

	oversized := `{"id":"` + strings.Repeat("A", maxProofBytes) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(oversized))
	request.Header.Set(SessionIDHeader, "sess-1")

	recorder := httptest.NewRecorder()
	driver.Finish(recorder, request, quicbaas.FactorTypeFIDO2)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
	if client.finishCalls != 0 {
		t.Fatal("an oversized body must not reach the backbone")
	}
}

func TestDriverBeginMTLSCompletesInOneRequest(t *testing.T) {
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess-mtls"},
		finish: finishResponse(t, "bearer-mtls", ""),
	}
	driver := newTestDriver(t, client, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	// A single-shot factor runs the whole ceremony without a round trip.
	if client.beginCalls != 1 || client.finishCalls != 1 {
		t.Fatalf("expected one begin and one finish, got %d and %d", client.beginCalls, client.finishCalls)
	}
	if client.finishReq.SessionID != "sess-mtls" {
		t.Fatalf("expected the session the driver just opened, got %q", client.finishReq.SessionID)
	}
	if len(client.finishReq.Signature) != 0 {
		t.Fatal("mtls carries no signature: the handshake was the proof")
	}
	if !strings.Contains(recorder.Body.String(), "platform.session.token") {
		t.Fatalf("expected the platform session credential, got %s", recorder.Body.String())
	}
}

func TestDriverRefusesAnErrorFreeCeremonyWithNoBearer(t *testing.T) {
	// The defect this guards: treating a nil error as authentication. The
	// bearer is the only evidence the ceremony succeeded.
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess-mtls"},
		finish: finishResponse(t, "", ""),
	}
	driver := newTestDriver(t, client, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDriverRefusesWhenNoBackboneIsWired(t *testing.T) {
	// A deployment with no login client must deny, never mint anything.
	driver := newTestDriver(t, nil, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from Begin, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	driver.Finish(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from Finish, got %d", recorder.Code)
	}
}

func TestDriverReportsAnUnregisteredFactorAsAPlatformFault(t *testing.T) {
	driver := newTestDriver(t, &fakeClient{}, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login/begin", nil), quicbaas.FactorTypeFIDO2)

	// No binder is a wiring defect, so it must not read as a client error.
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDriverSurfacesBackboneRefusalsAsUnauthorized(t *testing.T) {
	beginFailure := &fakeClient{beginErr: errors.New("factor not found")}
	driver := newTestDriver(t, beginFailure, NewMTLSBinder())
	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when begin is refused, got %d", recorder.Code)
	}

	finishFailure := &fakeClient{
		begin:     &quicbaas.BeginLoginResponse{SessionID: "sess"},
		finishErr: errors.New("empty lookup key"),
	}
	driver = newTestDriver(t, finishFailure, NewMTLSBinder())
	recorder = httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when finish is refused, got %d", recorder.Code)
	}
}

func TestDriverRejectsABeginResponseThatIsNil(t *testing.T) {
	// A nil response with a nil error is the backbone violating its own
	// contract; the driver must not dereference it.
	driver := newTestDriver(t, &fakeClient{}, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestNewFIDO2BinderRequiresACeremonyTenant(t *testing.T) {
	// A WebAuthn assertion is only valid against its tenant's relying
	// party, so an unscoped binder must not exist.
	if _, err := NewFIDO2Binder(""); err == nil {
		t.Fatal("expected a missing-tenant error")
	}
	if _, err := NewFIDO2Binder("tenant-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMTLSBinderFinishRequiresTheDriversSession(t *testing.T) {
	binder := NewMTLSBinder()
	if _, err := binder.Finish(httptest.NewRequest(http.MethodPost, "/login", nil), ""); err == nil {
		t.Fatal("expected a missing-session error")
	}
	req, err := binder.Finish(httptest.NewRequest(http.MethodPost, "/login", nil), "sess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Type != quicbaas.FactorTypeMTLS {
		t.Fatalf("expected the mtls factor type, got %q", req.Type)
	}
}

func TestReadProofRejectsAnAbsentOrMalformedBody(t *testing.T) {
	if _, err := readProof(nil); err == nil {
		t.Fatal("expected an error for a nil body")
	}
	if _, err := readProof(strings.NewReader("not json")); err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
	if _, err := readProof(&failingReader{}); err == nil {
		t.Fatal("expected an error for an unreadable body")
	}
	if _, err := readProof(strings.NewReader(`{"id":"A"}`)); err != nil {
		t.Fatalf("unexpected error for a valid body: %v", err)
	}
}

// failingReader fails every read so the unreadable-body branch is covered
// without depending on a closed network connection.
type failingReader struct{}

func (r *failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// TestDriverIssuesTheSessionTheInboundSeamAccepts is the contract this
// package exists to hold: what reaches the client is the credential the
// PLATFORM minted from the identity the BACKBONE resolved — never the
// backbone's own bearer, which no seam on this server can validate.
func TestDriverIssuesTheSessionMintedFromTheResolvedIdentity(t *testing.T) {
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess-mtls"},
		finish: finishResponse(t, "bearer-mtls", "refresh-mtls"),
	}
	issuer := newTestIssuer()
	driver := newTestDriverWithIssuer(t, client, issuer, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if issuer.calls != 1 {
		t.Fatalf("expected exactly one session to be issued, got %d", issuer.calls)
	}
	// The issuer is handed the ceremony's identity and nothing the client
	// sent, which is what keeps issuance a projection of the backbone's
	// verdict rather than a second authentication.
	if issuer.identity == nil || issuer.identity.Subject != "operator@platform" {
		t.Fatalf("expected the resolved identity to reach the issuer, got %+v", issuer.identity)
	}
	if issuer.identity.TenantID != "tenant-a" {
		t.Fatalf("expected the identity tenant to reach the issuer, got %q", issuer.identity.TenantID)
	}

	var body struct {
		Payload Session `json:"payload"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Payload.Bearer != "platform.session.token" {
		t.Fatalf("expected the minted session credential, got %q", body.Payload.Bearer)
	}
	if !body.Payload.ExpiresAt.Equal(issuer.expiresAt) {
		t.Fatalf("expected the minted credential's expiry, got %s", body.Payload.ExpiresAt)
	}
	// The backbone's renewal credential renews the backbone's session, not
	// the one the client is holding, so it must not be forwarded.
	if strings.Contains(recorder.Body.String(), "refresh-mtls") {
		t.Fatalf("the backbone renewal credential must not reach the client, got %s", recorder.Body.String())
	}
}

// TestDriverRefusesABearerWithNoIdentity covers a ceremony that returns
// evidence of success without saying who succeeded. There is no principal
// to mint a session for, so the login is refused rather than answered with
// an anonymous credential.
func TestDriverRefusesABearerWithNoIdentity(t *testing.T) {
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess-mtls"},
		finish: finishResponseFor(t, "bearer-mtls", "", nil),
	}
	issuer := newTestIssuer()
	driver := newTestDriverWithIssuer(t, client, issuer, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if issuer.calls != 0 {
		t.Fatal("no session may be minted for an unresolved principal")
	}
}

// TestDriverReportsAFailedMintAsAPlatformFault covers the signer being
// unreachable after the ceremony has already authenticated the caller.
// The client proved possession correctly, so a 4xx would blame them for a
// platform-side failure.
func TestDriverReportsAFailedMintAsAPlatformFault(t *testing.T) {
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess-mtls"},
		finish: finishResponse(t, "bearer-mtls", ""),
	}
	issuer := newTestIssuer()
	issuer.err = errors.New("signer unavailable")
	driver := newTestDriverWithIssuer(t, client, issuer, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

// TestSessionIssueErrorUnwrapsItsCause keeps the issuance failure
// diagnosable: the operator needs the signer's own error, not just the
// platform's framing of it.
func TestSessionIssueErrorUnwrapsItsCause(t *testing.T) {
	cause := errors.New("signer unavailable")
	err := &SessionIssueError{Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected the cause to be unwrappable")
	}
	if !strings.Contains(err.Error(), "signer unavailable") {
		t.Fatalf("expected the cause in the message, got %q", err.Error())
	}
	if (&SessionIssueError{}).Error() == "" {
		t.Fatal("expected a message for a causeless issuance failure")
	}
}

func TestDriverRefusesAFinishResponseMissingItsCeremonyHalf(t *testing.T) {
	// The SDK response embeds the ceremony's own response by pointer; a
	// nil embed would panic on the expiry read, so it must be refused as
	// no bearer rather than dereferenced.
	client := &fakeClient{
		begin:  &quicbaas.BeginLoginResponse{SessionID: "sess"},
		finish: &quicbaas.FinishLoginResponse{RefreshToken: "refresh"},
	}
	driver := newTestDriver(t, client, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

// finishResponse builds a completed ceremony's response through the shared
// fixture helper, which exists because the promoted bearer lives on an
// embedded pointer this repository may not name (see logintest).
func finishResponse(t *testing.T, bearer, refresh string) *quicbaas.FinishLoginResponse {
	t.Helper()
	return finishResponseFor(t, bearer, refresh, logintest.AuthenticatedIdentity())
}

// finishResponseFor is finishResponse with the resolved identity stated,
// for the tests that are about the identity rather than the ceremony.
func finishResponseFor(
	t *testing.T, bearer, refresh string, identity *logintest.Identity) *quicbaas.FinishLoginResponse {

	t.Helper()
	response, err := logintest.FinishResponse(
		bearer, refresh,
		time.Unix(1700000000, 0).UTC(),
		time.Unix(1700086400, 0).UTC(),
		identity)
	if err != nil {
		t.Fatalf("build finish response: %v", err)
	}
	return response
}
