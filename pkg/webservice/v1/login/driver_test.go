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

// singleShotBinder is a working single-shot factor for tests.
//
// The driver's single-shot path — Begin runs the whole ceremony because
// Challenge returns nil — needs a binder that completes, and the real mtls
// binder deliberately declines (see mtls.go). Testing the path through a
// factor that refuses would test the refusal twice and the path never, so
// the shape gets its own fixture and mtls gets its own test.
type singleShotBinder struct{}

func (b *singleShotBinder) Type() quicbaas.FactorType { return quicbaas.FactorTypePIV }

func (b *singleShotBinder) Begin(*http.Request) (quicbaas.BeginLoginRequest, error) {
	return quicbaas.BeginLoginRequest{Type: quicbaas.FactorTypePIV}, nil
}

// Challenge returns nil, which is what makes this factor single-shot.
func (b *singleShotBinder) Challenge(*quicbaas.BeginLoginResponse) (any, error) {
	return nil, nil
}

func (b *singleShotBinder) Finish(_ *http.Request, sessionID string) (quicbaas.FinishLoginRequest, error) {
	if sessionID == "" {
		return quicbaas.FinishLoginRequest{}, &MissingSessionError{}
	}
	return quicbaas.FinishLoginRequest{SessionID: sessionID, Type: quicbaas.FactorTypePIV}, nil
}

// Tenant lands the session in the tenant the ceremony ran in, so the
// driver's other paths can be tested without a workspace in the way.
func (b *singleShotBinder) Tenant(_ context.Context, identity *quicbaas.Identity) (string, error) {
	return identity.TenantID, nil
}

// fakeWorkspaces stands in for the platform's tenant service. It records
// the subject it was asked about, so a test can assert the workspace was
// resolved for the principal the BACKBONE authenticated.
type fakeWorkspaces struct {
	subject   string
	workspace string
	err       error
}

func (f *fakeWorkspaces) Workspace(_ context.Context, subject string) (string, error) {
	f.subject = subject
	return f.workspace, f.err
}

func newTestWorkspaces() *fakeWorkspaces {
	return &fakeWorkspaces{workspace: "workspace-a"}
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

func TestDriverBeginFIDO2IssuesAUsernamelessChallenge(t *testing.T) {
	fido2, err := NewFIDO2Binder("tenant-a", newTestWorkspaces())
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
	fido2, err := NewFIDO2Binder("tenant-a", newTestWorkspaces())
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
	fido2, err := NewFIDO2Binder("tenant-a", newTestWorkspaces())
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
	fido2, err := NewFIDO2Binder("tenant-a", newTestWorkspaces())
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
	fido2, err := NewFIDO2Binder("tenant-a", newTestWorkspaces())
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
	driver := newTestDriver(t, client, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

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
	driver := newTestDriver(t, client, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDriverRefusesWhenNoBackboneIsWired(t *testing.T) {
	// A deployment with no login client must deny, never mint anything.
	driver := newTestDriver(t, nil, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from Begin, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	driver.Finish(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)
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
	driver := newTestDriver(t, beginFailure, &singleShotBinder{})
	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when begin is refused, got %d", recorder.Code)
	}

	finishFailure := &fakeClient{
		begin:     &quicbaas.BeginLoginResponse{SessionID: "sess"},
		finishErr: errors.New("empty lookup key"),
	}
	driver = newTestDriver(t, finishFailure, &singleShotBinder{})
	recorder = httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when finish is refused, got %d", recorder.Code)
	}
}

func TestDriverRejectsABeginResponseThatIsNil(t *testing.T) {
	// A nil response with a nil error is the backbone violating its own
	// contract; the driver must not dereference it.
	driver := newTestDriver(t, &fakeClient{}, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestNewFIDO2BinderRequiresACeremonyTenant(t *testing.T) {
	// A WebAuthn assertion is only valid against its tenant's relying
	// party, so an unscoped binder must not exist.
	if _, err := NewFIDO2Binder("", newTestWorkspaces()); err == nil {
		t.Fatal("expected a missing-tenant error")
	}
	// And without a resolver the only tenant it could land a session in
	// is the ceremony's, which a browser login never lands in (#662).
	var config *DriverConfigError
	if _, err := NewFIDO2Binder("tenant-a", nil); !errors.As(err, &config) {
		t.Fatalf("expected a missing-resolver DriverConfigError, got %v", err)
	}
	if _, err := NewFIDO2Binder("tenant-a", newTestWorkspaces()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMTLSBinderDeclinesTheCeremonyItCannotBind pins the refusal in
// mtls.go, and pins it on BOTH verbs.
//
// The platform cannot bind the caller's peer certificate to the ceremony
// through sdk/go (jeremyhahn/go-quicbaas#857). Opening one anyway is not
// merely useless: the SDK client can run in remote transport mode, where
// the backbone reads the verified peer certificate off the connection it
// actually sees — platformd's — and would resolve whatever identity THAT
// certificate is enrolled as, for an unauthenticated caller of /login. On
// the embedded transport the same request is only refused for an empty
// lookup key, so nothing reveals the hole until the daemon is pointed at a
// remote control plane.
//
// So the binder refuses before anything reaches the backbone, and it
// refuses on Finish too: a binder whose safety depends on the driver
// calling Begin first is a binder whose safety lives somewhere else.
func TestMTLSBinderDeclinesTheCeremonyItCannotBind(t *testing.T) {
	binder := NewMTLSBinder()
	request := httptest.NewRequest(http.MethodPost, "/login", nil)

	var unavailable *FactorUnavailableError

	_, err := binder.Begin(request)
	if !errors.As(err, &unavailable) {
		t.Fatalf("Begin: expected FactorUnavailableError, got %v", err)
	}
	if unavailable.Type != quicbaas.FactorTypeMTLS {
		t.Fatalf("expected the mtls factor named, got %q", unavailable.Type)
	}
	if !strings.Contains(unavailable.Reason, "857") {
		t.Fatalf("the refusal must name what would lift it, got %q", unavailable.Reason)
	}

	// Both sessionID states, so the refusal cannot be mistaken for the
	// missing-session check this verb used to perform.
	for _, sessionID := range []string{"", "sess"} {
		if _, err := binder.Finish(request, sessionID); !errors.As(err, &unavailable) {
			t.Fatalf("Finish(%q): expected FactorUnavailableError, got %v", sessionID, err)
		}
	}
	if _, err := binder.Tenant(context.Background(), &quicbaas.Identity{Subject: "operator@platform"}); !errors.As(err, &unavailable) {
		t.Fatalf("Tenant: expected FactorUnavailableError, got %v", err)
	}
}

// TestDriverAnswersADeclinedFactorWithForbidden pins the status the route
// returns: the surface exists and is closed, which is 403 — not a 4xx that
// blames a caller whose certificate was fine, and not a 500 that reads as
// a platform defect someone should go hunting for.
func TestDriverAnswersADeclinedFactorWithForbidden(t *testing.T) {
	client := &fakeClient{}
	driver := newTestDriver(t, client, NewMTLSBinder())

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypeMTLS)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if client.beginCalls != 0 {
		t.Fatal("a declined factor must not open a ceremony on the backbone")
	}
	if client.finishCalls != 0 {
		t.Fatal("a declined factor must not reach FinishLogin")
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
	driver := newTestDriverWithIssuer(t, client, issuer, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

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
	driver := newTestDriverWithIssuer(t, client, issuer, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

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
	driver := newTestDriverWithIssuer(t, client, issuer, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

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
	driver := newTestDriver(t, client, &singleShotBinder{})

	recorder := httptest.NewRecorder()
	driver.Begin(recorder, httptest.NewRequest(http.MethodPost, "/login", nil), quicbaas.FactorTypePIV)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

// finishFIDO2 runs a browser login's finish leg against a FIDO2 binder
// whose ceremony tenant is "tenant-a" — the operating tenant the backbone's
// identity names — and the given workspace resolver.
func finishFIDO2(t *testing.T, issuer *fakeIssuer, workspaces WorkspaceResolver) (*httptest.ResponseRecorder, *fakeClient) {
	t.Helper()
	return finishFIDO2WithRoles(t, issuer, workspaces, nil)
}

// finishFIDO2WithRoles completes a fido2 ceremony on a driver whose
// workspace sessions take their roles from roles (nil: none wired).
func finishFIDO2WithRoles(
	t *testing.T, issuer *fakeIssuer, workspaces WorkspaceResolver, roles RoleResolver) (*httptest.ResponseRecorder, *fakeClient) {

	t.Helper()
	fido2, err := NewFIDO2Binder("tenant-a", workspaces)
	if err != nil {
		t.Fatalf("NewFIDO2Binder: %v", err)
	}
	client := &fakeClient{finish: finishResponse(t, "bearer-xyz", "refresh-xyz")}
	logger, writer := testDeps()
	driver, err := NewDriver(DriverParams{
		Client:         client,
		Binders:        []Binder{fido2},
		SessionIssuer:  issuer,
		Roles:          roles,
		Logger:         logger,
		ResponseWriter: writer,
	})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(assertionBody("Q1JFRC1JRA")))
	request.Header.Set(SessionIDHeader, "sess-1")
	recorder := httptest.NewRecorder()
	driver.Finish(recorder, request, quicbaas.FactorTypeFIDO2)
	return recorder, client
}

func TestDriverLandsABrowserLoginInThePrincipalsWorkspace(t *testing.T) {
	issuer := newTestIssuer()
	workspaces := newTestWorkspaces()

	recorder, client := finishFIDO2(t, issuer, workspaces)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if workspaces.subject != "operator@platform" {
		t.Fatalf("expected the workspace of the authenticated principal, got %q", workspaces.subject)
	}
	// The backbone names the operating tenant the ceremony ran in; the
	// session must name the principal's workspace instead (#662).
	if issuer.identity == nil || issuer.identity.TenantID != "workspace-a" {
		t.Fatalf("expected the session minted in the workspace, got %+v", issuer.identity)
	}
	if issuer.identity.Subject != "operator@platform" {
		t.Fatalf("expected the backbone's subject kept, got %q", issuer.identity.Subject)
	}
	if client.finish.Identity.TenantID != "tenant-a" {
		t.Fatalf("the backbone's answer must not be edited in place, got %q", client.finish.Identity.TenantID)
	}
}

func TestDriverRefusesABrowserLoginWithNoWorkspace(t *testing.T) {
	notInTenant := errors.New("user not in tenant")
	cases := []struct {
		name       string
		workspaces *fakeWorkspaces
	}{
		{name: "resolver fails", workspaces: &fakeWorkspaces{err: notInTenant}},
		{name: "no workspace", workspaces: &fakeWorkspaces{}},
		{name: "workspace is the operating tenant", workspaces: &fakeWorkspaces{workspace: "tenant-a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newTestIssuer()

			recorder, _ := finishFIDO2(t, issuer, tc.workspaces)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
			}
			// Never a fallback: no session at all rather than one in the
			// operating tenant.
			if issuer.calls != 0 {
				t.Fatalf("no session may be minted without a workspace, got %+v", issuer.identity)
			}
			if strings.Contains(recorder.Body.String(), "platform.session.token") {
				t.Fatalf("no credential may reach the client, got %s", recorder.Body.String())
			}
		})
	}
}

func TestNoWorkspaceErrorNamesThePrincipalAndUnwrapsItsCause(t *testing.T) {
	cause := errors.New("user not in tenant")
	err := &NoWorkspaceError{Subject: "ann@example.com", Cause: cause}

	if !errors.Is(err, cause) {
		t.Fatal("expected the resolver's failure to unwrap")
	}
	if !strings.Contains(err.Error(), "ann@example.com") || !strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("expected the principal and the cause in the message, got %q", err.Error())
	}
	bare := &NoWorkspaceError{Subject: "ann@example.com"}
	if bare.Unwrap() != nil || strings.HasSuffix(bare.Error(), ": ") {
		t.Fatalf("expected a causeless message, got %q", bare.Error())
	}
}

// fakeRoles answers one principal's roles in a workspace and records the
// question it was asked.
type fakeRoles struct {
	tenantID string
	subject  string
	roles    []string
	err      error
}

func (f *fakeRoles) Roles(_ context.Context, tenantID, subject string) ([]string, error) {
	f.tenantID = tenantID
	f.subject = subject
	return f.roles, f.err
}

// TestDriverGivesAWorkspaceSessionTheWorkspaceRolesOnly is the regression
// test for the escalation Codex found on #891: the backbone resolves the
// principal in the operating tenant, where they are an admin, and the
// session lands in their workspace, where they are a member. The session
// must carry the member role, not the operating tenant's admin.
func TestDriverGivesAWorkspaceSessionTheWorkspaceRolesOnly(t *testing.T) {
	issuer := newTestIssuer()
	roles := &fakeRoles{roles: []string{"member"}}

	recorder, client := finishFIDO2WithRoles(t, issuer, newTestWorkspaces(), roles)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if roles.tenantID != "workspace-a" || roles.subject != "operator@platform" {
		t.Fatalf("expected the roles of operator@platform in workspace-a, asked for %q in %q",
			roles.subject, roles.tenantID)
	}
	if got := issuer.identity.Roles; len(got) != 1 || got[0] != "member" {
		t.Fatalf("expected the workspace roles [member] and nothing else, got %v", got)
	}
	if got := client.finish.Identity.Roles; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("the backbone's answer must not be edited in place, got %v", got)
	}
}

// TestDriverGivesAWorkspaceSessionNoRolesWithoutAResolver proves the
// fallback is the ordinary member, never the operating tenant's admin.
func TestDriverGivesAWorkspaceSessionNoRolesWithoutAResolver(t *testing.T) {
	issuer := newTestIssuer()

	recorder, _ := finishFIDO2(t, issuer, newTestWorkspaces())

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(issuer.identity.Roles) != 0 {
		t.Fatalf("expected no roles in the workspace, got %v", issuer.identity.Roles)
	}
}

// TestDriverRefusesAWorkspaceSessionWhoseRolesCannotBeResolved: a failing
// resolver refuses the session as a platform fault, and nothing is minted.
func TestDriverRefusesAWorkspaceSessionWhoseRolesCannotBeResolved(t *testing.T) {
	issuer := newTestIssuer()
	roles := &fakeRoles{err: errors.New("iam unreachable")}

	recorder, _ := finishFIDO2WithRoles(t, issuer, newTestWorkspaces(), roles)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if issuer.calls != 0 {
		t.Fatalf("no session may be minted without the workspace roles, got %d", issuer.calls)
	}
}

func TestWorkspaceRolesErrorNamesThePrincipalAndUnwrapsItsCause(t *testing.T) {
	cause := errors.New("iam unreachable")
	err := &WorkspaceRolesError{TenantID: "workspace-a", Subject: "operator@platform", Cause: cause}

	if !errors.Is(err, cause) {
		t.Fatalf("expected the cause to unwrap")
	}
	for _, want := range []string{"operator@platform", "workspace-a", "iam unreachable"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in %q", want, err.Error())
		}
	}
	bare := &WorkspaceRolesError{TenantID: "workspace-a", Subject: "operator@platform"}
	want := "login: the roles of operator@platform in workspace workspace-a could not be resolved"
	if bare.Error() != want {
		t.Fatalf("expected %q, got %q", want, bare.Error())
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
