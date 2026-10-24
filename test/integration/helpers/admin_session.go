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

//go:build integration

package helpers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The harness reaches the admin-gated webservice routes with a console
// session the platform itself issues. The admin claim flow (docs/auth/
// architecture.md §6b) proves the first-boot admin bundle, registers a
// passkey through the software authenticator and returns the bearer; the
// session is cached in a file so the sequential suite processes of one
// harness run share it, and is refreshed before it expires.
const (
	// EnvAdminBundleDir names the directory holding the first-boot admin
	// bundle (admin.crt, admin.key).
	EnvAdminBundleDir = "PLATFORM_ADMIN_BUNDLE_DIR"
	// EnvAdminSessionFile names the file the claimed session is cached in.
	EnvAdminSessionFile = "PLATFORM_ADMIN_SESSION_FILE"

	defaultAdminBundleDir   = "/tmp/platformd-integration/quicbaas/admin"
	defaultAdminSessionFile = "/tmp/platformd-integration/admin-session.json"

	adminCertFile = "admin.crt"
	adminKeyFile  = "admin.key"

	// adminRefreshMargin is how much lifetime a cached bearer must have
	// left to be used as is; below it the bearer is refreshed.
	adminRefreshMargin = 30 * time.Minute
	// adminClaimTimeout bounds each claim and refresh request.
	adminClaimTimeout = 30 * time.Second
	// adminResponseLimit caps the response bodies the session reads.
	adminResponseLimit = 1 << 20

	adminClaimPath     = "/api/v1/admin/claim"
	adminStatusPath    = adminClaimPath + "/status"
	adminChallengePath = adminClaimPath + "/challenge"
	adminVerifyPath    = adminClaimPath + "/verify"
	adminBeginPath     = adminClaimPath + "/passkey/begin"
	adminFinishPath    = adminClaimPath + "/passkey/finish"
	adminRefreshPath   = "/api/v1/login/refresh"

	adminClaimTokenHeader = "X-Admin-Claim"
	adminSessionIDHeader  = "X-Session-Id"
)

// Claim steps named in ErrAdminClaimStep.
const (
	AdminStepStatus    = "status"
	AdminStepChallenge = "challenge"
	AdminStepSign      = "sign"
	AdminStepVerify    = "verify"
	AdminStepBegin     = "passkey begin"
	AdminStepRegister  = "passkey register"
	AdminStepFinish    = "passkey finish"
	AdminStepRefresh   = "refresh"
)

// ErrAdminClaimStep reports the claim or refresh step that failed. Status
// and Body carry the server's answer when the step reached it; Cause the
// local failure otherwise.
type ErrAdminClaimStep struct {
	Step   string
	Status int
	Body   string
	Cause  error
}

// Error implements the error interface.
func (e ErrAdminClaimStep) Error() string {
	if e.Cause != nil {
		return "admin session: " + e.Step + ": " + e.Cause.Error()
	}
	return "admin session: " + e.Step + ": HTTP " + strconv.Itoa(e.Status) + ": " + e.Body
}

// Unwrap returns the underlying cause.
func (e ErrAdminClaimStep) Unwrap() error { return e.Cause }

// SetupProbeFailure describes a failed adapter Setup probe made through
// NewAdminHTTPClient. When the admin session could not be opened the
// endpoint did answer, so the message names the claim step that failed
// instead of calling the endpoint unreachable.
func SetupProbeFailure(err error) string {
	var step ErrAdminClaimStep
	if errors.As(err, &step) {
		return step.Error()
	}
	return "endpoint not reachable: " + err.Error()
}

// ErrAdminBundleUnreadable reports that the first-boot admin bundle could
// not be loaded.
type ErrAdminBundleUnreadable struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrAdminBundleUnreadable) Error() string {
	return "admin session: admin bundle " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrAdminBundleUnreadable) Unwrap() error { return e.Cause }

// ErrAdminAlreadyClaimed reports that the platform admin is claimed but
// this harness holds no usable session for it: the claim closes once it
// completes, so only a cached session can reach the admin routes.
type ErrAdminAlreadyClaimed struct {
	SessionFile string
	Cause       error
}

// Error implements the error interface.
func (e ErrAdminAlreadyClaimed) Error() string {
	message := "admin session: the platform admin is already claimed and " + e.SessionFile + " holds no usable session"
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

// Unwrap returns the underlying cause.
func (e ErrAdminAlreadyClaimed) Unwrap() error { return e.Cause }

// ErrAdminSessionCache reports that the session cache file could not be
// read or written.
type ErrAdminSessionCache struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrAdminSessionCache) Error() string {
	return "admin session: session cache " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrAdminSessionCache) Unwrap() error { return e.Cause }

// ErrAdminTokenMalformed reports a bearer whose expiry cannot be read.
type ErrAdminTokenMalformed struct {
	Reason string
}

// Error implements the error interface.
func (e ErrAdminTokenMalformed) Error() string {
	return "admin session: malformed bearer: " + e.Reason
}

// ErrUnsupportedAdminKey reports an admin key type the claim proof does
// not sign with.
type ErrUnsupportedAdminKey struct {
	Type string
}

// Error implements the error interface.
func (e ErrUnsupportedAdminKey) Error() string {
	return "admin session: unsupported admin key type " + e.Type
}

// AdminSession holds the harness's platform admin bearer: it claims the
// admin once, caches the session and refreshes it before it expires.
type AdminSession struct {
	baseURL     string
	bundleDir   string
	sessionFile string
	client      *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	// claimToken is a proved claim the daemon has not spent yet. Only the
	// passkey finish step spends one, so a claim that stopped at begin is
	// reused by the next attempt instead of proving a new one: every proof
	// holds a daemon claim secret for its whole TTL, and a suite that
	// retries on each failure would otherwise exhaust the daemon's cap.
	claimToken          string
	claimTokenExpiresAt time.Time
}

// NewAdminSession returns a session against the webservice at baseURL,
// proving the admin bundle in bundleDir and caching in sessionFile. client
// must trust the webservice's certificate.
func NewAdminSession(baseURL, bundleDir, sessionFile string, client *http.Client) *AdminSession {
	return &AdminSession{
		baseURL:     strings.TrimSuffix(baseURL, "/"),
		bundleDir:   bundleDir,
		sessionFile: sessionFile,
		client:      client,
	}
}

var (
	harnessAdminSessionOnce sync.Once
	harnessAdminSession     *AdminSession
)

// HarnessAdminSession is the process-wide session against the harness
// webservice, configured from PLATFORM_REST_ENDPOINT,
// PLATFORM_ADMIN_BUNDLE_DIR and PLATFORM_ADMIN_SESSION_FILE.
func HarnessAdminSession() *AdminSession {
	harnessAdminSessionOnce.Do(func() {
		harnessAdminSession = NewAdminSession(
			RESTBaseURL(GetRESTEndpoint()),
			envOrDefault(EnvAdminBundleDir, defaultAdminBundleDir),
			envOrDefault(EnvAdminSessionFile, defaultAdminSessionFile),
			NewHTTPClient(adminClaimTimeout),
		)
	})
	return harnessAdminSession
}

// Bearer returns a platform admin bearer with at least the refresh margin
// of lifetime left, claiming or refreshing as needed. The flow runs
// without ctx's cancellation: a claim stopped half way spends the
// one-time claim token and could not be retried.
func (s *AdminSession) Bearer(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx = context.WithoutCancel(ctx)

	if s.token == "" {
		if err := s.loadCache(); err != nil {
			return "", err
		}
	}
	now := time.Now()
	if s.token != "" && s.expiresAt.Sub(now) > adminRefreshMargin {
		return s.token, nil
	}

	var refreshErr error
	if s.token != "" && s.expiresAt.After(now) {
		token, err := s.refresh(ctx)
		if err == nil {
			return token, s.store(token)
		}
		refreshErr = err
	}

	claimed, err := s.claimed(ctx)
	if err != nil {
		return "", err
	}
	if claimed {
		return "", ErrAdminAlreadyClaimed{SessionFile: s.sessionFile, Cause: refreshErr}
	}
	token, err := s.claim(ctx)
	if err != nil {
		return "", err
	}
	return token, s.store(token)
}

// adminSessionCache is the session file's content. The base URL keeps a
// session from one webservice being offered to another.
type adminSessionCache struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
}

// loadCache reads the cached session, if one exists for this webservice.
func (s *AdminSession) loadCache() error {
	raw, err := os.ReadFile(s.sessionFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	var cache adminSessionCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	if cache.BaseURL != s.baseURL || cache.Token == "" {
		return nil
	}
	expiresAt, err := bearerExpiry(cache.Token)
	if err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	s.token, s.expiresAt = cache.Token, expiresAt
	return nil
}

// store keeps token in memory and writes it to the session file
// atomically, readable by the owner only.
func (s *AdminSession) store(token string) error {
	expiresAt, err := bearerExpiry(token)
	if err != nil {
		return err
	}
	s.token, s.expiresAt = token, expiresAt

	raw, err := json.Marshal(adminSessionCache{BaseURL: s.baseURL, Token: token})
	if err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	temp, err := os.CreateTemp(filepath.Dir(s.sessionFile), ".admin-session-*")
	if err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	if err := writeAndClose(temp, raw); err != nil {
		if removeErr := os.Remove(temp.Name()); removeErr != nil {
			return ErrAdminSessionCache{Path: s.sessionFile, Cause: errors.Join(err, removeErr)}
		}
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	if err := os.Rename(temp.Name(), s.sessionFile); err != nil {
		return ErrAdminSessionCache{Path: s.sessionFile, Cause: err}
	}
	return nil
}

// writeAndClose writes raw to file and closes it. CreateTemp already made
// the file mode 0600.
func writeAndClose(file *os.File, raw []byte) error {
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

// bearerExpiry reads the exp claim of a JWT bearer. The signature is not
// checked: the expiry only schedules the refresh, and the server verifies
// every bearer it is sent.
func bearerExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, ErrAdminTokenMalformed{Reason: "not a three-part JWT"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, ErrAdminTokenMalformed{Reason: "payload is not base64url: " + err.Error()}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, ErrAdminTokenMalformed{Reason: "payload is not JSON: " + err.Error()}
	}
	if claims.Exp == 0 {
		return time.Time{}, ErrAdminTokenMalformed{Reason: "no exp claim"}
	}
	return time.Unix(claims.Exp, 0), nil
}

// refresh exchanges the current bearer for a fresh one.
func (s *AdminSession) refresh(ctx context.Context) (string, error) {
	var token string
	header := http.Header{"Authorization": {"Bearer " + s.token}}
	if err := s.callEnveloped(ctx, AdminStepRefresh, http.MethodGet, adminRefreshPath, header, nil, &token); err != nil {
		return "", err
	}
	return token, nil
}

// claimed reports whether the platform admin has been claimed.
func (s *AdminSession) claimed(ctx context.Context) (bool, error) {
	var status struct {
		Claimed bool `json:"claimed"`
	}
	if err := s.callEnveloped(ctx, AdminStepStatus, http.MethodGet, adminStatusPath, nil, nil, &status); err != nil {
		return false, err
	}
	return status.Claimed, nil
}

// claim runs the admin claim flow (docs/auth/architecture.md §6b): prove
// the admin bundle with a signed challenge, register a passkey with the
// software authenticator, and take the console session the finish step
// issues.
func (s *AdminSession) claim(ctx context.Context) (string, error) {
	claimToken, err := s.proveClaim(ctx)
	if err != nil {
		return "", err
	}

	claimHeader := http.Header{adminClaimTokenHeader: {claimToken}}
	// The begin step answers with the bare CredentialCreation, not the
	// response envelope, so the browser API can take it as is.
	beginRaw, err := s.call(ctx, AdminStepBegin, http.MethodPost, adminBeginPath, claimHeader, nil)
	if err != nil {
		// Begin only reads the claim; it stays reusable unless the daemon
		// refused it (403), as a restarted daemon does.
		var stepErr ErrAdminClaimStep
		if errors.As(err, &stepErr) && stepErr.Status == http.StatusForbidden {
			s.claimToken = ""
		}
		return "", err
	}
	var options creationOptions
	if err := json.Unmarshal(beginRaw, &options); err != nil {
		return "", ErrAdminClaimStep{Step: AdminStepBegin, Cause: err}
	}

	authenticator, err := newSoftwareAuthenticator()
	if err != nil {
		return "", ErrAdminClaimStep{Step: AdminStepRegister, Cause: err}
	}
	registration, err := authenticator.register(options, s.baseURL)
	if err != nil {
		return "", ErrAdminClaimStep{Step: AdminStepRegister, Cause: err}
	}

	// Finish spends the claim whatever its outcome, so it is never offered
	// to the daemon again.
	s.claimToken = ""
	finishHeader := http.Header{
		adminClaimTokenHeader: {claimToken},
		adminSessionIDHeader:  {options.SessionID},
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := s.callEnveloped(ctx, AdminStepFinish, http.MethodPost, adminFinishPath, finishHeader, registration, &session); err != nil {
		return "", err
	}
	return session.Token, nil
}

// proveClaim returns the unspent claim token from an earlier attempt while
// it has at least adminClaimTimeout of life left, and otherwise proves
// possession of the admin key (challenge, sign, verify) for a new one.
func (s *AdminSession) proveClaim(ctx context.Context) (string, error) {
	if s.claimToken != "" && time.Until(s.claimTokenExpiresAt) > adminClaimTimeout {
		return s.claimToken, nil
	}
	s.claimToken = ""

	certPEM, signer, err := s.loadBundle()
	if err != nil {
		return "", err
	}

	var challenge struct {
		Challenge string `json:"challenge"`
	}
	if err := s.callEnveloped(ctx, AdminStepChallenge, http.MethodPost, adminChallengePath, nil, []byte("{}"), &challenge); err != nil {
		return "", err
	}
	signature, err := signAdminChallenge(signer, challenge.Challenge)
	if err != nil {
		return "", ErrAdminClaimStep{Step: AdminStepSign, Cause: err}
	}
	verifyBody, err := json.Marshal(struct {
		Challenge      string `json:"challenge"`
		CertificatePEM string `json:"certificate_pem"`
		Signature      []byte `json:"signature"`
	}{challenge.Challenge, string(certPEM), signature})
	if err != nil {
		return "", ErrAdminClaimStep{Step: AdminStepVerify, Cause: err}
	}
	var verified struct {
		ClaimToken string    `json:"claim_token"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	if err := s.callEnveloped(ctx, AdminStepVerify, http.MethodPost, adminVerifyPath, nil, verifyBody, &verified); err != nil {
		return "", err
	}
	s.claimToken = verified.ClaimToken
	s.claimTokenExpiresAt = verified.ExpiresAt
	return verified.ClaimToken, nil
}

// loadBundle reads the admin certificate PEM and its private key.
func (s *AdminSession) loadBundle() ([]byte, crypto.Signer, error) {
	certPath := filepath.Join(s.bundleDir, adminCertFile)
	keyPath := filepath.Join(s.bundleDir, adminKeyFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, ErrAdminBundleUnreadable{Path: certPath, Cause: err}
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, ErrAdminBundleUnreadable{Path: keyPath, Cause: err}
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, ErrAdminBundleUnreadable{Path: s.bundleDir, Cause: err}
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, ErrAdminBundleUnreadable{Path: keyPath, Cause: ErrUnsupportedAdminKey{Type: "non-signer"}}
	}
	// Send the leaf only, as PEM, whatever else the file carries.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	return leafPEM, signer, nil
}

// signAdminChallenge signs the challenge string as the claim service
// verifies it: Ed25519 over the message itself, ECDSA and RSA over its
// SHA-256 digest.
func signAdminChallenge(signer crypto.Signer, challenge string) ([]byte, error) {
	message := []byte(challenge)
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		return signer.Sign(rand.Reader, message, crypto.Hash(0))
	}
	digest := sha256.Sum256(message)
	return signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// callEnveloped calls the webservice and decodes the payload of its
// response envelope into out.
func (s *AdminSession) callEnveloped(ctx context.Context, step, method, path string, header http.Header, body []byte, out any) error {
	raw, err := s.call(ctx, step, method, path, header, body)
	if err != nil {
		return err
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return ErrAdminClaimStep{Step: step, Cause: err}
	}
	if err := json.Unmarshal(envelope.Payload, out); err != nil {
		return ErrAdminClaimStep{Step: step, Cause: err}
	}
	return nil
}

// call sends one request and returns the body of a 200 answer; any other
// status becomes an ErrAdminClaimStep carrying the server's body.
func (s *AdminSession) call(ctx context.Context, step, method, path string, header http.Header, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return nil, ErrAdminClaimStep{Step: step, Cause: err}
	}
	for name, values := range header {
		req.Header[name] = values
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ErrAdminClaimStep{Step: step, Cause: err}
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, adminResponseLimit))
	closeErr := resp.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, ErrAdminClaimStep{Step: step, Status: resp.StatusCode, Cause: err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ErrAdminClaimStep{Step: step, Status: resp.StatusCode, Body: string(raw)}
	}
	return raw, nil
}

// adminBearerTransport adds the harness admin bearer to every request that
// carries no Authorization header of its own.
type adminBearerTransport struct {
	session *AdminSession
	base    http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *adminBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(req)
	}
	token, err := t.session.Bearer(req.Context())
	if err != nil {
		if req.Body != nil {
			if closeErr := req.Body.Close(); closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
		return nil, err
	}
	authorized := req.Clone(req.Context())
	authorized.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(authorized)
}

// NewAdminHTTPClient is NewHTTPClient for the admin-gated webservice
// routes: it presents the harness client certificate and the harness
// admin bearer. A failed claim surfaces as the request's error, naming the
// step and the server's answer.
func NewAdminHTTPClient(timeout time.Duration) *http.Client {
	client := NewHTTPClient(timeout)
	client.Transport = &adminBearerTransport{session: HarnessAdminSession(), base: client.Transport}
	return client
}
