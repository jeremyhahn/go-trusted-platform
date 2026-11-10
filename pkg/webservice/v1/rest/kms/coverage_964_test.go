package kms

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// covErr is the typed SDK error the coverage fakes return. Its text drives
// the status mapping in Handlers.fail.
type covErr string

func (e covErr) Error() string { return string(e) }

var covTime = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// covKMS records the requests the key handlers send and returns err when set.
type covKMS struct {
	kmsclient.Client
	err       error
	importReq *kmsclient.ImportKeyRequest
	statusReq *kmsclient.UpdateKeyStatusRequest
	keyID     string
}

func (f *covKMS) ImportKey(_ context.Context, req *kmsclient.ImportKeyRequest) (*kmsclient.ImportKeyResponse, error) {
	f.importReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &kmsclient.ImportKeyResponse{KeyID: "imported", Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *covKMS) ListKeys(_ context.Context) (*kmsclient.ListKeysResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &kmsclient.ListKeysResponse{Keys: []kmsclient.KeyInfo{{
		KeyID: "k1", Name: "one", Algorithm: kmsclient.AlgorithmRSA2048, Version: 2,
		Usage: []kmsclient.KeyUsage{kmsclient.KeyUsageSign}, CreatedAt: covTime, RotatedAt: covTime,
	}}}, nil
}

func (f *covKMS) GetKey(_ context.Context, keyID string) (*kmsclient.KeyInfo, error) {
	f.keyID = keyID
	if f.err != nil {
		return nil, f.err
	}
	return &kmsclient.KeyInfo{
		KeyID: keyID, Name: "named", Algorithm: kmsclient.AlgorithmED25519, Version: 3,
		Usage: []kmsclient.KeyUsage{kmsclient.KeyUsageSign, kmsclient.KeyUsageVerify},
	}, nil
}

func (f *covKMS) DeleteKey(_ context.Context, keyID string) error {
	f.keyID = keyID
	return f.err
}

func (f *covKMS) UpdateKeyStatus(_ context.Context, req *kmsclient.UpdateKeyStatusRequest) (*kmsclient.UpdateKeyStatusResponse, error) {
	f.statusReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &kmsclient.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
}

func (f *covKMS) ListKeyVersions(_ context.Context, keyID string) (*kmsclient.ListKeyVersionsResponse, error) {
	f.keyID = keyID
	if f.err != nil {
		return nil, f.err
	}
	return &kmsclient.ListKeyVersionsResponse{KeyID: keyID, Versions: []kmsclient.KeyVersionInfo{
		{Version: 1, Status: kmsclient.KeyStatusDisabled, Algorithm: kmsclient.AlgorithmAES256GCM, CreatedAt: covTime, DisabledAt: covTime},
		{Version: 2, Status: kmsclient.KeyStatusEnabled, Algorithm: kmsclient.AlgorithmAES256GCM, CreatedAt: covTime},
	}}, nil
}

// covCrypto records the requests the crypto handlers send.
type covCrypto struct {
	cryptoclient.Client
	err       error
	verify    *cryptoclient.VerifyRequest
	hmac      *cryptoclient.GenerateHMACRequest
	verifyMAC *cryptoclient.VerifyHMACRequest
	hash      *cryptoclient.HashRequest
	random    *cryptoclient.GenerateRandomRequest
}

func (f *covCrypto) Verify(_ context.Context, req *cryptoclient.VerifyRequest) (*cryptoclient.VerifyResponse, error) {
	f.verify = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.VerifyResponse{Valid: true}, nil
}

func (f *covCrypto) GenerateHMAC(_ context.Context, req *cryptoclient.GenerateHMACRequest) (*cryptoclient.GenerateHMACResponse, error) {
	f.hmac = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.GenerateHMACResponse{KeyID: req.KeyID, HMAC: []byte("mac")}, nil
}

func (f *covCrypto) VerifyHMAC(_ context.Context, req *cryptoclient.VerifyHMACRequest) (*cryptoclient.VerifyHMACResponse, error) {
	f.verifyMAC = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.VerifyHMACResponse{Valid: true}, nil
}

func (f *covCrypto) Hash(_ context.Context, req *cryptoclient.HashRequest) (*cryptoclient.HashResponse, error) {
	f.hash = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.HashResponse{HashAlg: req.HashAlg, Hash: []byte("digest")}, nil
}

func (f *covCrypto) GenerateRandom(_ context.Context, req *cryptoclient.GenerateRandomRequest) (*cryptoclient.GenerateRandomResponse, error) {
	f.random = req
	if f.err != nil {
		return nil, f.err
	}
	return &cryptoclient.GenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
}

// covDEK records the requests the DEK handlers send. A nil dek makes the
// lookups return a nil DEKInfo, as an SDK that omits it would.
type covDEK struct {
	dekclient.Client
	err       error
	dek       *dekclient.DEKInfo
	createReq *dekclient.CreateDEKRequest
	deleteReq *dekclient.DeleteDEKRequest
	rotateReq *dekclient.RotateDEKRequest
	path      string
}

func (f *covDEK) CreateDEK(_ context.Context, req *dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
	f.createReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.CreateDEKResponse{DEK: f.dek}, nil
}

func (f *covDEK) GetDEK(_ context.Context, path string) (*dekclient.DEKInfo, error) {
	f.path = path
	if f.err != nil {
		return nil, f.err
	}
	return f.dek, nil
}

func (f *covDEK) ListDEKs(_ context.Context, _ *dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.ListDEKsResponse{DEKs: []dekclient.DEKInfo{*f.dek}, TotalCount: 1}, nil
}

func (f *covDEK) RotateDEK(_ context.Context, req *dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error) {
	f.rotateReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.RotateDEKResponse{Path: req.Path, OldVersion: 1, NewVersion: 2}, nil
}

func (f *covDEK) DeleteDEK(_ context.Context, req *dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error) {
	f.deleteReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.DeleteDEKResponse{Path: req.Path, Deleted: true}, nil
}

func (f *covDEK) GetDEKStatus(_ context.Context, path string) (*dekclient.DEKStatusResponse, error) {
	f.path = path
	if f.err != nil {
		return nil, f.err
	}
	return &dekclient.DEKStatusResponse{DEK: f.dek}, nil
}

// covSecrets records the requests the secret handlers send.
type covSecrets struct {
	secretsclient.Client
	err         error
	storeReq    *secretsclient.StoreSecretRequest
	rollbackReq *secretsclient.RollbackSecretRequest
	statusReq   *secretsclient.UpdateSecretStatusRequest
	versionReq  *secretsclient.GetSecretVersionRequest
	prefix      string
	deleted     string
}

func (f *covSecrets) Store(_ context.Context, req *secretsclient.StoreSecretRequest) (*secretsclient.StoreSecretResponse, error) {
	f.storeReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.StoreSecretResponse{Version: 4}, nil
}

func (f *covSecrets) List(_ context.Context, prefix string) (*secretsclient.ListSecretsResponse, error) {
	f.prefix = prefix
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.ListSecretsResponse{Paths: []string{prefix + "a", prefix + "b"}}, nil
}

func (f *covSecrets) Delete(_ context.Context, path string) error {
	f.deleted = path
	return f.err
}

func (f *covSecrets) Rollback(_ context.Context, req *secretsclient.RollbackSecretRequest) (*secretsclient.RollbackSecretResponse, error) {
	f.rollbackReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.RollbackSecretResponse{SecretID: req.SecretID, NewVersion: req.TargetVersion + 10}, nil
}

func (f *covSecrets) UpdateStatus(_ context.Context, req *secretsclient.UpdateSecretStatusRequest) error {
	f.statusReq = req
	return f.err
}

func (f *covSecrets) ListVersions(_ context.Context, _ string) (*secretsclient.ListSecretVersionsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.ListSecretVersionsResponse{Versions: []secretsclient.SecretVersionInfo{
		{Version: 1, CreatedAt: covTime},
		{Version: 2, CreatedAt: covTime},
	}}, nil
}

func (f *covSecrets) GetVersion(_ context.Context, req *secretsclient.GetSecretVersionRequest) (*secretsclient.SecretVersionInfo, error) {
	f.versionReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.SecretVersionInfo{SecretID: req.SecretID, Version: req.Version, Data: []byte("v"), CreatedAt: covTime}, nil
}

// covFakes bundles one of each fake so a test can wire every service.
type covFakes struct {
	kms     *covKMS
	crypto  *covCrypto
	dek     *covDEK
	secrets *covSecrets
}

func newCovFakes(err error) *covFakes {
	return &covFakes{
		kms:     &covKMS{err: err},
		crypto:  &covCrypto{err: err},
		dek:     &covDEK{err: err, dek: &dekclient.DEKInfo{Path: "app/db", Algorithm: "AES-256-GCM", Version: 5}},
		secrets: &covSecrets{err: err},
	}
}

func (f *covFakes) handlers() *Handlers {
	logger := logging.DefaultLogger()
	return NewHandlers(logger, f.kms, f.crypto, f.dek, f.secrets, response.NewResponseWriter(logger, nil))
}

// covRequest builds a request with a raw body and the given mux vars.
func covRequest(method, target, body string, vars map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return mux.SetURLVars(req, vars)
}

func covServe(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func covStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, want, w.Body.String())
	}
}

var (
	nameVars = map[string]string{"name": "key-1"}
	dekVars  = map[string]string{"path": "app/db"}
)

// covRoute is one handler invocation, used by the tables that cover the same
// failure for every route.
type covRoute struct {
	name   string
	call   func(h *Handlers) http.HandlerFunc
	method string
	target string
	body   string
	vars   map[string]string
}

func covRoutes() []covRoute {
	return []covRoute{
		{"ImportKey", func(h *Handlers) http.HandlerFunc { return h.ImportKey }, http.MethodPost, "/keys/import", `{"algorithm":"AES-256-GCM"}`, nil},
		{"ListKeys", func(h *Handlers) http.HandlerFunc { return h.ListKeys }, http.MethodGet, "/keys", "", nil},
		{"GetKey", func(h *Handlers) http.HandlerFunc { return h.GetKey }, http.MethodGet, "/keys/key-1", "", nameVars},
		{"DeleteKey", func(h *Handlers) http.HandlerFunc { return h.DeleteKey }, http.MethodDelete, "/keys/key-1", "", nameVars},
		{"UpdateKeyStatus", func(h *Handlers) http.HandlerFunc { return h.UpdateKeyStatus }, http.MethodPut, "/keys/key-1/status", `{"status":"disabled"}`, nameVars},
		{"ListKeyVersions", func(h *Handlers) http.HandlerFunc { return h.ListKeyVersions }, http.MethodGet, "/keys/key-1/versions", "", nameVars},
		{"Verify", func(h *Handlers) http.HandlerFunc { return h.Verify }, http.MethodPost, "/keys/key-1/verify", `{}`, nameVars},
		{"HMAC", func(h *Handlers) http.HandlerFunc { return h.HMAC }, http.MethodPost, "/keys/key-1/hmac", `{}`, nameVars},
		{"VerifyHMAC", func(h *Handlers) http.HandlerFunc { return h.VerifyHMAC }, http.MethodPost, "/keys/key-1/hmac/verify", `{}`, nameVars},
		{"Hash", func(h *Handlers) http.HandlerFunc { return h.Hash }, http.MethodPost, "/hash", `{}`, nil},
		{"GenerateRandom", func(h *Handlers) http.HandlerFunc { return h.GenerateRandom }, http.MethodPost, "/random", `{"num_bytes":8}`, nil},
		{"CreateDEK", func(h *Handlers) http.HandlerFunc { return h.CreateDEK }, http.MethodPost, "/deks", `{"path":"app/db"}`, nil},
		{"ListDEKs", func(h *Handlers) http.HandlerFunc { return h.ListDEKs }, http.MethodGet, "/deks", "", nil},
		{"GetDEK", func(h *Handlers) http.HandlerFunc { return h.GetDEK }, http.MethodGet, "/deks/app/db", "", dekVars},
		{"DeleteDEK", func(h *Handlers) http.HandlerFunc { return h.DeleteDEK }, http.MethodDelete, "/deks/app/db", "", dekVars},
		{"RotateDEK", func(h *Handlers) http.HandlerFunc { return h.RotateDEK }, http.MethodPost, "/deks/app/db/rotate", "", dekVars},
		{"GetDEKStatus", func(h *Handlers) http.HandlerFunc { return h.GetDEKStatus }, http.MethodGet, "/deks/app/db/status", "", dekVars},
		{"StoreSecret", func(h *Handlers) http.HandlerFunc { return h.StoreSecret }, http.MethodPost, "/secrets", `{"path":"s"}`, nil},
		{"ListSecrets", func(h *Handlers) http.HandlerFunc { return h.ListSecrets }, http.MethodGet, "/secrets", "", nil},
		{"DeleteSecret", func(h *Handlers) http.HandlerFunc { return h.DeleteSecret }, http.MethodDelete, "/secrets/s", "", nameVars},
		{"RollbackSecret", func(h *Handlers) http.HandlerFunc { return h.RollbackSecret }, http.MethodPost, "/secrets/s/rollback", `{"version":1}`, nameVars},
		{"UpdateSecretStatus", func(h *Handlers) http.HandlerFunc { return h.UpdateSecretStatus }, http.MethodPut, "/secrets/s/status", `{"enabled":true}`, nameVars},
		{"ListSecretVersions", func(h *Handlers) http.HandlerFunc { return h.ListSecretVersions }, http.MethodGet, "/secrets/s/versions", "", nameVars},
		{"GetSecretVersion", func(h *Handlers) http.HandlerFunc { return h.GetSecretVersion }, http.MethodGet, "/secrets/s/versions/1", "", map[string]string{"name": "s", "version": "1"}},
	}
}

// TestCoverage964_SDKErrorIsMappedOnEveryRoute checks that an SDK failure is
// surfaced through fail on every route rather than answered as a success.
func TestCoverage964_SDKErrorIsMappedOnEveryRoute(t *testing.T) {
	for _, rt := range covRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			h := newCovFakes(covErr("resource not found")).handlers()
			w := covServe(rt.call(h), covRequest(rt.method, rt.target, rt.body, rt.vars))
			covStatus(t, w, http.StatusNotFound)
		})
	}
}

// TestCoverage964_MalformedJSONIsBadRequest checks that every route reading
// a body rejects malformed JSON before calling the SDK.
func TestCoverage964_MalformedJSONIsBadRequest(t *testing.T) {
	for _, rt := range covRoutes() {
		if rt.body == "" {
			continue
		}
		t.Run(rt.name, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(rt.call(f.handlers()), covRequest(rt.method, rt.target, "{", rt.vars))
			covStatus(t, w, http.StatusBadRequest)
			if f.kms.importReq != nil || f.kms.statusReq != nil || f.crypto.verify != nil ||
				f.crypto.hmac != nil || f.crypto.verifyMAC != nil || f.crypto.hash != nil ||
				f.crypto.random != nil || f.dek.createReq != nil || f.secrets.storeReq != nil ||
				f.secrets.rollbackReq != nil || f.secrets.statusReq != nil {
				t.Fatal("SDK was called with a malformed request body")
			}
		})
	}
}

// TestCoverage964_ValidationIsBadRequest covers the field checks each
// handler applies before calling the SDK.
func TestCoverage964_ValidationIsBadRequest(t *testing.T) {
	cases := []struct {
		name  string
		call  func(h *Handlers) http.HandlerFunc
		body  string
		vars  map[string]string
		field string
	}{
		{"ImportKey unknown algorithm", func(h *Handlers) http.HandlerFunc { return h.ImportKey }, `{"algorithm":"DES"}`, nil, "unknown kms algorithm"},
		{"ImportKey unknown usage", func(h *Handlers) http.HandlerFunc { return h.ImportKey }, `{"algorithm":"RSA-2048","usage":["mine"]}`, nil, "usage"},
		{"UpdateKeyStatus unknown status", func(h *Handlers) http.HandlerFunc { return h.UpdateKeyStatus }, `{"status":"asleep"}`, nameVars, "status"},
		{"GenerateRandom zero bytes", func(h *Handlers) http.HandlerFunc { return h.GenerateRandom }, `{"num_bytes":0}`, nil, "num_bytes"},
		{"CreateDEK missing path", func(h *Handlers) http.HandlerFunc { return h.CreateDEK }, `{"algorithm":"AES-256-GCM"}`, nil, "path"},
		{"StoreSecret missing path and name", func(h *Handlers) http.HandlerFunc { return h.StoreSecret }, `{"value":"aGk="}`, nil, "path"},
		{"RollbackSecret zero version", func(h *Handlers) http.HandlerFunc { return h.RollbackSecret }, `{"version":0}`, nameVars, "version"},
		{"GetSecretVersion non-integer", func(h *Handlers) http.HandlerFunc { return h.GetSecretVersion }, "", map[string]string{"name": "s", "version": "latest"}, "version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(tc.call(f.handlers()), covRequest(http.MethodPost, "/", tc.body, tc.vars))
			covStatus(t, w, http.StatusBadRequest)
			if !strings.Contains(w.Body.String(), tc.field) {
				t.Fatalf("body %s does not name %q", w.Body.String(), tc.field)
			}
			if f.kms.importReq != nil || f.kms.statusReq != nil || f.crypto.random != nil ||
				f.dek.createReq != nil || f.secrets.storeReq != nil || f.secrets.rollbackReq != nil ||
				f.secrets.versionReq != nil {
				t.Fatal("SDK was called with an invalid request")
			}
		})
	}
}

// TestCoverage964_FailMapsErrorTextToStatus covers every branch of fail.
func TestCoverage964_FailMapsErrorTextToStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{covErr("key Not Found"), http.StatusNotFound},
		{covErr("no such key"), http.StatusNotFound},
		{covErr("invalid key id"), http.StatusBadRequest},
		{covErr("validation failed"), http.StatusBadRequest},
		{covErr("unauthenticated caller"), http.StatusUnauthorized},
		{covErr("unauthorized"), http.StatusUnauthorized},
		{covErr("permission denied"), http.StatusForbidden},
		{covErr("forbidden"), http.StatusForbidden},
		{covErr("backend offline"), http.StatusInternalServerError},
		{nil, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		name := "nil"
		if tc.err != nil {
			name = tc.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			h := newCovFakes(nil).handlers()
			w := httptest.NewRecorder()
			h.fail(w, httptest.NewRequest(http.MethodGet, "/", nil), tc.err)
			covStatus(t, w, tc.want)
		})
	}
}

func TestCoverage964_ImportKeyForwardsParsedRequest(t *testing.T) {
	f := newCovFakes(nil)
	body := `{"key_material":"AQID","name":"imp","algorithm":"ecdsa_p384","usage":["sign","Verify"],"tags":{"t":"v"}}`
	w := covServe(f.handlers().ImportKey, covRequest(http.MethodPost, "/keys/import", body, nil))
	covStatus(t, w, http.StatusCreated)

	got := f.kms.importReq
	if got.Algorithm != kmsclient.AlgorithmECDSAP384 || got.Name != "imp" || string(got.KeyMaterial) != "\x01\x02\x03" {
		t.Fatalf("forwarded request = %+v", got)
	}
	if !reflect.DeepEqual(got.Usage, []kmsclient.KeyUsage{kmsclient.KeyUsageSign, kmsclient.KeyUsageVerify}) || got.Tags["t"] != "v" {
		t.Fatalf("usage/tags = %v %v", got.Usage, got.Tags)
	}
	var out ImportKeyResponse
	decodeEnvelope(t, w, &out)
	if out != (ImportKeyResponse{KeyID: "imported", Version: 1, Algorithm: "ECDSA-P384"}) {
		t.Fatalf("response = %+v", out)
	}
}

func TestCoverage964_KeyReadHandlersEncodeSDKValues(t *testing.T) {
	f := newCovFakes(nil)
	h := f.handlers()

	w := covServe(h.ListKeys, covRequest(http.MethodGet, "/keys", "", nil))
	covStatus(t, w, http.StatusOK)
	var list ListKeysResponse
	decodeEnvelope(t, w, &list)
	want := KeyInfoResponse{KeyID: "k1", Name: "one", Algorithm: "RSA-2048", Version: 2, Usage: []string{"SIGN"}, CreatedAt: covTime, RotatedAt: covTime}
	if len(list.Keys) != 1 || !reflect.DeepEqual(list.Keys[0], want) {
		t.Fatalf("keys = %+v", list.Keys)
	}

	w = covServe(h.GetKey, covRequest(http.MethodGet, "/keys/key-1", "", nameVars))
	covStatus(t, w, http.StatusOK)
	var key KeyInfoResponse
	decodeEnvelope(t, w, &key)
	if key.KeyID != "key-1" || key.Algorithm != "ED25519" || key.Version != 3 || !reflect.DeepEqual(key.Usage, []string{"SIGN", "VERIFY"}) {
		t.Fatalf("key = %+v", key)
	}

	w = covServe(h.ListKeyVersions, covRequest(http.MethodGet, "/keys/key-1/versions", "", nameVars))
	covStatus(t, w, http.StatusOK)
	var versions ListKeyVersionsResponse
	decodeEnvelope(t, w, &versions)
	wantVersions := []KeyVersionInfoResponse{
		{Version: 1, Status: "DISABLED", Algorithm: "AES-256-GCM", CreatedAt: covTime, DisabledAt: covTime},
		{Version: 2, Status: "ENABLED", Algorithm: "AES-256-GCM", CreatedAt: covTime},
	}
	if !reflect.DeepEqual(versions.Versions, wantVersions) {
		t.Fatalf("versions = %+v", versions.Versions)
	}
}

func TestCoverage964_DeleteKeyAndUpdateStatusTargetNamedKey(t *testing.T) {
	f := newCovFakes(nil)
	h := f.handlers()

	w := covServe(h.DeleteKey, covRequest(http.MethodDelete, "/keys/key-1", "", nameVars))
	covStatus(t, w, http.StatusOK)
	if f.kms.keyID != "key-1" {
		t.Fatalf("deleted key = %q", f.kms.keyID)
	}

	w = covServe(h.UpdateKeyStatus, covRequest(http.MethodPut, "/keys/key-1/status", `{"status":" pending_deletion ","version":7}`, nameVars))
	covStatus(t, w, http.StatusOK)
	if got := f.kms.statusReq; got.KeyID != "key-1" || got.Version != 7 || got.Status != kmsclient.KeyStatusPendingDeletion {
		t.Fatalf("status request = %+v", got)
	}
	var out UpdateKeyStatusResponse
	decodeEnvelope(t, w, &out)
	if out != (UpdateKeyStatusResponse{KeyID: "key-1", Version: 7, Status: "PENDING_DELETION"}) {
		t.Fatalf("response = %+v", out)
	}
}

func TestCoverage964_CryptoHandlersForwardKeyAndHash(t *testing.T) {
	f := newCovFakes(nil)
	h := f.handlers()

	w := covServe(h.Verify, covRequest(http.MethodPost, "/", `{"data":"ZA==","signature":"cw==","hash":"sha512"}`, nameVars))
	covStatus(t, w, http.StatusOK)
	var verify VerifyResponse
	decodeEnvelope(t, w, &verify)
	if !verify.Valid || f.crypto.verify.KeyID != "key-1" || f.crypto.verify.HashAlg != cryptoclient.HashSHA512 ||
		string(f.crypto.verify.Data) != "d" || string(f.crypto.verify.Signature) != "s" {
		t.Fatalf("verify = %+v, request = %+v", verify, f.crypto.verify)
	}

	w = covServe(h.HMAC, covRequest(http.MethodPost, "/", `{"data":"ZA==","hash":"SHA-384"}`, nameVars))
	covStatus(t, w, http.StatusOK)
	var mac HMACResponse
	decodeEnvelope(t, w, &mac)
	if mac.KeyID != "key-1" || string(mac.HMAC) != "mac" || f.crypto.hmac.HashAlg != cryptoclient.HashSHA384 {
		t.Fatalf("hmac = %+v, request = %+v", mac, f.crypto.hmac)
	}

	w = covServe(h.VerifyHMAC, covRequest(http.MethodPost, "/", `{"data":"ZA==","hmac":"bQ=="}`, nameVars))
	covStatus(t, w, http.StatusOK)
	var verifyMAC VerifyHMACResponse
	decodeEnvelope(t, w, &verifyMAC)
	if !verifyMAC.Valid || string(f.crypto.verifyMAC.HMAC) != "m" || f.crypto.verifyMAC.HashAlg != cryptoclient.HashSHA256 {
		t.Fatalf("verify hmac = %+v, request = %+v", verifyMAC, f.crypto.verifyMAC)
	}

	w = covServe(h.Hash, covRequest(http.MethodPost, "/", `{"data":"ZA==","hash":"sha384"}`, nil))
	covStatus(t, w, http.StatusOK)
	var hash HashResponse
	decodeEnvelope(t, w, &hash)
	if hash.Hash != "SHA-384" || string(hash.Digest) != "digest" {
		t.Fatalf("hash = %+v", hash)
	}

	w = covServe(h.GenerateRandom, covRequest(http.MethodPost, "/", `{"num_bytes":16}`, nil))
	covStatus(t, w, http.StatusOK)
	var random GenerateRandomResponse
	decodeEnvelope(t, w, &random)
	if len(random.Bytes) != 16 || f.crypto.random.NumBytes != 16 {
		t.Fatalf("random = %d bytes, request = %+v", len(random.Bytes), f.crypto.random)
	}
}

func TestCoverage964_CreateDEKPrefersSDKVersion(t *testing.T) {
	cases := []struct {
		name string
		dek  *dekclient.DEKInfo
		want CreateDEKResponse
	}{
		{"SDK returns DEK", &dekclient.DEKInfo{Algorithm: "CHACHA20-POLY1305", Version: 3}, CreateDEKResponse{Path: "app/db", Version: 3, Algorithm: "CHACHA20-POLY1305"}},
		{"SDK omits DEK", nil, CreateDEKResponse{Path: "app/db", Algorithm: "AES-256-GCM"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCovFakes(nil)
			f.dek.dek = tc.dek
			w := covServe(f.handlers().CreateDEK, covRequest(http.MethodPost, "/deks", `{"path":"app/db","algorithm":"AES-256-GCM","description":"d"}`, nil))
			covStatus(t, w, http.StatusCreated)
			if f.dek.createReq.Description != "d" {
				t.Fatalf("request = %+v", f.dek.createReq)
			}
			var out CreateDEKResponse
			decodeEnvelope(t, w, &out)
			if out != tc.want {
				t.Fatalf("response = %+v, want %+v", out, tc.want)
			}
		})
	}
}

func TestCoverage964_DEKHandlersUsePathVar(t *testing.T) {
	f := newCovFakes(nil)
	f.dek.dek = &dekclient.DEKInfo{
		Path: "app/db", Algorithm: "AES-256-GCM", Version: 5, Status: "active", IsDefault: true,
		CreatedAt: covTime, RotatedAt: covTime, UsageCount: 9, BytesUsed: 10, MaxUsageCount: 100,
		MaxBytesUsed: 200, WarningPercent: 80, Description: "db", BackendType: "pkcs8",
	}
	h := f.handlers()
	wantInfo := DEKInfoResponse{
		Path: "app/db", Algorithm: "AES-256-GCM", Version: 5, Status: "active", IsDefault: true,
		CreatedAt: covTime, RotatedAt: covTime, UsageCount: 9, BytesUsed: 10, Description: "db", BackendType: "pkcs8",
	}

	w := covServe(h.ListDEKs, covRequest(http.MethodGet, "/deks", "", nil))
	covStatus(t, w, http.StatusOK)
	var list ListDEKsResponse
	decodeEnvelope(t, w, &list)
	if len(list.DEKs) != 1 || list.DEKs[0] != wantInfo {
		t.Fatalf("deks = %+v", list.DEKs)
	}

	w = covServe(h.GetDEK, covRequest(http.MethodGet, "/deks/app/db", "", dekVars))
	covStatus(t, w, http.StatusOK)
	var info DEKInfoResponse
	decodeEnvelope(t, w, &info)
	if info != wantInfo || f.dek.path != "app/db" {
		t.Fatalf("dek = %+v (path %q)", info, f.dek.path)
	}

	w = covServe(h.GetDEKStatus, covRequest(http.MethodGet, "/deks/app/db/status", "", dekVars))
	covStatus(t, w, http.StatusOK)
	var st DEKStatusResponse
	decodeEnvelope(t, w, &st)
	wantStatus := DEKStatusResponse{
		Path: "app/db", Algorithm: "AES-256-GCM", Version: 5, Status: "active", IsDefault: true,
		UsageCount: 9, BytesUsed: 10, MaxUsageCount: 100, MaxBytesUsed: 200, WarningPercent: 80,
		CreatedAt: covTime, RotatedAt: covTime,
	}
	if st != wantStatus {
		t.Fatalf("status = %+v", st)
	}

	w = covServe(h.RotateDEK, covRequest(http.MethodPost, "/deks/app/db/rotate", "", dekVars))
	covStatus(t, w, http.StatusOK)
	var rot RotateDEKResponse
	decodeEnvelope(t, w, &rot)
	if rot != (RotateDEKResponse{Path: "app/db", NewVersion: 2}) || f.dek.rotateReq.Path != "app/db" {
		t.Fatalf("rotate = %+v", rot)
	}
}

func TestCoverage964_GetDEKStatusWithoutDEKIsEmpty(t *testing.T) {
	f := newCovFakes(nil)
	f.dek.dek = nil
	w := covServe(f.handlers().GetDEKStatus, covRequest(http.MethodGet, "/", "", dekVars))
	covStatus(t, w, http.StatusOK)
	var st DEKStatusResponse
	decodeEnvelope(t, w, &st)
	if st != (DEKStatusResponse{}) {
		t.Fatalf("status = %+v, want zero value", st)
	}
	if encodeDEK(nil) != (DEKInfoResponse{}) {
		t.Fatal("encodeDEK(nil) is not the zero value")
	}
}

func TestCoverage964_DeleteDEKForwardsForce(t *testing.T) {
	cases := []struct {
		target string
		force  bool
	}{
		{"/deks/app/db?force=true", true},
		{"/deks/app/db?force=yes", false},
		{"/deks/app/db", false},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(f.handlers().DeleteDEK, covRequest(http.MethodDelete, tc.target, "", dekVars))
			covStatus(t, w, http.StatusOK)
			if got := f.dek.deleteReq; got.Path != "app/db" || got.Force != tc.force {
				t.Fatalf("delete request = %+v, want force %v", got, tc.force)
			}
		})
	}
}

func TestCoverage964_StoreSecretBuildsData(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantPath string
		wantData map[string]interface{}
	}{
		{"path only", `{"path":"db/pw","value":"aGk="}`, "db/pw", map[string]interface{}{"value": SecretValue("hi")}},
		{"name promoted with metadata", `{"name":"web","value":"plain text","content_type":"text/plain","description":"d","tags":{"env":"dev"}}`, "web",
			map[string]interface{}{"value": SecretValue("plain text"), "content_type": "text/plain", "description": "d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(f.handlers().StoreSecret, covRequest(http.MethodPost, "/secrets", tc.body, nil))
			covStatus(t, w, http.StatusCreated)
			got := f.secrets.storeReq
			if got.Path != tc.wantPath || !reflect.DeepEqual(got.Data, tc.wantData) {
				t.Fatalf("store request = %+v", got)
			}
			var out StoreSecretResponse
			decodeEnvelope(t, w, &out)
			if out != (StoreSecretResponse{Path: tc.wantPath, Version: 4}) {
				t.Fatalf("response = %+v", out)
			}
		})
	}
}

func TestCoverage964_SecretHandlersTargetNamedSecret(t *testing.T) {
	f := newCovFakes(nil)
	h := f.handlers()
	secretVars := map[string]string{"name": "db/pw", "version": "2"}

	w := covServe(h.ListSecrets, covRequest(http.MethodGet, "/secrets?prefix=db/", "", nil))
	covStatus(t, w, http.StatusOK)
	var list ListSecretsResponse
	decodeEnvelope(t, w, &list)
	if f.secrets.prefix != "db/" || len(list.Secrets) != 2 || list.Secrets[1].Path != "db/b" {
		t.Fatalf("list = %+v (prefix %q)", list, f.secrets.prefix)
	}

	w = covServe(h.DeleteSecret, covRequest(http.MethodDelete, "/", "", secretVars))
	covStatus(t, w, http.StatusOK)
	if f.secrets.deleted != "db/pw" {
		t.Fatalf("deleted = %q", f.secrets.deleted)
	}

	w = covServe(h.RollbackSecret, covRequest(http.MethodPost, "/", `{"version":2}`, secretVars))
	covStatus(t, w, http.StatusOK)
	var rb RollbackSecretResponse
	decodeEnvelope(t, w, &rb)
	if rb != (RollbackSecretResponse{Path: "db/pw", Version: 12}) || f.secrets.rollbackReq.TargetVersion != 2 {
		t.Fatalf("rollback = %+v", rb)
	}

	w = covServe(h.ListSecretVersions, covRequest(http.MethodGet, "/", "", secretVars))
	covStatus(t, w, http.StatusOK)
	var versions ListSecretVersionsResponse
	decodeEnvelope(t, w, &versions)
	wantVersions := []SecretVersionResponse{{Path: "db/pw", Version: 1, CreatedAt: covTime}, {Path: "db/pw", Version: 2, CreatedAt: covTime}}
	if !reflect.DeepEqual(versions.Versions, wantVersions) {
		t.Fatalf("versions = %+v", versions.Versions)
	}

	w = covServe(h.GetSecretVersion, covRequest(http.MethodGet, "/", "", secretVars))
	covStatus(t, w, http.StatusOK)
	var v SecretVersionResponse
	decodeEnvelope(t, w, &v)
	if !reflect.DeepEqual(v, SecretVersionResponse{Path: "db/pw", Version: 2, Value: []byte("v"), CreatedAt: covTime}) ||
		f.secrets.versionReq.SecretID != "db/pw" {
		t.Fatalf("version = %+v", v)
	}
}

func TestCoverage964_UpdateSecretStatusMapsEnabled(t *testing.T) {
	cases := []struct {
		body string
		want secretsclient.SecretStatus
	}{
		{`{"enabled":true}`, secretsclient.SecretStatusEnabled},
		{`{"enabled":false}`, secretsclient.SecretStatusDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(f.handlers().UpdateSecretStatus, covRequest(http.MethodPut, "/", tc.body, nameVars))
			covStatus(t, w, http.StatusOK)
			if got := f.secrets.statusReq; got.SecretID != "key-1" || got.Status != tc.want {
				t.Fatalf("status request = %+v, want %q", got, tc.want)
			}
		})
	}
}

func TestCoverage964_ParseKeyAlgorithm(t *testing.T) {
	cases := []struct {
		in   string
		want kmsclient.KeyAlgorithm
	}{
		{"aes-256-gcm", kmsclient.AlgorithmAES256GCM},
		{"AES256GCM", kmsclient.AlgorithmAES256GCM},
		{" aes_256 ", kmsclient.AlgorithmAES256GCM},
		{"chacha20_poly1305", kmsclient.AlgorithmChaCha20Poly1305},
		{"CHACHA20POLY1305", kmsclient.AlgorithmChaCha20Poly1305},
		{"rsa-2048", kmsclient.AlgorithmRSA2048},
		{"RSA2048", kmsclient.AlgorithmRSA2048},
		{"rsa_4096", kmsclient.AlgorithmRSA4096},
		{"RSA4096", kmsclient.AlgorithmRSA4096},
		{"ecdsa-p256", kmsclient.AlgorithmECDSAP256},
		{"ECDSAP256", kmsclient.AlgorithmECDSAP256},
		{"p256", kmsclient.AlgorithmECDSAP256},
		{"ECDSA-P384", kmsclient.AlgorithmECDSAP384},
		{"ecdsap384", kmsclient.AlgorithmECDSAP384},
		{"P384", kmsclient.AlgorithmECDSAP384},
		{"ed25519", kmsclient.AlgorithmED25519},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseKeyAlgorithm(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("parseKeyAlgorithm(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}

	_, err := parseKeyAlgorithm("DES")
	var unknown *ErrUnknownAlgorithm
	if !errors.As(err, &unknown) || unknown.Algorithm != "DES" {
		t.Fatalf("parseKeyAlgorithm(DES) error = %v, want *ErrUnknownAlgorithm", err)
	}
}

func TestCoverage964_ParseKeyStatus(t *testing.T) {
	cases := []struct {
		in   string
		want kmsclient.KeyStatus
	}{
		{"enabled", kmsclient.KeyStatusEnabled},
		{"DISABLED", kmsclient.KeyStatusDisabled},
		{" pending_deletion ", kmsclient.KeyStatusPendingDeletion},
		{"Deleted", kmsclient.KeyStatusDeleted},
		{"rotating", kmsclient.KeyStatusRotating},
		{"COMPROMISED", kmsclient.KeyStatusCompromised},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseKeyStatus(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("parseKeyStatus(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}

	_, err := parseKeyStatus("asleep")
	var invalid *ErrInvalidRequest
	if !errors.As(err, &invalid) || invalid.Field != "status" {
		t.Fatalf("parseKeyStatus(asleep) error = %v, want *ErrInvalidRequest on status", err)
	}
}

func TestCoverage964_ParseHashAlgorithm(t *testing.T) {
	cases := map[string]cryptoclient.HashAlgorithm{
		"sha-384": cryptoclient.HashSHA384,
		"SHA384":  cryptoclient.HashSHA384,
		"sha-512": cryptoclient.HashSHA512,
		"SHA512":  cryptoclient.HashSHA512,
		"sha-256": cryptoclient.HashSHA256,
		"":        cryptoclient.HashSHA256,
		"md5":     cryptoclient.HashSHA256,
	}
	for in, want := range cases {
		if got := parseHashAlgorithm(in); got != want {
			t.Errorf("parseHashAlgorithm(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCoverage964_SecretValueUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want SecretValue
	}{
		{"null", `null`, nil},
		{"base64 string", `"aGVsbG8="`, SecretValue("hello")},
		{"plain string", `"not base64!"`, SecretValue("not base64!")},
		{"byte array", `[104,105]`, SecretValue("hi")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := SecretValue("previous")
			if err := v.UnmarshalJSON([]byte(tc.in)); err != nil {
				t.Fatalf("UnmarshalJSON(%s): %v", tc.in, err)
			}
			if !reflect.DeepEqual(v, tc.want) {
				t.Fatalf("UnmarshalJSON(%s) = %q, want %q", tc.in, v, tc.want)
			}
		})
	}

	for _, bad := range []string{`123`, `"unterminated`} {
		var v SecretValue
		if err := v.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("UnmarshalJSON(%s) returned no error", bad)
		}
	}
}

func TestCoverage964_SecretValueMarshal(t *testing.T) {
	cases := []struct {
		in   SecretValue
		want string
	}{
		{nil, `null`},
		{SecretValue("hi"), `"aGk="`},
	}
	for _, tc := range cases {
		got, err := json.Marshal(tc.in)
		if err != nil || string(got) != tc.want {
			t.Fatalf("Marshal(%q) = %s, %v; want %s", tc.in, got, err, tc.want)
		}
	}
}

func TestCoverage964_GenerateKeyRequestResolve(t *testing.T) {
	cases := []struct {
		name string
		in   GenerateKeyRequest
		alg  string
		use  []string
	}{
		{"no key spec", GenerateKeyRequest{Algorithm: "RSA-2048"}, "RSA-2048", nil},
		{"spec fills empty fields", GenerateKeyRequest{KeySpec: &KMSKeySpec{Algorithm: "ED25519", Usage: []string{"sign"}}}, "ED25519", []string{"sign"}},
		{"top level wins", GenerateKeyRequest{Algorithm: "RSA-4096", Usage: []string{"encrypt"}, KeySpec: &KMSKeySpec{Algorithm: "ED25519", Usage: []string{"sign"}}}, "RSA-4096", []string{"encrypt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.in
			req.Resolve()
			if req.Algorithm != tc.alg || !reflect.DeepEqual(req.Usage, tc.use) {
				t.Fatalf("Resolve() = %q %v, want %q %v", req.Algorithm, req.Usage, tc.alg, tc.use)
			}
		})
	}
}

func TestCoverage964_ErrInvalidRequestWithoutField(t *testing.T) {
	err := &ErrInvalidRequest{Reason: "body is empty"}
	if got := err.Error(); got != "invalid kms request: body is empty" {
		t.Fatalf("Error() = %q", got)
	}
}
