package configdelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// cov964Envelope mirrors the REST envelope with the payload kept raw so a
// test can decode it into the typed response it expects.
type cov964Envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// cov964SignHandler wires a real handler over a service built by
// newSignService, so nonce, EAB and EK checks all run for real.
func cov964SignHandler(t *testing.T, svc *Service) RestHandler {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	h, err := NewHandler(HandlerParams{
		Service:        svc,
		ResponseWriter: response.NewResponseWriter(logger, nil),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}
	return h
}

// cov964PostSign drives the sign endpoint with body and decodes the envelope.
func cov964PostSign(t *testing.T, h RestHandler, body []byte) (int, cov964Envelope) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sign", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.SignDigest(w, req)

	var env cov964Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to decode response %q: %v", w.Body.String(), err)
	}
	return w.Code, env
}

func cov964Marshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestCov964Handler_SignDigest_HappyPath(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig-bytes"), certPEM: []byte("db-cert-pem")}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)
	h := cov964SignHandler(t, svc)

	digest := sha256Digest()
	code, env := cov964PostSign(t, h, cov964Marshal(t, signRequest(t, svc, certB64, digest)))

	if code != http.StatusOK || !env.Success {
		t.Fatalf("expected 200 success, got %d: %+v", code, env)
	}
	var resp SignResponse
	if err := json.Unmarshal(env.Payload, &resp); err != nil {
		t.Fatalf("failed to decode sign response: %v", err)
	}
	if string(resp.Signature) != "sig-bytes" || string(resp.CertPEM) != "db-cert-pem" {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
	if !bytes.Equal(signer.lastDigest, digest) {
		t.Fatalf("signer received wrong digest over the wire: %x", signer.lastDigest)
	}
}

func TestCov964Handler_SignDigest_ErrorStatus(t *testing.T) {
	disabled := func(certPEM string) *entities.DeviceProfile {
		p := remoteSignProfile(certPEM)
		p.Config.(map[string]interface{})["secure-boot"].(map[string]interface{})["enabled"] = false
		return p
	}

	tests := []struct {
		name string
		// build returns the handler and request body under test.
		build      func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner)
		wantStatus int
		wantErr    string
	}{
		{
			name: "malformed json is a bad request",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{}
				svc := newSignService(t, remoteSignProfile(""), signer, boundEAB(nil), false)
				return cov964SignHandler(t, svc), []byte("{not json"), signer
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid request",
		},
		{
			name: "empty digest is a bad request",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{}
				profile := remoteSignProfile("")
				svc := newSignService(t, profile, signer, boundEAB(profile), false)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, "", nil)), signer
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "digest is required",
		},
		{
			name: "unknown nonce is a bad request",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{}
				profile := remoteSignProfile("")
				svc := newSignService(t, profile, signer, boundEAB(profile), false)
				req := signRequest(t, svc, "", sha256Digest())
				req.Nonce = "never-issued-nonce"
				return cov964SignHandler(t, svc), cov964Marshal(t, req), signer
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    ErrNonceExpired{}.Error(),
		},
		{
			name: "rejected eab is forbidden",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{}
				eabSvc := &mockEABService{validateFunc: func(context.Context, string, []byte) (*eab.Credential, error) {
					return nil, eab.ErrCredentialNotFound{KeyID: "key-1"}
				}}
				profile := remoteSignProfile("")
				svc := newSignService(t, profile, signer, eabSvc, false)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, "", sha256Digest())), signer
			},
			wantStatus: http.StatusForbidden,
			wantErr:    "eab validation failed",
		},
		{
			name: "mismatched ek certificate is forbidden",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				prestaged, _ := newSelfSignedEKCert(t)
				_, presented := newSelfSignedEKCert(t)
				signer := &fakeDBKeySigner{}
				profile := remoteSignProfile(prestaged)
				svc := newSignService(t, profile, signer, boundEAB(profile), true)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, presented, sha256Digest())), signer
			},
			wantStatus: http.StatusForbidden,
			wantErr:    ErrEKCertMismatch{}.Error(),
		},
		{
			name: "secure boot disabled is a conflict",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{}
				profile := disabled("")
				svc := newSignService(t, profile, signer, boundEAB(profile), false)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, "", sha256Digest())), signer
			},
			wantStatus: http.StatusConflict,
			wantErr:    "secure boot is not enabled",
		},
		{
			name: "no signer wired is service unavailable",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				profile := remoteSignProfile("")
				svc := newSignService(t, profile, nil, boundEAB(profile), false)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, "", sha256Digest())), &fakeDBKeySigner{}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantErr:    ErrSignerUnavailable{}.Error(),
		},
		{
			name: "kms failure is an internal error",
			build: func(t *testing.T) (RestHandler, []byte, *fakeDBKeySigner) {
				signer := &fakeDBKeySigner{signErr: errors.New("kms offline")}
				profile := remoteSignProfile("")
				svc := newSignService(t, profile, signer, boundEAB(profile), false)
				return cov964SignHandler(t, svc), cov964Marshal(t, signRequest(t, svc, "", sha256Digest())), signer
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, body, signer := tt.build(t)
			code, env := cov964PostSign(t, h, body)
			if code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %+v", tt.wantStatus, code, env)
			}
			if env.Success {
				t.Fatalf("expected success=false, got %+v", env)
			}
			if tt.wantErr != "" && !strings.Contains(env.Error, tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, env.Error)
			}
			if tt.wantStatus != http.StatusInternalServerError && signer.signCalls != 0 {
				t.Fatalf("signer must not be called on a rejected request (calls=%d)", signer.signCalls)
			}
		})
	}
}

func TestCov964Service_SignDigest_CertUnavailable(t *testing.T) {
	certErr := errors.New("cert store empty")
	profile := remoteSignProfile("")
	signer := &fakeDBKeySigner{signature: []byte("sig"), certErr: certErr}
	svc := newSignService(t, profile, signer, boundEAB(profile), false)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, "", sha256Digest()))

	var unavailable ErrCertUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected ErrCertUnavailable, got %T: %v", err, err)
	}
	if !errors.Is(err, certErr) {
		t.Fatalf("expected ErrCertUnavailable to unwrap to the store error, got %v", err)
	}
	if signer.lastCertRef != "Trusted Platform Secure Boot DB" {
		t.Fatalf("certificate looked up by %q, want the profile db cn", signer.lastCertRef)
	}
}

func TestCov964RemoteDBKeyRefs_NotConfigured(t *testing.T) {
	withSecureBoot := func(sb map[string]interface{}) *entities.DeviceProfile {
		return &entities.DeviceProfile{ID: 7, Config: map[string]interface{}{"secure-boot": sb}}
	}
	db := map[string]interface{}{"cn": "DB", "key-uri": "kms://platform/secureboot/db"}

	tests := []struct {
		name       string
		profile    *entities.DeviceProfile
		keyRef     string
		wantReason string
	}{
		{"non-db key ref", remoteSignProfile(""), "kek", "only the db key"},
		{"nil profile", nil, "db", "no platform config"},
		{"no config", &entities.DeviceProfile{ID: 7}, "db", "no platform config"},
		{"no secure-boot section", &entities.DeviceProfile{ID: 7, Config: map[string]interface{}{"hostname": "n1"}}, "db", "no secure-boot section"},
		{"secure-boot does not decode", &entities.DeviceProfile{ID: 7, Config: map[string]interface{}{"secure-boot": "on"}}, "db", "did not decode"},
		{"disabled", withSecureBoot(map[string]interface{}{"enabled": false, "db": db}), "db", "not enabled"},
		{"local resign mode", withSecureBoot(map[string]interface{}{"enabled": true, "resign-mode": "local", "db": db}), "db", "resign-mode is not remote"},
		{"no key uri", withSecureBoot(map[string]interface{}{"enabled": true, "resign-mode": "remote", "db": map[string]interface{}{"cn": "DB"}}), "", "no secure-boot db key-uri"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := remoteDBKeyRefs(tt.profile, tt.keyRef)
			var notConfigured ErrRemoteSignNotConfigured
			if !errors.As(err, &notConfigured) {
				t.Fatalf("expected ErrRemoteSignNotConfigured, got %T: %v", err, err)
			}
			if !strings.Contains(notConfigured.Reason, tt.wantReason) {
				t.Fatalf("expected reason containing %q, got %q", tt.wantReason, notConfigured.Reason)
			}
		})
	}
}

func TestCov964RemoteDBKeyRefs_DefaultsToRemoteDB(t *testing.T) {
	profile := &entities.DeviceProfile{ID: 7, Config: map[string]interface{}{
		"secure-boot": map[string]interface{}{
			"enabled": true,
			"db":      map[string]interface{}{"cn": "DB", "key-uri": "kms://platform/secureboot/db"},
		},
	}}

	keyURI, certCN, err := remoteDBKeyRefs(profile, "")
	if err != nil {
		t.Fatalf("an empty key ref and resign-mode must default to remote db signing: %v", err)
	}
	if keyURI != "kms://platform/secureboot/db" || certCN != "DB" {
		t.Fatalf("unexpected refs: key=%q cn=%q", keyURI, certCN)
	}
}

func TestCov964Errors_MessagesAndUnwrap(t *testing.T) {
	cause := errors.New("root cause")

	messages := []struct {
		err  error
		want string
	}{
		{ErrEKCertNotPEM{}, "prestaged ek certificate is not valid PEM"},
		{ErrUnsupportedEKKeyType{}, "unsupported ek certificate public key type"},
		{ErrSignerUnavailable{}, "no db key signer configured"},
		{ErrSignFailed{Cause: cause}, "digest signing failed: root cause"},
		{ErrCertUnavailable{Cause: cause}, "db certificate unavailable: root cause"},
		{ErrRemoteSignNotConfigured{}, "remote signing not configured for this device"},
	}
	for _, m := range messages {
		if got := m.err.Error(); !strings.HasPrefix(got, "configdelivery: ") || !strings.Contains(got, m.want) {
			t.Errorf("%T.Error() = %q, want it to contain %q", m.err, got, m.want)
		}
	}

	for _, err := range []error{ErrEKCertParseFailed{Cause: cause}, ErrCertUnavailable{Cause: cause}, ErrSignFailed{Cause: cause}} {
		if !errors.Is(err, cause) {
			t.Errorf("%T does not unwrap to its cause", err)
		}
	}
	if errors.Is(ErrCertUnavailable{}, cause) {
		t.Error("ErrCertUnavailable without a cause must not match an unrelated error")
	}
}
