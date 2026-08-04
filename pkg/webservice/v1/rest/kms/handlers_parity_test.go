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

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// fakeKMSClient captures parity-surface calls forwarded to the QuicBaaS
// KMS client. Unused Client methods are inherited from the embedded
// interface and panic if called, which is intentional for handler-scoped
// tests.
type fakeKMSClient struct {
	kmsclient.Client

	revokedKeyID string
	revokeErr    error

	metadata    *kmsclient.KeyMetadataResponse
	metadataErr error

	rotationPolicy    *kmsclient.KeyRotationPolicy
	rotationPolicyErr error

	updateReq *kmsclient.UpdateKeyMetadataRequest
	updateErr error

	policy       *kmsclient.KeyPolicy
	policyErr    error
	setPolicyReq *kmsclient.SetKeyPolicyRequest
	setPolicyErr error

	algorithms    *kmsclient.SupportedAlgorithmsResponse
	algorithmsErr error

	backendStatus    *kmsclient.BackendStatusResponse
	backendStatusErr error
}

func (f *fakeKMSClient) RevokeKey(_ context.Context, keyID, _ string) error {
	f.revokedKeyID = keyID
	return f.revokeErr
}

func (f *fakeKMSClient) GetKeyMetadata(_ context.Context, _ string) (*kmsclient.KeyMetadataResponse, error) {
	return f.metadata, f.metadataErr
}

func (f *fakeKMSClient) GetKeyRotationPolicy(_ context.Context, _ string) (*kmsclient.KeyRotationPolicy, error) {
	return f.rotationPolicy, f.rotationPolicyErr
}

func (f *fakeKMSClient) UpdateKeyMetadata(_ context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	f.updateReq = req
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return f.metadata, nil
}

func (f *fakeKMSClient) GetKeyPolicy(_ context.Context, _ string) (*kmsclient.KeyPolicy, error) {
	return f.policy, f.policyErr
}

func (f *fakeKMSClient) SetKeyPolicy(_ context.Context, req *kmsclient.SetKeyPolicyRequest) error {
	f.setPolicyReq = req
	return f.setPolicyErr
}

func (f *fakeKMSClient) GetSupportedAlgorithms(_ context.Context) (*kmsclient.SupportedAlgorithmsResponse, error) {
	return f.algorithms, f.algorithmsErr
}

func (f *fakeKMSClient) BackendStatus(_ context.Context) (*kmsclient.BackendStatusResponse, error) {
	return f.backendStatus, f.backendStatusErr
}

// fakeSecretsClient captures rotation-policy calls forwarded to the
// QuicBaaS secrets client.
type fakeSecretsClient struct {
	secretsclient.Client

	policy    *secretsclient.RotationPolicy
	policyErr error
	setReq    *secretsclient.SetRotationPolicyRequest
	setErr    error
}

func (f *fakeSecretsClient) GetRotationPolicy(_ context.Context, _ string) (*secretsclient.RotationPolicy, error) {
	return f.policy, f.policyErr
}

func (f *fakeSecretsClient) SetRotationPolicy(_ context.Context, req *secretsclient.SetRotationPolicyRequest) error {
	f.setReq = req
	return f.setErr
}

func newParityTestHandlers(kms kmsclient.Client, secrets secretsclient.Client) *Handlers {
	logger := logging.DefaultLogger()
	return NewHandlers(logger, kms, nil, nil, secrets, response.NewResponseWriter(logger, nil))
}

// parityRequest builds a request with the {name} route variable bound.
func parityRequest(t *testing.T, method, target, name string, body interface{}) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reader)
	return mux.SetURLVars(req, map[string]string{"name": name})
}

// decodeEnvelope unwraps the WebServiceResponse envelope payload.
func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder, payload interface{}) {
	t.Helper()
	var envelope struct {
		Code    int             `json:"code"`
		Success bool            `json:"success"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (body: %s)", err, w.Body.String())
	}
	if err := json.Unmarshal(envelope.Payload, payload); err != nil {
		t.Fatalf("decode payload: %v (body: %s)", err, w.Body.String())
	}
}

// =============================================================================
// RevokeKey
// =============================================================================

// TestRevokeKey_Success verifies the revoke route delegates to the SDK
// client and reports the persisted post-revoke key status.
func TestRevokeKey_Success(t *testing.T) {
	fake := &fakeKMSClient{
		metadata: &kmsclient.KeyMetadataResponse{
			KeyID:  "db-key",
			Status: kmsclient.KeyStatusDisabled,
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.RevokeKey(w, parityRequest(t, http.MethodPost, "/api/v1/kms/keys/db-key/revoke", "db-key",
		&RevokeKeyRequest{Reason: "compromised"}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.revokedKeyID != "db-key" {
		t.Errorf("revoked key = %q, want db-key", fake.revokedKeyID)
	}
	var resp RevokeKeyResponse
	decodeEnvelope(t, w, &resp)
	if resp.KeyID != "db-key" {
		t.Errorf("KeyID = %q, want db-key", resp.KeyID)
	}
	if resp.Status != "DISABLED" {
		t.Errorf("Status = %q, want DISABLED", resp.Status)
	}
	if resp.RevokedAt.IsZero() {
		t.Error("RevokedAt is zero, want a request-time stamp")
	}
}

// TestRevokeKey_NotFound verifies SDK not-found errors map to 404.
func TestRevokeKey_NotFound(t *testing.T) {
	fake := &fakeKMSClient{revokeErr: errors.New("kms.RevokeKey: key not found")}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.RevokeKey(w, parityRequest(t, http.MethodPost, "/api/v1/kms/keys/missing/revoke", "missing", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
	}
}

// =============================================================================
// GetKeyMetadata / UpdateKeyMetadata
// =============================================================================

// TestGetKeyMetadata_Success verifies metadata and the key rotation
// policy are surfaced on the wire.
func TestGetKeyMetadata_Success(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fake := &fakeKMSClient{
		metadata: &kmsclient.KeyMetadataResponse{
			KeyID:              "db-key",
			Name:               "DB Key",
			Description:        "test key",
			Algorithm:          kmsclient.AlgorithmAES256GCM,
			Status:             kmsclient.KeyStatusEnabled,
			Version:            3,
			Exportable:         true,
			DeletionProtection: true,
			Usage:              []kmsclient.KeyUsage{kmsclient.KeyUsageEncrypt},
			Owner:              "ops",
			CreatedAt:          created,
			Tags:               map[string]string{"env": "test"},
		},
		rotationPolicy: &kmsclient.KeyRotationPolicy{
			Enabled:         true,
			AutoRotate:      true,
			IntervalSeconds: 86400,
			RetainVersions:  5,
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GetKeyMetadata(w, parityRequest(t, http.MethodGet, "/api/v1/kms/keys/db-key/metadata", "db-key", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp KeyMetadataResponse
	decodeEnvelope(t, w, &resp)
	if resp.KeyID != "db-key" || resp.Name != "DB Key" {
		t.Errorf("identity = %q/%q, want db-key/DB Key", resp.KeyID, resp.Name)
	}
	if !resp.Exportable || !resp.DeletionProtection {
		t.Errorf("flags = %v/%v, want true/true", resp.Exportable, resp.DeletionProtection)
	}
	if resp.Status != "ENABLED" || resp.Version != 3 {
		t.Errorf("status/version = %q/%d, want ENABLED/3", resp.Status, resp.Version)
	}
	if !resp.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", resp.CreatedAt, created)
	}
	if resp.RotationPolicy == nil {
		t.Fatal("RotationPolicy missing from metadata response")
	}
	if resp.RotationPolicy.RetainVersions != 5 || resp.RotationPolicy.IntervalSeconds != 86400 {
		t.Errorf("rotation policy = %+v, want retain 5 / interval 86400", resp.RotationPolicy)
	}
}

// TestGetKeyMetadata_NotFound verifies SDK not-found errors map to 404.
func TestGetKeyMetadata_NotFound(t *testing.T) {
	fake := &fakeKMSClient{metadataErr: errors.New("kms.GetKeyMetadata: key not found")}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GetKeyMetadata(w, parityRequest(t, http.MethodGet, "/api/v1/kms/keys/missing/metadata", "missing", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
	}
}

// TestUpdateKeyMetadata_Success verifies the update request fields reach
// the SDK client unchanged.
func TestUpdateKeyMetadata_Success(t *testing.T) {
	fake := &fakeKMSClient{
		metadata: &kmsclient.KeyMetadataResponse{
			KeyID: "db-key",
			Name:  "Renamed",
			Tags:  map[string]string{"team": "security"},
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.UpdateKeyMetadata(w, parityRequest(t, http.MethodPut, "/api/v1/kms/keys/db-key/metadata", "db-key",
		&UpdateKeyMetadataRequest{
			Name:        "Renamed",
			Description: "updated",
			Tags:        map[string]string{"team": "security"},
			RemoveTags:  []string{"stale"},
		}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.updateReq == nil {
		t.Fatal("SDK UpdateKeyMetadata was not called")
	}
	if fake.updateReq.KeyID != "db-key" || fake.updateReq.Name != "Renamed" {
		t.Errorf("forwarded request = %+v, want key db-key name Renamed", fake.updateReq)
	}
	if len(fake.updateReq.RemoveTags) != 1 || fake.updateReq.RemoveTags[0] != "stale" {
		t.Errorf("RemoveTags = %v, want [stale]", fake.updateReq.RemoveTags)
	}
	var resp KeyMetadataResponse
	decodeEnvelope(t, w, &resp)
	if resp.Name != "Renamed" {
		t.Errorf("Name = %q, want Renamed", resp.Name)
	}
}

// TestUpdateKeyMetadata_SDKError verifies SDK failures surface as errors.
func TestUpdateKeyMetadata_SDKError(t *testing.T) {
	fake := &fakeKMSClient{updateErr: errors.New("kms.UpdateKeyMetadata: invalid input")}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.UpdateKeyMetadata(w, parityRequest(t, http.MethodPut, "/api/v1/kms/keys/db-key/metadata", "db-key",
		&UpdateKeyMetadataRequest{Name: "x"}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
}

// =============================================================================
// GetKeyPolicy / SetKeyPolicy
// =============================================================================

// TestGetKeyPolicy_Success verifies the policy document maps onto the
// REST wire envelope.
func TestGetKeyPolicy_Success(t *testing.T) {
	updated := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	fake := &fakeKMSClient{
		policy: &kmsclient.KeyPolicy{
			KeyID:             "db-key",
			Version:           2,
			AllowedOperations: []kmsclient.KeyUsage{kmsclient.KeyUsageEncrypt, kmsclient.KeyUsageDecrypt},
			AllowedPrincipals: []string{"user:admin@example.com"},
			DeniedPrincipals:  []string{"user:blocked@example.com"},
			RotationRequired:  true,
			MaxUsageCount:     10000,
			UpdatedAt:         updated,
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GetKeyPolicy(w, parityRequest(t, http.MethodGet, "/api/v1/kms/keys/db-key/policy", "db-key", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp KeyPolicyResponse
	decodeEnvelope(t, w, &resp)
	if resp.KeyID != "db-key" || resp.Version != 2 {
		t.Errorf("identity = %q/%d, want db-key/2", resp.KeyID, resp.Version)
	}
	if len(resp.AllowedOperations) != 2 || resp.AllowedOperations[0] != "ENCRYPT" {
		t.Errorf("AllowedOperations = %v, want [ENCRYPT DECRYPT]", resp.AllowedOperations)
	}
	if !resp.RotationRequired || resp.MaxUsageCount != 10000 {
		t.Errorf("policy fields = %v/%d, want true/10000", resp.RotationRequired, resp.MaxUsageCount)
	}
}

// TestGetKeyPolicy_NotFound verifies SDK not-found errors map to 404.
func TestGetKeyPolicy_NotFound(t *testing.T) {
	fake := &fakeKMSClient{policyErr: errors.New("kms.GetKeyPolicy: key policy not found")}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GetKeyPolicy(w, parityRequest(t, http.MethodGet, "/api/v1/kms/keys/missing/policy", "missing", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
	}
}

// TestSetKeyPolicy_Success verifies the policy is forwarded to the SDK
// and the stamped version is read back for the response.
func TestSetKeyPolicy_Success(t *testing.T) {
	fake := &fakeKMSClient{
		policy: &kmsclient.KeyPolicy{
			KeyID:     "db-key",
			Version:   1,
			UpdatedAt: time.Now(),
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.SetKeyPolicy(w, parityRequest(t, http.MethodPut, "/api/v1/kms/keys/db-key/policy", "db-key",
		&SetKeyPolicyRequest{
			Operations:       []string{"encrypt", "decrypt"},
			AllowPrincipals:  []string{"user:admin@example.com"},
			DenyPrincipals:   []string{"user:blocked@example.com"},
			ExpiresIn:        "720h",
			RotationRequired: true,
			MaxUsageCount:    10000,
		}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.setPolicyReq == nil {
		t.Fatal("SDK SetKeyPolicy was not called")
	}
	if fake.setPolicyReq.KeyID != "db-key" {
		t.Errorf("KeyID = %q, want db-key", fake.setPolicyReq.KeyID)
	}
	pol := fake.setPolicyReq.Policy
	if len(pol.AllowedOperations) != 2 {
		t.Errorf("AllowedOperations = %v, want 2 usages", pol.AllowedOperations)
	}
	if pol.ExpiresAt.IsZero() {
		t.Error("ExpiresAt not resolved from expires_in duration")
	}
	if !pol.RotationRequired || pol.MaxUsageCount != 10000 {
		t.Errorf("policy fields = %v/%d, want true/10000", pol.RotationRequired, pol.MaxUsageCount)
	}
	var resp SetKeyPolicyResponse
	decodeEnvelope(t, w, &resp)
	if resp.PolicyVersion != 1 {
		t.Errorf("PolicyVersion = %d, want 1", resp.PolicyVersion)
	}
}

// TestSetKeyPolicy_InvalidExpiresIn verifies a malformed duration is
// rejected with 400 before reaching the SDK.
func TestSetKeyPolicy_InvalidExpiresIn(t *testing.T) {
	fake := &fakeKMSClient{}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.SetKeyPolicy(w, parityRequest(t, http.MethodPut, "/api/v1/kms/keys/db-key/policy", "db-key",
		&SetKeyPolicyRequest{ExpiresIn: "not-a-duration"}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if fake.setPolicyReq != nil {
		t.Error("SDK SetKeyPolicy was called despite invalid expires_in")
	}
}

// TestSetKeyPolicy_InvalidOperation verifies an unknown operation name is
// rejected with 400 before reaching the SDK.
func TestSetKeyPolicy_InvalidOperation(t *testing.T) {
	fake := &fakeKMSClient{}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.SetKeyPolicy(w, parityRequest(t, http.MethodPut, "/api/v1/kms/keys/db-key/policy", "db-key",
		&SetKeyPolicyRequest{Operations: []string{"launder"}}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if fake.setPolicyReq != nil {
		t.Error("SDK SetKeyPolicy was called despite invalid operation")
	}
}

// =============================================================================
// ListAlgorithms / BackendStatus
// =============================================================================

// TestListAlgorithms_Success verifies the supported algorithm list is
// passed through from the SDK.
func TestListAlgorithms_Success(t *testing.T) {
	fake := &fakeKMSClient{
		algorithms: &kmsclient.SupportedAlgorithmsResponse{
			Algorithms: []string{"AES-256-GCM", "RSA-2048", "ECDSA-P256"},
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.ListAlgorithms(w, httptest.NewRequest(http.MethodGet, "/api/v1/kms/algorithms", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp ListAlgorithmsResponse
	decodeEnvelope(t, w, &resp)
	if len(resp.Algorithms) != 3 || resp.Algorithms[0] != "AES-256-GCM" {
		t.Errorf("Algorithms = %v, want passthrough of 3 entries", resp.Algorithms)
	}
}

// TestListAlgorithms_SDKError verifies SDK failures surface as 500.
func TestListAlgorithms_SDKError(t *testing.T) {
	fake := &fakeKMSClient{algorithmsErr: errors.New("backend unreachable")}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.ListAlgorithms(w, httptest.NewRequest(http.MethodGet, "/api/v1/kms/algorithms", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
}

// TestBackendStatus_Success verifies backend health fields are surfaced.
func TestBackendStatus_Success(t *testing.T) {
	fake := &fakeKMSClient{
		backendStatus: &kmsclient.BackendStatusResponse{
			BackendType:  "pkcs8",
			Status:       "healthy",
			Capabilities: map[string]bool{"encryption": true},
		},
	}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.BackendStatus(w, httptest.NewRequest(http.MethodGet, "/api/v1/kms/backend/status", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp BackendStatusResponse
	decodeEnvelope(t, w, &resp)
	if resp.BackendType != "pkcs8" || resp.Status != "healthy" {
		t.Errorf("backend = %q/%q, want pkcs8/healthy", resp.BackendType, resp.Status)
	}
	if !resp.Capabilities["encryption"] {
		t.Error("Capabilities[encryption] = false, want true")
	}
}

// TestBackendStatus_Unavailable verifies a nil KMS client yields the
// service-unavailable envelope instead of a panic.
func TestBackendStatus_Unavailable(t *testing.T) {
	h := newParityTestHandlers(nil, nil)

	w := httptest.NewRecorder()
	h.BackendStatus(w, httptest.NewRequest(http.MethodGet, "/api/v1/kms/backend/status", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
}

// =============================================================================
// Secrets rotation policy retain_versions
// =============================================================================

// TestGetRotationPolicy_RetainVersions verifies retain_versions is
// surfaced on the secrets rotation-policy wire contract.
func TestGetRotationPolicy_RetainVersions(t *testing.T) {
	fake := &fakeSecretsClient{
		policy: &secretsclient.RotationPolicy{
			Enabled:        true,
			Interval:       24 * time.Hour,
			RetainVersions: 10,
		},
	}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.GetRotationPolicy(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets/db-pass/policy", "db-pass", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp RotationPolicyResponse
	decodeEnvelope(t, w, &resp)
	if resp.RetainVersions != 10 {
		t.Errorf("RetainVersions = %d, want 10", resp.RetainVersions)
	}
	if resp.IntervalSeconds != 86400 {
		t.Errorf("IntervalSeconds = %d, want 86400", resp.IntervalSeconds)
	}
}

// TestGetRotationPolicy_NotFound verifies SDK not-found errors map to 404.
func TestGetRotationPolicy_NotFound(t *testing.T) {
	fake := &fakeSecretsClient{policyErr: errors.New("secrets.GetRotationPolicy: rotation policy not found")}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.GetRotationPolicy(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets/missing/policy", "missing", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", w.Code, w.Body.String())
	}
}

// TestSetRotationPolicy_RetainVersionsForwarded verifies retain_versions
// reaches the SDK rotation policy.
func TestSetRotationPolicy_RetainVersionsForwarded(t *testing.T) {
	fake := &fakeSecretsClient{}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.SetRotationPolicy(w, parityRequest(t, http.MethodPut, "/api/v1/kms/secrets/db-pass/policy", "db-pass",
		&RotationPolicyRequest{
			Enabled:         true,
			IntervalSeconds: 86400,
			RetainVersions:  10,
		}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if fake.setReq == nil {
		t.Fatal("SDK SetRotationPolicy was not called")
	}
	if fake.setReq.Policy.RetainVersions != 10 {
		t.Errorf("RetainVersions = %d, want 10", fake.setReq.Policy.RetainVersions)
	}
	if fake.setReq.Policy.Interval != 24*time.Hour {
		t.Errorf("Interval = %v, want 24h", fake.setReq.Policy.Interval)
	}
}

// TestSetRotationPolicy_SDKError verifies SDK failures surface as errors.
func TestSetRotationPolicy_SDKError(t *testing.T) {
	fake := &fakeSecretsClient{setErr: errors.New("secrets.SetRotationPolicy: invalid input")}
	h := newParityTestHandlers(nil, fake)

	w := httptest.NewRecorder()
	h.SetRotationPolicy(w, parityRequest(t, http.MethodPut, "/api/v1/kms/secrets/db-pass/policy", "db-pass",
		&RotationPolicyRequest{Enabled: true}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
}
