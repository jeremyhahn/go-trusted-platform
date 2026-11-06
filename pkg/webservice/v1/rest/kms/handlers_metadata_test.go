package kms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

// metadataNotFoundError is the fake's answer for a key it never generated.
type metadataNotFoundError struct {
	name string
}

func (e *metadataNotFoundError) Error() string {
	return "key not found: " + e.name
}

// metadataUpdateError is the fake's injected UpdateKeyMetadata failure.
type metadataUpdateError struct{}

func (e *metadataUpdateError) Error() string {
	return "metadata update failed"
}

// metadataKMS keeps the keys it generates so their metadata can be read back.
type metadataKMS struct {
	kmsclient.Client
	keys      map[string]*kmsclient.KeyMetadataResponse
	updateErr error
}

func (f *metadataKMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.keys[req.Name] = &kmsclient.KeyMetadataResponse{KeyID: req.Name, Name: req.Name, Algorithm: req.Algorithm}
	return &kmsclient.GenerateKeyResponse{KeyID: req.Name, Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *metadataKMS) UpdateKeyMetadata(_ context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	key, ok := f.keys[req.KeyID]
	if !ok {
		return nil, &metadataNotFoundError{name: req.KeyID}
	}
	key.Description = req.Description
	key.Tags = req.Tags
	return key, nil
}

func (f *metadataKMS) GetKeyMetadata(_ context.Context, name string) (*kmsclient.KeyMetadataResponse, error) {
	key, ok := f.keys[name]
	if !ok {
		return nil, &metadataNotFoundError{name: name}
	}
	return key, nil
}

func (f *metadataKMS) GetKeyRotationPolicy(_ context.Context, _ string) (*kmsclient.KeyRotationPolicy, error) {
	return nil, nil
}

func metadataGenerateBody() map[string]interface{} {
	return map[string]interface{}{
		"name":        "k1",
		"algorithm":   "AES-256-GCM",
		"description": "d1",
		"tags":        map[string]string{"env": "prod"},
	}
}

// TestGenerateKey_RecordsDescriptionAndTags: a generated key keeps the
// requested description and tags, in the 201 and when read back.
func TestGenerateKey_RecordsDescriptionAndTags(t *testing.T) {
	fake := &metadataKMS{keys: map[string]*kmsclient.KeyMetadataResponse{}}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GenerateKey(w, parityRequest(t, http.MethodPost, "/api/v1/kms/keys", "", metadataGenerateBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("GenerateKey status = %d, want 201: %s", w.Code, w.Body.String())
	}
	var gen GenerateKeyResponse
	decodeEnvelope(t, w, &gen)
	if gen.Description != "d1" || gen.Tags["env"] != "prod" {
		t.Errorf("GenerateKey response description=%q tags=%v, want d1 env=prod", gen.Description, gen.Tags)
	}

	w = httptest.NewRecorder()
	h.GetKeyMetadata(w, parityRequest(t, http.MethodGet, "/api/v1/kms/keys/k1", "k1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GetKeyMetadata status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var meta KeyMetadataResponse
	decodeEnvelope(t, w, &meta)
	if meta.Description != "d1" || meta.Tags["env"] != "prod" {
		t.Errorf("read back description=%q tags=%v, want d1 env=prod", meta.Description, meta.Tags)
	}
}

// TestGenerateKey_MetadataUpdateFailureIsNotCreated: a failed metadata
// update is an error response, never a 201.
func TestGenerateKey_MetadataUpdateFailureIsNotCreated(t *testing.T) {
	fake := &metadataKMS{keys: map[string]*kmsclient.KeyMetadataResponse{}, updateErr: &metadataUpdateError{}}
	h := newParityTestHandlers(fake, nil)

	w := httptest.NewRecorder()
	h.GenerateKey(w, parityRequest(t, http.MethodPost, "/api/v1/kms/keys", "", metadataGenerateBody()))
	if w.Code == http.StatusCreated {
		t.Fatalf("GenerateKey status = 201 after a failed metadata update: %s", w.Body.String())
	}
}
