package kms

import (
	"context"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// keyAdminKMS records the key-admin calls the SDK REST round trip makes and
// answers them from fixed values; every key but "kek" is missing.
type keyAdminKMS struct {
	kmsclient.Client
	importReq   *kmsclient.ImportKeyRequest
	statusReq   *kmsclient.UpdateKeyStatusRequest
	versionsKey string
	backendHit  bool
}

func (f *keyAdminKMS) ImportKey(_ context.Context, req *kmsclient.ImportKeyRequest) (*kmsclient.ImportKeyResponse, error) {
	f.importReq = req
	return &kmsclient.ImportKeyResponse{KeyID: req.Name, Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *keyAdminKMS) UpdateKeyStatus(_ context.Context, req *kmsclient.UpdateKeyStatusRequest) (*kmsclient.UpdateKeyStatusResponse, error) {
	f.statusReq = req
	if req.KeyID != "kek" {
		return nil, errKeyNotFound
	}
	return &kmsclient.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
}

var keyAdminCreated = time.Unix(1700000000, 0).UTC()

func (f *keyAdminKMS) ListKeyVersions(_ context.Context, keyID string) (*kmsclient.ListKeyVersionsResponse, error) {
	f.versionsKey = keyID
	if keyID != "kek" {
		return nil, errKeyNotFound
	}
	return &kmsclient.ListKeyVersionsResponse{KeyID: keyID, Versions: []kmsclient.KeyVersionInfo{
		{Version: 1, Status: kmsclient.KeyStatusDisabled, Algorithm: kmsclient.AlgorithmAES256GCM,
			CreatedAt: keyAdminCreated, DisabledAt: keyAdminCreated.Add(time.Hour)},
		{Version: 2, Status: kmsclient.KeyStatusEnabled, Algorithm: kmsclient.AlgorithmAES256GCM,
			CreatedAt: keyAdminCreated.Add(time.Hour)},
	}}, nil
}

func (f *keyAdminKMS) BackendStatus(context.Context) (*kmsclient.BackendStatusResponse, error) {
	f.backendHit = true
	return &kmsclient.BackendStatusResponse{
		BackendType: "tpm2", Status: "healthy", Device: "tpmrm0", KeyID: "srk",
		PCRBanks: []string{"sha256"}, PCRRegisters: []int{0, 7},
		Capabilities: map[string]bool{"seal": true},
	}, nil
}

// TestSDKREST_ImportKey: the name, spec, material and tags reach the KMS
// service, and the imported key's handle reaches the SDK caller.
func TestSDKREST_ImportKey(t *testing.T) {
	kms := &keyAdminKMS{}
	client := kmsOverSDK(t, kms, nil)

	resp, err := client.ImportKey(context.Background(), &platformv1.ImportKeyRequest{
		Name: "kek",
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
			Usage:     []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, platformv1.KeyUsage_KEY_USAGE_DECRYPT},
		},
		KeyMaterial:   []byte("material"),
		WrappingKeyId: "wrap",
		Description:   "imported",
		Tags:          map[string]string{"team": "ops"},
	})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	got := kms.importReq
	wantUsage := []kmsclient.KeyUsage{kmsclient.KeyUsageEncrypt, kmsclient.KeyUsageDecrypt}
	if got == nil || got.Name != "kek" || got.Algorithm != kmsclient.AlgorithmAES256GCM ||
		!reflect.DeepEqual(got.Usage, wantUsage) || string(got.KeyMaterial) != "material" ||
		got.WrappingKeyID != "wrap" || got.Description != "imported" || got.Tags["team"] != "ops" {
		t.Fatalf("service request = %+v", got)
	}
	key := resp.GetKey()
	if key.GetKeyId() != "kek" || key.GetVersion() != 1 ||
		key.GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256 {
		t.Fatalf("reply = %v", resp)
	}
}

// TestSDKREST_UpdateKeyStatus: the key, version and status reach the KMS
// service, and the new status reaches the SDK caller.
func TestSDKREST_UpdateKeyStatus(t *testing.T) {
	kms := &keyAdminKMS{}
	client := kmsOverSDK(t, kms, nil)

	resp, err := client.UpdateKeyStatus(context.Background(), &platformv1.UpdateKeyStatusRequest{
		KeyId: "kek", Version: 3, Status: platformv1.KeyStatus_KEY_STATUS_DISABLED})
	if err != nil {
		t.Fatalf("UpdateKeyStatus: %v", err)
	}
	got := kms.statusReq
	if got == nil || got.KeyID != "kek" || got.Version != 3 || got.Status != kmsclient.KeyStatusDisabled {
		t.Fatalf("service request = %+v", got)
	}
	if resp.GetKeyId() != "kek" || resp.GetVersion() != 3 ||
		resp.GetKeyStatus() != platformv1.KeyStatus_KEY_STATUS_DISABLED {
		t.Fatalf("reply = %v", resp)
	}
}

// TestSDKREST_UpdateKeyStatusUnknownKeyIsNotFound: the route's 404 reaches
// the SDK caller as NotFound.
func TestSDKREST_UpdateKeyStatusUnknownKeyIsNotFound(t *testing.T) {
	kms := &keyAdminKMS{}
	client := kmsOverSDK(t, kms, nil)

	_, err := client.UpdateKeyStatus(context.Background(), &platformv1.UpdateKeyStatusRequest{
		KeyId: "missing", Status: platformv1.KeyStatus_KEY_STATUS_ENABLED})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err %v)", status.Code(err), err)
	}
	if kms.statusReq == nil || kms.statusReq.KeyID != "missing" {
		t.Fatalf("service request = %+v", kms.statusReq)
	}
}

// TestSDKREST_GetKeyVersions: the key reaches the KMS service, and every
// version with its status, algorithm and times reaches the SDK caller.
func TestSDKREST_GetKeyVersions(t *testing.T) {
	kms := &keyAdminKMS{}
	client := kmsOverSDK(t, kms, nil)

	resp, err := client.GetKeyVersions(context.Background(), &platformv1.GetKeyVersionsRequest{KeyId: "kek"})
	if err != nil {
		t.Fatalf("GetKeyVersions: %v", err)
	}
	if kms.versionsKey != "kek" {
		t.Fatalf("service key = %q", kms.versionsKey)
	}
	versions := resp.GetVersions()
	if resp.GetKeyId() != "kek" || len(versions) != 2 {
		t.Fatalf("reply = %v", resp)
	}
	aes := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256
	first, second := versions[0], versions[1]
	if first.GetVersion() != 1 || first.GetStatus() != platformv1.KeyStatus_KEY_STATUS_DISABLED ||
		first.GetAlgorithm() != aes || first.GetCreatedAt() != keyAdminCreated.Unix() ||
		first.GetDisabledAt() != keyAdminCreated.Add(time.Hour).Unix() {
		t.Fatalf("first version = %v", first)
	}
	if second.GetVersion() != 2 || second.GetStatus() != platformv1.KeyStatus_KEY_STATUS_ENABLED ||
		second.GetAlgorithm() != aes || second.GetDisabledAt() != 0 {
		t.Fatalf("second version = %v", second)
	}
}

// TestSDKREST_BackendStatus: the backend's health and capabilities reach the
// SDK caller.
func TestSDKREST_BackendStatus(t *testing.T) {
	kms := &keyAdminKMS{}
	client := kmsOverSDK(t, kms, nil)

	resp, err := client.BackendStatus(context.Background(), &platformv1.BackendStatusRequest{})
	if err != nil {
		t.Fatalf("BackendStatus: %v", err)
	}
	if !kms.backendHit {
		t.Fatal("BackendStatus did not reach the KMS service")
	}
	if resp.GetBackendType() != "tpm2" || resp.GetBackendStatus() != "healthy" || resp.GetDevice() != "tpmrm0" ||
		resp.GetKeyId() != "srk" || !reflect.DeepEqual(resp.GetPcrBanks(), []string{"sha256"}) ||
		!reflect.DeepEqual(resp.GetPcrRegisters(), []int32{0, 7}) || !resp.GetCapabilities()["seal"] {
		t.Fatalf("reply = %v", resp)
	}
}
