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

package xkms

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mockClient implements xkms.Client for testing.
type mockClient struct {
	connectErr error
	closeErr   error
	closed     bool
	connected  bool
	mu         sync.Mutex

	// Response data for each method
	healthResp               *xkms.HealthResponse
	healthErr                error
	listBackendsResp         *xkms.ListBackendsResponse
	listBackendsErr          error
	getBackendResp           *xkms.BackendInfo
	getBackendErr            error
	generateKeyResp          *xkms.GenerateKeyResponse
	generateKeyErr           error
	listKeysResp             *xkms.ListKeysResponse
	listKeysErr              error
	getKeyResp               *xkms.GetKeyResponse
	getKeyErr                error
	deleteKeyResp            *xkms.DeleteKeyResponse
	deleteKeyErr             error
	signResp                 *xkms.SignResponse
	signErr                  error
	verifyResp               *xkms.VerifyResponse
	verifyErr                error
	encryptResp              *xkms.EncryptResponse
	encryptErr               error
	decryptResp              *xkms.DecryptResponse
	decryptErr               error
	encryptAsymResp          *xkms.EncryptAsymResponse
	encryptAsymErr           error
	getCertificateResp       *xkms.GetCertificateResponse
	getCertificateErr        error
	saveCertificateErr       error
	deleteCertificateErr     error
	certificateExistsResp    bool
	certificateExistsErr     error
	listCertificatesResp     *xkms.ListCertificatesResponse
	listCertificatesErr      error
	saveCertificateChainErr  error
	getCertificateChainResp  *xkms.GetCertificateChainResponse
	getCertificateChainErr   error
	getTLSCertificateResp    *xkms.GetTLSCertificateResponse
	getTLSCertificateErr     error
	importKeyResp            *xkms.ImportKeyResponse
	importKeyErr             error
	exportKeyResp            *xkms.ExportKeyResponse
	exportKeyErr             error
	rotateKeyResp            *xkms.RotateKeyResponse
	rotateKeyErr             error
	getImportParametersResp  *xkms.GetImportParametersResponse
	getImportParametersErr   error
	wrapKeyResp              *xkms.WrapKeyResponse
	wrapKeyErr               error
	unwrapKeyResp            *xkms.UnwrapKeyResponse
	unwrapKeyErr             error
	copyKeyResp              *xkms.CopyKeyResponse
	copyKeyErr               error
	sealResp                 *xkms.SealResponse
	sealErr                  error
	unsealResp               *xkms.UnsealResponse
	unsealErr                error
	canSealResp              *xkms.CanSealResponse
	canSealErr               error
	attestKeyResp            *xkms.AttestKeyResponse
	attestKeyErr             error
	listUsersResp            *xkms.ListUsersResponse
	listUsersErr             error
	createUserResp           *xkms.GetUserResponse
	createUserErr            error
	createUserReq            *xkms.CreateUserRequest
	getUserResp              *xkms.GetUserResponse
	getUserErr               error
	deleteUserErr            error
	enableUserErr            error
	disableUserErr           error
	bindUserCertErr          error
	bindUserCertUsername     string
	bindUserCertThumbprint   string
	bindUserCertNotAfter     int64
	listUserCredentialsResp  *xkms.ListUserCredentialsResponse
	listUserCredentialsErr   error
	beginRegistrationResp    *xkms.BeginRegistrationResponse
	beginRegistrationErr     error
	finishRegistrationResp   *xkms.FinishRegistrationResponse
	finishRegistrationErr    error
	beginAuthenticationResp  *xkms.BeginAuthenticationResponse
	beginAuthenticationErr   error
	finishAuthenticationResp *xkms.FinishAuthenticationResponse
	finishAuthenticationErr  error
	deriveKeyResp            *xkms.DeriveKeyResponse
	deriveKeyErr             error
}

func newMockClient() *mockClient {
	return &mockClient{
		healthResp:               &xkms.HealthResponse{Status: "healthy"},
		listBackendsResp:         &xkms.ListBackendsResponse{},
		getBackendResp:           &xkms.BackendInfo{},
		generateKeyResp:          &xkms.GenerateKeyResponse{},
		listKeysResp:             &xkms.ListKeysResponse{},
		getKeyResp:               &xkms.GetKeyResponse{},
		deleteKeyResp:            &xkms.DeleteKeyResponse{},
		signResp:                 &xkms.SignResponse{},
		verifyResp:               &xkms.VerifyResponse{},
		encryptResp:              &xkms.EncryptResponse{},
		decryptResp:              &xkms.DecryptResponse{},
		encryptAsymResp:          &xkms.EncryptAsymResponse{},
		getCertificateResp:       &xkms.GetCertificateResponse{},
		certificateExistsResp:    true,
		listCertificatesResp:     &xkms.ListCertificatesResponse{},
		getCertificateChainResp:  &xkms.GetCertificateChainResponse{},
		getTLSCertificateResp:    &xkms.GetTLSCertificateResponse{},
		importKeyResp:            &xkms.ImportKeyResponse{},
		exportKeyResp:            &xkms.ExportKeyResponse{},
		rotateKeyResp:            &xkms.RotateKeyResponse{},
		getImportParametersResp:  &xkms.GetImportParametersResponse{},
		wrapKeyResp:              &xkms.WrapKeyResponse{},
		unwrapKeyResp:            &xkms.UnwrapKeyResponse{},
		copyKeyResp:              &xkms.CopyKeyResponse{},
		sealResp:                 &xkms.SealResponse{},
		unsealResp:               &xkms.UnsealResponse{},
		canSealResp:              &xkms.CanSealResponse{},
		listUsersResp:            &xkms.ListUsersResponse{},
		getUserResp:              &xkms.GetUserResponse{},
		listUserCredentialsResp:  &xkms.ListUserCredentialsResponse{},
		beginRegistrationResp:    &xkms.BeginRegistrationResponse{},
		finishRegistrationResp:   &xkms.FinishRegistrationResponse{},
		beginAuthenticationResp:  &xkms.BeginAuthenticationResponse{},
		finishAuthenticationResp: &xkms.FinishAuthenticationResponse{},
		deriveKeyResp:            &xkms.DeriveKeyResponse{},
	}
}

func (m *mockClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closeErr != nil {
		return m.closeErr
	}
	m.closed = true
	return nil
}

func (m *mockClient) Health(ctx context.Context) (*xkms.HealthResponse, error) {
	return m.healthResp, m.healthErr
}

func (m *mockClient) ListBackends(ctx context.Context, opts ...xkms.ListOption) (*xkms.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

func (m *mockClient) GetBackend(ctx context.Context, backendID string) (*xkms.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

func (m *mockClient) GenerateKey(ctx context.Context, req *xkms.GenerateKeyRequest) (*xkms.GenerateKeyResponse, error) {
	return m.generateKeyResp, m.generateKeyErr
}

func (m *mockClient) ListKeys(ctx context.Context, backend string, opts ...xkms.ListOption) (*xkms.ListKeysResponse, error) {
	return m.listKeysResp, m.listKeysErr
}

func (m *mockClient) GetKey(ctx context.Context, backend, keyID string) (*xkms.GetKeyResponse, error) {
	return m.getKeyResp, m.getKeyErr
}

func (m *mockClient) DeleteKey(ctx context.Context, backend, keyID string) (*xkms.DeleteKeyResponse, error) {
	return m.deleteKeyResp, m.deleteKeyErr
}

func (m *mockClient) Sign(ctx context.Context, req *xkms.SignRequest) (*xkms.SignResponse, error) {
	return m.signResp, m.signErr
}

func (m *mockClient) Verify(ctx context.Context, req *xkms.VerifyRequest) (*xkms.VerifyResponse, error) {
	return m.verifyResp, m.verifyErr
}

func (m *mockClient) Encrypt(ctx context.Context, req *xkms.EncryptRequest) (*xkms.EncryptResponse, error) {
	return m.encryptResp, m.encryptErr
}

func (m *mockClient) Decrypt(ctx context.Context, req *xkms.DecryptRequest) (*xkms.DecryptResponse, error) {
	return m.decryptResp, m.decryptErr
}

func (m *mockClient) EncryptAsym(ctx context.Context, req *xkms.EncryptAsymRequest) (*xkms.EncryptAsymResponse, error) {
	return m.encryptAsymResp, m.encryptAsymErr
}

func (m *mockClient) GetCertificate(ctx context.Context, backend, keyID string) (*xkms.GetCertificateResponse, error) {
	return m.getCertificateResp, m.getCertificateErr
}

func (m *mockClient) SaveCertificate(ctx context.Context, req *xkms.SaveCertificateRequest) error {
	return m.saveCertificateErr
}

func (m *mockClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return m.deleteCertificateErr
}

func (m *mockClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return m.certificateExistsResp, m.certificateExistsErr
}

func (m *mockClient) ListCertificates(ctx context.Context, backend string, opts ...xkms.ListOption) (*xkms.ListCertificatesResponse, error) {
	return m.listCertificatesResp, m.listCertificatesErr
}

func (m *mockClient) SaveCertificateChain(ctx context.Context, req *xkms.SaveCertificateChainRequest) error {
	return m.saveCertificateChainErr
}

func (m *mockClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*xkms.GetCertificateChainResponse, error) {
	return m.getCertificateChainResp, m.getCertificateChainErr
}

func (m *mockClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*xkms.GetTLSCertificateResponse, error) {
	return m.getTLSCertificateResp, m.getTLSCertificateErr
}

func (m *mockClient) ImportKey(ctx context.Context, req *xkms.ImportKeyRequest) (*xkms.ImportKeyResponse, error) {
	return m.importKeyResp, m.importKeyErr
}

func (m *mockClient) ExportKey(ctx context.Context, req *xkms.ExportKeyRequest) (*xkms.ExportKeyResponse, error) {
	return m.exportKeyResp, m.exportKeyErr
}

func (m *mockClient) DeriveKey(ctx context.Context, req *xkms.DeriveKeyRequest) (*xkms.DeriveKeyResponse, error) {
	return m.deriveKeyResp, m.deriveKeyErr
}

func (m *mockClient) DeriveKeyECDH(ctx context.Context, req *xkms.DeriveKeyECDHRequest) (*xkms.DeriveKeyECDHResponse, error) {
	return nil, nil
}

func (m *mockClient) RotateKey(ctx context.Context, req *xkms.RotateKeyRequest) (*xkms.RotateKeyResponse, error) {
	return m.rotateKeyResp, m.rotateKeyErr
}

func (m *mockClient) GetImportParameters(ctx context.Context, req *xkms.GetImportParametersRequest) (*xkms.GetImportParametersResponse, error) {
	return m.getImportParametersResp, m.getImportParametersErr
}

func (m *mockClient) WrapKey(ctx context.Context, req *xkms.WrapKeyRequest) (*xkms.WrapKeyResponse, error) {
	return m.wrapKeyResp, m.wrapKeyErr
}

func (m *mockClient) UnwrapKey(ctx context.Context, req *xkms.UnwrapKeyRequest) (*xkms.UnwrapKeyResponse, error) {
	return m.unwrapKeyResp, m.unwrapKeyErr
}

func (m *mockClient) CopyKey(ctx context.Context, req *xkms.CopyKeyRequest) (*xkms.CopyKeyResponse, error) {
	return m.copyKeyResp, m.copyKeyErr
}

func (m *mockClient) Seal(ctx context.Context, req *xkms.SealRequest) (*xkms.SealResponse, error) {
	return m.sealResp, m.sealErr
}

func (m *mockClient) Unseal(ctx context.Context, req *xkms.UnsealRequest) (*xkms.UnsealResponse, error) {
	return m.unsealResp, m.unsealErr
}

func (m *mockClient) CanSeal(ctx context.Context, backend string) (*xkms.CanSealResponse, error) {
	return m.canSealResp, m.canSealErr
}

func (m *mockClient) AttestKey(ctx context.Context, req *xkms.AttestKeyRequest) (*xkms.AttestKeyResponse, error) {
	return m.attestKeyResp, m.attestKeyErr
}

func (m *mockClient) CreateUser(ctx context.Context, req *xkms.CreateUserRequest) (*xkms.GetUserResponse, error) {
	m.createUserReq = req
	return m.createUserResp, m.createUserErr
}

func (m *mockClient) ListUsers(ctx context.Context, opts ...xkms.ListOption) (*xkms.ListUsersResponse, error) {
	return m.listUsersResp, m.listUsersErr
}

func (m *mockClient) GetUser(ctx context.Context, username string) (*xkms.GetUserResponse, error) {
	return m.getUserResp, m.getUserErr
}

func (m *mockClient) DeleteUser(ctx context.Context, username string) error {
	return m.deleteUserErr
}

func (m *mockClient) EnableUser(ctx context.Context, username string) error {
	return m.enableUserErr
}

func (m *mockClient) DisableUser(ctx context.Context, username string) error {
	return m.disableUserErr
}

func (m *mockClient) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	m.bindUserCertUsername = username
	m.bindUserCertThumbprint = thumbprint
	m.bindUserCertNotAfter = notAfterUnix
	return m.bindUserCertErr
}

func (m *mockClient) ListUserCredentials(ctx context.Context, username string) (*xkms.ListUserCredentialsResponse, error) {
	return m.listUserCredentialsResp, m.listUserCredentialsErr
}

func (m *mockClient) BeginRegistration(ctx context.Context, req *xkms.BeginRegistrationRequest) (*xkms.BeginRegistrationResponse, error) {
	return m.beginRegistrationResp, m.beginRegistrationErr
}

func (m *mockClient) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
	return m.finishRegistrationResp, m.finishRegistrationErr
}

func (m *mockClient) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
	return m.beginAuthenticationResp, m.beginAuthenticationErr
}

func (m *mockClient) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
	return m.finishAuthenticationResp, m.finishAuthenticationErr
}

func (m *mockClient) WrapKeyByID(ctx context.Context, req *xkms.WrapKeyByIDRequest) (*xkms.WrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockClient) UnwrapKeyByID(ctx context.Context, req *xkms.UnwrapKeyByIDRequest) (*xkms.UnwrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockClient) ExportKeyMaterial(ctx context.Context, req *xkms.ExportKeyMaterialRequest) (*xkms.ExportKeyMaterialResponse, error) {
	return nil, nil
}

// BarrierService stubs

func (m *mockClient) BarrierInitialize(ctx context.Context, req *xkms.BarrierInitializeRequest) error {
	return nil
}

func (m *mockClient) BarrierUnseal(ctx context.Context, req *xkms.BarrierUnsealRequest) error {
	return nil
}

func (m *mockClient) BarrierSeal(ctx context.Context) error {
	return nil
}

func (m *mockClient) BarrierStatus(ctx context.Context) (*xkms.BarrierStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierInitializeShamir(ctx context.Context, req *xkms.BarrierInitializeShamirRequest) (*xkms.BarrierInitializeShamirResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierUnsealWithShare(ctx context.Context, req *xkms.BarrierUnsealShareRequest) (*xkms.BarrierUnsealShareResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierUnsealWithShares(ctx context.Context, req *xkms.BarrierUnsealSharesRequest) error {
	return nil
}

func (m *mockClient) BarrierRekey(ctx context.Context, req *xkms.BarrierRekeyRequest) (*xkms.BarrierRekeyResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierGenerateRecoveryKeys(ctx context.Context, req *xkms.BarrierGenerateRecoveryKeysRequest) (*xkms.BarrierRecoveryKeysResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierRecoverWithKeys(ctx context.Context, req *xkms.BarrierRecoverWithKeysRequest) error {
	return nil
}

func (m *mockClient) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	return nil
}

func (m *mockClient) BarrierHasRecoveryKeys(ctx context.Context) (*xkms.BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierGenerateRootToken(ctx context.Context, req *xkms.BarrierGenerateRootTokenRequest) (*xkms.BarrierRootTokenResponse, error) {
	return nil, nil
}

func (m *mockClient) BarrierEnableEncryption(ctx context.Context, req *xkms.BarrierEnableEncryptionRequest) (*xkms.BarrierEnableEncryptionResponse, error) {
	return nil, nil
}

// PIVService stubs

func (m *mockClient) ListPIVSlots(ctx context.Context, req *xkms.ListPIVSlotsRequest) (*xkms.ListPIVSlotsResponse, error) {
	return nil, nil
}

func (m *mockClient) GetPIVCertificate(ctx context.Context, req *xkms.GetPIVCertificateRequest) (*xkms.GetPIVCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) StorePIVCertificate(ctx context.Context, req *xkms.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) DeletePIVCertificate(ctx context.Context, req *xkms.DeletePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) GeneratePIVKey(ctx context.Context, req *xkms.GeneratePIVKeyRequest) (*xkms.GeneratePIVKeyResponse, error) {
	return nil, nil
}

func (m *mockClient) ImportPIVCertificate(ctx context.Context, req *xkms.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) ExportPIVCertificate(ctx context.Context, req *xkms.GetPIVCertificateRequest) (*xkms.GetPIVCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) GeneratePIVCSR(ctx context.Context, req *xkms.GeneratePIVCSRRequest) (*xkms.GeneratePIVCSRResponse, error) {
	return nil, nil
}

// CAService stubs

func (m *mockClient) GetCABundle(ctx context.Context, req *xkms.GetCABundleRequest) (*xkms.GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockClient) GetCACertificate(ctx context.Context, req *xkms.GetCACertificateRequest) (*xkms.GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) SignCSR(ctx context.Context, req *xkms.SignCSRRequest) (*xkms.SignCSRResponse, error) {
	return nil, nil
}

func (m *mockClient) IssueCertificate(ctx context.Context, req *xkms.IssueCertificateRequest) (*xkms.IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) RevokeCertificate(ctx context.Context, req *xkms.RevokeCertificateRequest) (*xkms.RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) GenerateCRL(ctx context.Context, req *xkms.GenerateCRLRequest) (*xkms.GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockClient) IsRevoked(ctx context.Context, req *xkms.IsRevokedRequest) (*xkms.IsRevokedResponse, error) {
	return nil, nil
}

// TCGCAService stubs

func (m *mockClient) IssueEKCertificate(ctx context.Context, req *xkms.IssueEKCertificateRequest) (*xkms.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) IssueAKCertificate(ctx context.Context, req *xkms.IssueAKCertificateRequest) (*xkms.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockClient) SignTCGCSR(ctx context.Context, req *xkms.SignTCGCSRRequest) (*xkms.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockClient) EnrollDevice(ctx context.Context, req *xkms.EnrollDeviceRequest) (*xkms.EnrollDeviceResponse, error) {
	return nil, nil
}

// PINService stubs

func (m *mockClient) SetSOPIN(ctx context.Context, req *xkms.SetSOPINRequest) error {
	return nil
}

func (m *mockClient) SetUserPIN(ctx context.Context, req *xkms.SetUserPINRequest) error {
	return nil
}

func (m *mockClient) ChangeSOPIN(ctx context.Context, req *xkms.ChangeSOPINRequest) error {
	return nil
}

func (m *mockClient) ChangeUserPIN(ctx context.Context, req *xkms.ChangeUserPINRequest) error {
	return nil
}

func (m *mockClient) VerifySOPIN(ctx context.Context, req *xkms.VerifySOPINRequest) error {
	return nil
}

func (m *mockClient) VerifyUserPIN(ctx context.Context, req *xkms.VerifyUserPINRequest) error {
	return nil
}

func (m *mockClient) GetLockoutStatus(ctx context.Context) (*xkms.LockoutStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) ResetLockout(ctx context.Context, req *xkms.ResetLockoutRequest) error {
	return nil
}

// PasswordService stubs

func (m *mockClient) PasswordAdd(ctx context.Context, req *xkms.PasswordAddRequest) (*xkms.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockClient) PasswordGet(ctx context.Context, req *xkms.PasswordGetRequest) (*xkms.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockClient) PasswordList(ctx context.Context, req *xkms.PasswordListRequest) (*xkms.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockClient) PasswordUpdate(ctx context.Context, req *xkms.PasswordUpdateRequest) error {
	return nil
}

func (m *mockClient) PasswordDelete(ctx context.Context, req *xkms.PasswordDeleteRequest) error {
	return nil
}

func (m *mockClient) PasswordStoreUnlock(ctx context.Context, req *xkms.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockClient) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockClient) PasswordStoreStatus(ctx context.Context) (*xkms.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) PasswordStoreSetAccessMode(ctx context.Context, req *xkms.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockClient) PasswordGenerate(ctx context.Context, req *xkms.PasswordGenerateRequest) (*xkms.PasswordGenerateResponse, error) {
	return nil, nil
}

// SealStoreService stubs

func (m *mockClient) SealStorePut(ctx context.Context, req *xkms.SealStorePutRequest) error {
	return nil
}

func (m *mockClient) SealStoreGet(ctx context.Context, req *xkms.SealStoreGetRequest) (*xkms.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockClient) SealStoreDelete(ctx context.Context, req *xkms.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockClient) SealStoreList(ctx context.Context) (*xkms.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockClient) SealStoreReseal(ctx context.Context, req *xkms.SealStoreResealRequest) error {
	return nil
}

func (m *mockClient) SealStoreStatus(ctx context.Context) (*xkms.SealStoreStatusResponse, error) {
	return nil, nil
}

// PolicyService stubs

func (m *mockClient) PolicyCreate(ctx context.Context, req *xkms.PolicyCreateRequest) (*xkms.PolicyCreateResponse, error) {
	return nil, nil
}

func (m *mockClient) PolicyGet(ctx context.Context, req *xkms.PolicyGetRequest) (*xkms.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockClient) PolicyList(ctx context.Context) (*xkms.PolicyListResponse, error) {
	return nil, nil
}

func (m *mockClient) PolicyDelete(ctx context.Context, req *xkms.PolicyDeleteRequest) error {
	return nil
}

func (m *mockClient) PolicyRefresh(ctx context.Context, req *xkms.PolicyRefreshRequest) (*xkms.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockClient) PolicyVerify(ctx context.Context, req *xkms.PolicyVerifyRequest) (*xkms.PolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockClient) PolicyExport(ctx context.Context, req *xkms.PolicyExportRequest) (*xkms.PolicyExportResponse, error) {
	return nil, nil
}

// CustodianGroupService stubs

func (m *mockClient) CreateCustodianGroup(ctx context.Context, req *xkms.CreateCustodianGroupRequest) (*xkms.CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockClient) GetCustodianGroup(ctx context.Context, groupID string) (*xkms.GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockClient) ListCustodianGroups(ctx context.Context) (*xkms.ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *mockClient) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return nil
}

func (m *mockClient) AddCustodianMember(ctx context.Context, req *xkms.AddCustodianMemberRequest) (*xkms.AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *mockClient) RemoveCustodianMember(ctx context.Context, req *xkms.RemoveCustodianMemberRequest) error {
	return nil
}

func (m *mockClient) DistributeShares(ctx context.Context, req *xkms.DistributeSharesRequest) (*xkms.DistributeSharesResponse, error) {
	return nil, nil
}

// ShareService stubs

func (m *mockClient) SubmitShare(ctx context.Context, req *xkms.SubmitShareRequest) (*xkms.SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockClient) ListShares(ctx context.Context) (*xkms.ListSharesResponse, error) {
	return nil, nil
}

func (m *mockClient) GetShareCollectionStatus(ctx context.Context, groupID string) (*xkms.ShareCollectionStatus, error) {
	return nil, nil
}

// TenantService stubs

func (m *mockClient) CreateTenant(ctx context.Context, req *xkms.CreateTenantRequest) (*xkms.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockClient) GetTenant(ctx context.Context, tenantID string) (*xkms.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockClient) ListTenants(ctx context.Context) (*xkms.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockClient) DeleteTenant(ctx context.Context, tenantID string) error {
	return nil
}

func (m *mockClient) TenantBarrierInit(ctx context.Context, req *xkms.TenantBarrierInitRequest) error {
	return nil
}

func (m *mockClient) TenantBarrierUnseal(ctx context.Context, req *xkms.TenantBarrierUnsealRequest) error {
	return nil
}

func (m *mockClient) TenantBarrierStatus(ctx context.Context, tenantID string) (*xkms.TenantBarrierStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) UpdateTenantEntitlements(ctx context.Context, req *xkms.UpdateTenantEntitlementsRequest) (*xkms.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockClient) UpdateTenantQuotas(ctx context.Context, req *xkms.UpdateTenantQuotasRequest) (*xkms.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// InitCeremonyService stubs

func (m *mockClient) GetInitStatus(ctx context.Context) (*xkms.InitStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) ClaimCertBegin(ctx context.Context, req *xkms.ClaimCertBeginRequest) (*xkms.ClaimCertBeginResponse, error) {
	return nil, nil
}

func (m *mockClient) ClaimCertComplete(ctx context.Context, req *xkms.ClaimCertCompleteRequest) (*xkms.ClaimCertCompleteResponse, error) {
	return nil, nil
}

func (m *mockClient) ClaimShareBegin(ctx context.Context, req *xkms.ClaimShareBeginRequest) (*xkms.ClaimShareBeginResponse, error) {
	return nil, nil
}

func (m *mockClient) ClaimShareComplete(ctx context.Context, req *xkms.ClaimShareCompleteRequest) (*xkms.ClaimShareCompleteResponse, error) {
	return nil, nil
}

func (m *mockClient) SignCSRInit(ctx context.Context, req *xkms.SignCSRInitRequest) (*xkms.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService stubs

func (m *mockClient) SubmitCredential(ctx context.Context, req *xkms.CredentialSubmitRequest) (*xkms.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockClient) GetCredentialStrategy(ctx context.Context) (*xkms.CredentialStrategyResponse, error) {
	return nil, nil
}

// createTestAdapterWithMock creates an adapter with a pre-injected mock client.
func createTestAdapterWithMock(t *testing.T, mock *mockClient) *Adapter {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}
	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	// Inject the mock client directly
	adapter.client = mock
	adapter.started.Store(true)
	return adapter
}

func TestNewAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("valid_config", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportEmbedded,
			RequestTimeout: 30 * time.Second,
		}

		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if adapter == nil {
			t.Fatal("expected adapter, got nil")
		}
		if adapter.IsStarted() {
			t.Error("expected adapter to not be started")
		}
		if adapter.IsClosed() {
			t.Error("expected adapter to not be closed")
		}
	})

	t.Run("nil_config", func(t *testing.T) {
		adapter, err := NewAdapter(nil, logger)
		if err != ErrNilConfig {
			t.Errorf("expected ErrNilConfig, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}

		adapter, err := NewAdapter(cfg, nil)
		if err != ErrNilLogger {
			t.Errorf("expected ErrNilLogger, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("invalid_config_validation", func(t *testing.T) {
		cfg := &Config{
			Transport: "invalid-transport",
		}

		adapter, err := NewAdapter(cfg, logger)
		if err == nil {
			t.Error("expected error for invalid config")
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
		var unsupportedErr ErrUnsupportedTransport
		if !errors.As(err, &unsupportedErr) {
			t.Errorf("expected ErrUnsupportedTransport, got %T", err)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("embedded_mode_defaults", func(t *testing.T) {
		cfg := &Config{}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportEmbedded {
			t.Errorf("expected transport to be embedded, got %s", cfg.Transport)
		}
		if cfg.RequestTimeout != DefaultRequestTimeout {
			t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
		}
	})

	t.Run("remote_mode_inferred", func(t *testing.T) {
		cfg := &Config{
			Backend: "xkms-cluster",
			Address: "localhost:9443",
			TLS:     &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportGRPC {
			t.Errorf("expected transport to be grpc, got %s", cfg.Transport)
		}
	})

	t.Run("unix_missing_socket", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportUnix,
		}
		err := cfg.Validate()
		if err != ErrMissingUnixSocket {
			t.Errorf("expected ErrMissingUnixSocket, got %v", err)
		}
	})

	t.Run("unix_with_socket", func(t *testing.T) {
		cfg := &Config{
			Transport:  TransportUnix,
			UnixSocket: "/tmp/xkms.sock",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("grpc_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("grpc_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:9443",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("rest_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("rest_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
			Address:   "https://localhost:8443",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("quic_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("quic_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
			Address:   "localhost:8444",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("mcp_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("mcp_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
			Address:   "localhost:9444",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("unsupported_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: "invalid",
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for unsupported transport")
		}
		_, ok := err.(ErrUnsupportedTransport)
		if !ok {
			t.Errorf("expected ErrUnsupportedTransport, got %T", err)
		}
	})
}

func TestConfig_IsEmbedded(t *testing.T) {
	t.Run("empty_config_is_embedded", func(t *testing.T) {
		cfg := &Config{}
		if !cfg.IsEmbedded() {
			t.Error("expected empty config to be embedded")
		}
	})

	t.Run("explicit_embedded", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		if !cfg.IsEmbedded() {
			t.Error("expected explicit embedded transport to be embedded")
		}
	})

	t.Run("with_backend_is_remote", func(t *testing.T) {
		cfg := &Config{
			Backend: "xkms-cluster",
		}
		if cfg.IsEmbedded() {
			t.Error("expected config with backend to be remote")
		}
		if !cfg.IsRemote() {
			t.Error("expected config with backend to be remote")
		}
	})

	t.Run("grpc_is_remote", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:9443",
		}
		if cfg.IsEmbedded() {
			t.Error("expected gRPC transport to be remote")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Transport != TransportEmbedded {
		t.Errorf("expected embedded transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestRemoteConfig(t *testing.T) {
	cfg := RemoteConfig("localhost:9443", TransportGRPC)
	if cfg.Address != "localhost:9443" {
		t.Errorf("expected address localhost:9443, got %s", cfg.Address)
	}
	if cfg.Transport != TransportGRPC {
		t.Errorf("expected gRPC transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestUnixConfig(t *testing.T) {
	cfg := UnixConfig("/tmp/xkms.sock")
	if cfg.UnixSocket != "/tmp/xkms.sock" {
		t.Errorf("expected socket /tmp/xkms.sock, got %s", cfg.UnixSocket)
	}
	if cfg.Transport != TransportUnix {
		t.Errorf("expected Unix transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestAdapter_NotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()

	// All operations should return ErrAdapterNotStarted when not started
	_, err = adapter.Health(ctx)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Health, got %v", err)
	}

	_, err = adapter.ListBackends(ctx)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ListBackends, got %v", err)
	}

	_, err = adapter.GetBackend(ctx, "software")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetBackend, got %v", err)
	}

	_, err = adapter.GenerateKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GenerateKey, got %v", err)
	}

	_, err = adapter.ListKeys(ctx, "software")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ListKeys, got %v", err)
	}

	_, err = adapter.GetKey(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetKey, got %v", err)
	}

	_, err = adapter.DeleteKey(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from DeleteKey, got %v", err)
	}

	_, err = adapter.Sign(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Sign, got %v", err)
	}

	_, err = adapter.Verify(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Verify, got %v", err)
	}

	_, err = adapter.Encrypt(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Encrypt, got %v", err)
	}

	_, err = adapter.Decrypt(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Decrypt, got %v", err)
	}

	_, err = adapter.EncryptAsym(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from EncryptAsym, got %v", err)
	}

	_, err = adapter.GetCertificate(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetCertificate, got %v", err)
	}

	err = adapter.SaveCertificate(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from SaveCertificate, got %v", err)
	}

	err = adapter.DeleteCertificate(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from DeleteCertificate, got %v", err)
	}

	_, err = adapter.CertificateExists(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from CertificateExists, got %v", err)
	}

	_, err = adapter.ListCertificates(ctx, "software")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ListCertificates, got %v", err)
	}

	err = adapter.SaveCertificateChain(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from SaveCertificateChain, got %v", err)
	}

	_, err = adapter.GetCertificateChain(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetCertificateChain, got %v", err)
	}

	_, err = adapter.GetTLSCertificate(ctx, "software", "test-key")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetTLSCertificate, got %v", err)
	}

	_, err = adapter.ImportKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ImportKey, got %v", err)
	}

	_, err = adapter.ExportKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ExportKey, got %v", err)
	}

	_, err = adapter.RotateKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from RotateKey, got %v", err)
	}

	_, err = adapter.GetImportParameters(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetImportParameters, got %v", err)
	}

	_, err = adapter.WrapKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from WrapKey, got %v", err)
	}

	_, err = adapter.UnwrapKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from UnwrapKey, got %v", err)
	}

	_, err = adapter.CopyKey(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from CopyKey, got %v", err)
	}

	_, err = adapter.Seal(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Seal, got %v", err)
	}

	_, err = adapter.Unseal(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from Unseal, got %v", err)
	}

	_, err = adapter.CanSeal(ctx, "tpm2")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from CanSeal, got %v", err)
	}

	_, err = adapter.ListUsers(ctx)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ListUsers, got %v", err)
	}

	_, err = adapter.GetUser(ctx, "testuser")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from GetUser, got %v", err)
	}

	err = adapter.DeleteUser(ctx, "testuser")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from DeleteUser, got %v", err)
	}

	err = adapter.EnableUser(ctx, "testuser")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from EnableUser, got %v", err)
	}

	err = adapter.DisableUser(ctx, "testuser")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from DisableUser, got %v", err)
	}

	_, err = adapter.ListUserCredentials(ctx, "testuser")
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from ListUserCredentials, got %v", err)
	}

	_, err = adapter.BeginRegistration(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from BeginRegistration, got %v", err)
	}

	_, err = adapter.FinishRegistration(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from FinishRegistration, got %v", err)
	}

	_, err = adapter.BeginAuthentication(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from BeginAuthentication, got %v", err)
	}

	_, err = adapter.FinishAuthentication(ctx, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted from FinishAuthentication, got %v", err)
	}

	// Client should return nil when not started
	if adapter.Client() != nil {
		t.Error("expected Client() to return nil when not started")
	}
}

func TestAdapter_EmbeddedRequiresService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()

	// Starting embedded without a service should fail
	err = adapter.Start(ctx, nil)
	if err != ErrEmbeddedServiceRequired {
		t.Errorf("expected ErrEmbeddedServiceRequired, got %v", err)
	}
}

func TestAdapter_StopBeforeStart(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()

	// Stop before start should not error
	err = adapter.Stop(ctx)
	if err != nil {
		t.Errorf("expected no error stopping unstated adapter, got %v", err)
	}
}

func TestAdapter_TransportHelpers(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("embedded_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be true")
		}
		if adapter.IsRemote() {
			t.Error("expected IsRemote() to be false")
		}
		if adapter.Transport() != TransportEmbedded {
			t.Errorf("expected Transport() to be embedded, got %s", adapter.Transport())
		}
	})

	t.Run("grpc_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:9443",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
		if adapter.Transport() != TransportGRPC {
			t.Errorf("expected Transport() to be grpc, got %s", adapter.Transport())
		}
	})

	t.Run("rest_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
			Address:   "https://localhost:8443",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
		if adapter.Transport() != TransportREST {
			t.Errorf("expected Transport() to be rest, got %s", adapter.Transport())
		}
	})

	t.Run("unix_transport", func(t *testing.T) {
		cfg := &Config{
			Transport:  TransportUnix,
			UnixSocket: "/tmp/xkms.sock",
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
		if adapter.Transport() != TransportUnix {
			t.Errorf("expected Transport() to be unix, got %s", adapter.Transport())
		}
	})

	t.Run("quic_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
			Address:   "localhost:8444",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
		if adapter.Transport() != TransportQUIC {
			t.Errorf("expected Transport() to be quic, got %s", adapter.Transport())
		}
	})

	t.Run("mcp_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
			Address:   "localhost:9444",
			TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
		if adapter.Transport() != TransportMCP {
			t.Errorf("expected Transport() to be mcp, got %s", adapter.Transport())
		}
	})
}

func TestAdapter_ConfigAccessor(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport:      TransportEmbedded,
		RequestTimeout: 60 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	returnedConfig := adapter.Config()
	if returnedConfig != cfg {
		t.Error("expected Config() to return the same config instance")
	}
	if returnedConfig.RequestTimeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", returnedConfig.RequestTimeout)
	}
}

func TestAdapterError(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := &AdapterError{Component: "xkms",
			Op:  "test",
			Msg: "test error",
		}
		expected := "xkms adapter test: test error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Component: "xkms", Op: "cause", Msg: "underlying error"}
		err := &AdapterError{Component: "xkms",
			Op:    "test",
			Msg:   "test error",
			Cause: cause,
		}
		expected := "xkms adapter test: test error: xkms adapter cause: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})

	t.Run("with_cause_method", func(t *testing.T) {
		base := &AdapterError{Component: "xkms",
			Op:  "test",
			Msg: "test error",
		}
		cause := &AdapterError{Component: "xkms", Op: "cause", Msg: "underlying error"}
		err := base.WithCause(cause)
		if err.Cause != cause {
			t.Error("expected WithCause to set cause")
		}
		if err.Op != base.Op {
			t.Error("expected WithCause to preserve Op")
		}
		if err.Msg != base.Msg {
			t.Error("expected WithCause to preserve Msg")
		}
	})
}

func TestErrUnsupportedTransport(t *testing.T) {
	err := ErrUnsupportedTransport{Transport: "invalid"}
	expected := "xkms adapter: unsupported transport: invalid"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrConnectionFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrConnectionFailed{
			Address:   "localhost:9443",
			Transport: TransportGRPC,
		}
		expected := "xkms adapter: connection failed to localhost:9443 via grpc"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Component: "xkms", Op: "dial", Msg: "connection refused"}
		err := ErrConnectionFailed{
			Address:   "localhost:9443",
			Transport: TransportGRPC,
			Cause:     cause,
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
		// Also test the error message includes the cause
		errMsg := err.Error()
		if !strings.Contains(errMsg, "connection refused") {
			t.Errorf("expected error message to contain 'connection refused', got %q", errMsg)
		}
	})
}

func TestErrServiceUnavailable(t *testing.T) {
	err := ErrServiceUnavailable{Service: "keys"}
	expected := "xkms adapter: service unavailable: keys"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrBackendNotFound(t *testing.T) {
	err := ErrBackendNotFound{Backend: "tpm2"}
	expected := "xkms adapter: backend not found: tpm2"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSecretResolutionFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrSecretResolutionFailed{URI: "kms://platform/tls/key"}
		expected := "xkms adapter: secret resolution failed for kms://platform/tls/key"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Component: "xkms", Op: "lookup", Msg: "secret not found"}
		err := ErrSecretResolutionFailed{
			URI:   "kms://platform/tls/key",
			Cause: cause,
		}
		// Test Error() method with cause (covers the if branch)
		errMsg := err.Error()
		if !strings.Contains(errMsg, "kms://platform/tls/key") {
			t.Errorf("expected error message to contain URI, got %q", errMsg)
		}
		if !strings.Contains(errMsg, "secret not found") {
			t.Errorf("expected error message to contain cause, got %q", errMsg)
		}
		// Test Unwrap()
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})
}

func TestErrKeyNotFound(t *testing.T) {
	err := ErrKeyNotFound{Backend: "software", KeyID: "test-key"}
	expected := "xkms adapter: key not found: backend=software, key=test-key"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrCertificateNotFound(t *testing.T) {
	err := ErrCertificateNotFound{Backend: "software", KeyID: "test-key"}
	expected := "xkms adapter: certificate not found: backend=software, key=test-key"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestTLSConfig(t *testing.T) {
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:9443",
		TLS: &TLSConfig{
			CACert:     "/etc/ssl/ca.crt",
			ClientCert: "/etc/ssl/client.crt",
			ClientKey:  "/etc/ssl/client.key",
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.TLS.CACert != "/etc/ssl/ca.crt" {
		t.Errorf("expected CACert to be /etc/ssl/ca.crt, got %s", cfg.TLS.CACert)
	}
	if cfg.TLS.ClientCert != "/etc/ssl/client.crt" {
		t.Errorf("expected ClientCert to be /etc/ssl/client.crt, got %s", cfg.TLS.ClientCert)
	}
	if cfg.TLS.ClientKey != "/etc/ssl/client.key" {
		t.Errorf("expected ClientKey to be /etc/ssl/client.key, got %s", cfg.TLS.ClientKey)
	}
}

func TestPoolConfig(t *testing.T) {
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:9443",
		TLS:       &TLSConfig{CACert: "/etc/ssl/ca.crt"},
		Pool: &PoolConfig{
			MaxConnections: 100,
			MinConnections: 10,
			MaxIdleTime:    5 * time.Minute,
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Pool.MaxConnections != 100 {
		t.Errorf("expected MaxConnections to be 100, got %d", cfg.Pool.MaxConnections)
	}
	if cfg.Pool.MinConnections != 10 {
		t.Errorf("expected MinConnections to be 10, got %d", cfg.Pool.MinConnections)
	}
	if cfg.Pool.MaxIdleTime != 5*time.Minute {
		t.Errorf("expected MaxIdleTime to be 5m, got %v", cfg.Pool.MaxIdleTime)
	}
}

func TestAdapter_StartAfterClose(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Manually set closed state
	adapter.closed.Store(true)

	ctx := context.Background()

	// Starting after close should return error
	err = adapter.Start(ctx, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed, got %v", err)
	}
}

func TestAdapter_DoubleStop(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()

	// First stop should succeed
	err = adapter.Stop(ctx)
	if err != nil {
		t.Errorf("expected no error on first stop, got %v", err)
	}

	// Second stop should also succeed (idempotent)
	err = adapter.Stop(ctx)
	if err != nil {
		t.Errorf("expected no error on second stop, got %v", err)
	}
}

func TestAdapter_StartIdempotent(t *testing.T) {
	mock := newMockClient()
	adapter := createTestAdapterWithMock(t, mock)

	ctx := context.Background()

	// Adapter is already started by createTestAdapterWithMock
	// Starting again should be a no-op
	err := adapter.Start(ctx, nil)
	if err != nil {
		t.Errorf("expected no error on second start, got %v", err)
	}
}

func TestAdapter_ClientReturnsNilWhenClosed(t *testing.T) {
	mock := newMockClient()
	adapter := createTestAdapterWithMock(t, mock)

	// Verify client is returned when started
	if adapter.Client() == nil {
		t.Error("expected Client() to return client when started")
	}

	// Close the adapter
	adapter.closed.Store(true)

	// Client should return nil when closed
	if adapter.Client() != nil {
		t.Error("expected Client() to return nil when closed")
	}
}

func TestAdapter_StopWithClientCloseError(t *testing.T) {
	mock := newMockClient()
	mock.closeErr = errors.New("close failed")

	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}
	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	adapter.client = mock
	adapter.started.Store(true)

	ctx := context.Background()
	err = adapter.Stop(ctx)
	if err == nil {
		t.Error("expected error from Stop when client close fails")
	}
	if err.Error() != "close failed" {
		t.Errorf("expected 'close failed' error, got %v", err)
	}
}

func TestAdapter_OperationsWithMockedClient(t *testing.T) {
	ctx := context.Background()

	t.Run("health_operations", func(t *testing.T) {
		mock := newMockClient()
		mock.healthResp = &xkms.HealthResponse{Status: "healthy"}
		adapter := createTestAdapterWithMock(t, mock)

		resp, err := adapter.Health(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status != "healthy" {
			t.Error("expected healthy response")
		}
	})

	t.Run("health_error", func(t *testing.T) {
		mock := newMockClient()
		mock.healthErr = errors.New("health check failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.Health(ctx)
		if err == nil {
			t.Error("expected error from Health")
		}
	})

	t.Run("backend_operations", func(t *testing.T) {
		mock := newMockClient()
		mock.listBackendsResp = &xkms.ListBackendsResponse{}
		mock.getBackendResp = &xkms.BackendInfo{ID: "software"}
		adapter := createTestAdapterWithMock(t, mock)

		listResp, err := adapter.ListBackends(ctx)
		if err != nil {
			t.Errorf("unexpected error from ListBackends: %v", err)
		}
		if listResp == nil {
			t.Error("expected response from ListBackends")
		}

		getResp, err := adapter.GetBackend(ctx, "software")
		if err != nil {
			t.Errorf("unexpected error from GetBackend: %v", err)
		}
		if getResp == nil || getResp.ID != "software" {
			t.Error("expected backend info response")
		}
	})

	t.Run("backend_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.listBackendsErr = errors.New("list failed")
		mock.getBackendErr = errors.New("get failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.ListBackends(ctx)
		if err == nil {
			t.Error("expected error from ListBackends")
		}

		_, err = adapter.GetBackend(ctx, "software")
		if err == nil {
			t.Error("expected error from GetBackend")
		}
	})

	t.Run("key_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.GenerateKey(ctx, &xkms.GenerateKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from GenerateKey: %v", err)
		}

		_, err = adapter.ListKeys(ctx, "software")
		if err != nil {
			t.Errorf("unexpected error from ListKeys: %v", err)
		}

		_, err = adapter.GetKey(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from GetKey: %v", err)
		}

		_, err = adapter.DeleteKey(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from DeleteKey: %v", err)
		}
	})

	t.Run("key_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.generateKeyErr = errors.New("generate failed")
		mock.listKeysErr = errors.New("list failed")
		mock.getKeyErr = errors.New("get failed")
		mock.deleteKeyErr = errors.New("delete failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.GenerateKey(ctx, nil)
		if err == nil {
			t.Error("expected error from GenerateKey")
		}

		_, err = adapter.ListKeys(ctx, "software")
		if err == nil {
			t.Error("expected error from ListKeys")
		}

		_, err = adapter.GetKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from GetKey")
		}

		_, err = adapter.DeleteKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from DeleteKey")
		}
	})

	t.Run("crypto_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.Sign(ctx, &xkms.SignRequest{})
		if err != nil {
			t.Errorf("unexpected error from Sign: %v", err)
		}

		_, err = adapter.Verify(ctx, &xkms.VerifyRequest{})
		if err != nil {
			t.Errorf("unexpected error from Verify: %v", err)
		}

		_, err = adapter.Encrypt(ctx, &xkms.EncryptRequest{})
		if err != nil {
			t.Errorf("unexpected error from Encrypt: %v", err)
		}

		_, err = adapter.Decrypt(ctx, &xkms.DecryptRequest{})
		if err != nil {
			t.Errorf("unexpected error from Decrypt: %v", err)
		}

		_, err = adapter.EncryptAsym(ctx, &xkms.EncryptAsymRequest{})
		if err != nil {
			t.Errorf("unexpected error from EncryptAsym: %v", err)
		}
	})

	t.Run("crypto_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.signErr = errors.New("sign failed")
		mock.verifyErr = errors.New("verify failed")
		mock.encryptErr = errors.New("encrypt failed")
		mock.decryptErr = errors.New("decrypt failed")
		mock.encryptAsymErr = errors.New("encrypt asym failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.Sign(ctx, nil)
		if err == nil {
			t.Error("expected error from Sign")
		}

		_, err = adapter.Verify(ctx, nil)
		if err == nil {
			t.Error("expected error from Verify")
		}

		_, err = adapter.Encrypt(ctx, nil)
		if err == nil {
			t.Error("expected error from Encrypt")
		}

		_, err = adapter.Decrypt(ctx, nil)
		if err == nil {
			t.Error("expected error from Decrypt")
		}

		_, err = adapter.EncryptAsym(ctx, nil)
		if err == nil {
			t.Error("expected error from EncryptAsym")
		}
	})

	t.Run("certificate_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.GetCertificate(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from GetCertificate: %v", err)
		}

		err = adapter.SaveCertificate(ctx, &xkms.SaveCertificateRequest{})
		if err != nil {
			t.Errorf("unexpected error from SaveCertificate: %v", err)
		}

		err = adapter.DeleteCertificate(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from DeleteCertificate: %v", err)
		}

		exists, err := adapter.CertificateExists(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from CertificateExists: %v", err)
		}
		if !exists {
			t.Error("expected certificate to exist")
		}

		_, err = adapter.ListCertificates(ctx, "software")
		if err != nil {
			t.Errorf("unexpected error from ListCertificates: %v", err)
		}

		err = adapter.SaveCertificateChain(ctx, &xkms.SaveCertificateChainRequest{})
		if err != nil {
			t.Errorf("unexpected error from SaveCertificateChain: %v", err)
		}

		_, err = adapter.GetCertificateChain(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from GetCertificateChain: %v", err)
		}

		_, err = adapter.GetTLSCertificate(ctx, "software", "test-key")
		if err != nil {
			t.Errorf("unexpected error from GetTLSCertificate: %v", err)
		}
	})

	t.Run("certificate_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.getCertificateErr = errors.New("get cert failed")
		mock.saveCertificateErr = errors.New("save cert failed")
		mock.deleteCertificateErr = errors.New("delete cert failed")
		mock.certificateExistsErr = errors.New("exists check failed")
		mock.listCertificatesErr = errors.New("list certs failed")
		mock.saveCertificateChainErr = errors.New("save chain failed")
		mock.getCertificateChainErr = errors.New("get chain failed")
		mock.getTLSCertificateErr = errors.New("get tls cert failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.GetCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from GetCertificate")
		}

		err = adapter.SaveCertificate(ctx, nil)
		if err == nil {
			t.Error("expected error from SaveCertificate")
		}

		err = adapter.DeleteCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from DeleteCertificate")
		}

		_, err = adapter.CertificateExists(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from CertificateExists")
		}

		_, err = adapter.ListCertificates(ctx, "software")
		if err == nil {
			t.Error("expected error from ListCertificates")
		}

		err = adapter.SaveCertificateChain(ctx, nil)
		if err == nil {
			t.Error("expected error from SaveCertificateChain")
		}

		_, err = adapter.GetCertificateChain(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from GetCertificateChain")
		}

		_, err = adapter.GetTLSCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("expected error from GetTLSCertificate")
		}
	})

	t.Run("import_export_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.ImportKey(ctx, &xkms.ImportKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from ImportKey: %v", err)
		}

		_, err = adapter.ExportKey(ctx, &xkms.ExportKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from ExportKey: %v", err)
		}

		_, err = adapter.RotateKey(ctx, &xkms.RotateKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from RotateKey: %v", err)
		}

		_, err = adapter.GetImportParameters(ctx, &xkms.GetImportParametersRequest{})
		if err != nil {
			t.Errorf("unexpected error from GetImportParameters: %v", err)
		}

		_, err = adapter.WrapKey(ctx, &xkms.WrapKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from WrapKey: %v", err)
		}

		_, err = adapter.UnwrapKey(ctx, &xkms.UnwrapKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from UnwrapKey: %v", err)
		}

		_, err = adapter.CopyKey(ctx, &xkms.CopyKeyRequest{})
		if err != nil {
			t.Errorf("unexpected error from CopyKey: %v", err)
		}
	})

	t.Run("import_export_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.importKeyErr = errors.New("import failed")
		mock.exportKeyErr = errors.New("export failed")
		mock.rotateKeyErr = errors.New("rotate failed")
		mock.getImportParametersErr = errors.New("get params failed")
		mock.wrapKeyErr = errors.New("wrap failed")
		mock.unwrapKeyErr = errors.New("unwrap failed")
		mock.copyKeyErr = errors.New("copy failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.ImportKey(ctx, nil)
		if err == nil {
			t.Error("expected error from ImportKey")
		}

		_, err = adapter.ExportKey(ctx, nil)
		if err == nil {
			t.Error("expected error from ExportKey")
		}

		_, err = adapter.RotateKey(ctx, nil)
		if err == nil {
			t.Error("expected error from RotateKey")
		}

		_, err = adapter.GetImportParameters(ctx, nil)
		if err == nil {
			t.Error("expected error from GetImportParameters")
		}

		_, err = adapter.WrapKey(ctx, nil)
		if err == nil {
			t.Error("expected error from WrapKey")
		}

		_, err = adapter.UnwrapKey(ctx, nil)
		if err == nil {
			t.Error("expected error from UnwrapKey")
		}

		_, err = adapter.CopyKey(ctx, nil)
		if err == nil {
			t.Error("expected error from CopyKey")
		}
	})

	t.Run("sealing_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.Seal(ctx, &xkms.SealRequest{})
		if err != nil {
			t.Errorf("unexpected error from Seal: %v", err)
		}

		_, err = adapter.Unseal(ctx, &xkms.UnsealRequest{})
		if err != nil {
			t.Errorf("unexpected error from Unseal: %v", err)
		}

		_, err = adapter.CanSeal(ctx, "tpm2")
		if err != nil {
			t.Errorf("unexpected error from CanSeal: %v", err)
		}
	})

	t.Run("sealing_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.sealErr = errors.New("seal failed")
		mock.unsealErr = errors.New("unseal failed")
		mock.canSealErr = errors.New("can seal check failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.Seal(ctx, nil)
		if err == nil {
			t.Error("expected error from Seal")
		}

		_, err = adapter.Unseal(ctx, nil)
		if err == nil {
			t.Error("expected error from Unseal")
		}

		_, err = adapter.CanSeal(ctx, "tpm2")
		if err == nil {
			t.Error("expected error from CanSeal")
		}
	})

	t.Run("user_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.ListUsers(ctx)
		if err != nil {
			t.Errorf("unexpected error from ListUsers: %v", err)
		}

		_, err = adapter.GetUser(ctx, "testuser")
		if err != nil {
			t.Errorf("unexpected error from GetUser: %v", err)
		}

		err = adapter.DeleteUser(ctx, "testuser")
		if err != nil {
			t.Errorf("unexpected error from DeleteUser: %v", err)
		}

		err = adapter.EnableUser(ctx, "testuser")
		if err != nil {
			t.Errorf("unexpected error from EnableUser: %v", err)
		}

		err = adapter.DisableUser(ctx, "testuser")
		if err != nil {
			t.Errorf("unexpected error from DisableUser: %v", err)
		}

		_, err = adapter.ListUserCredentials(ctx, "testuser")
		if err != nil {
			t.Errorf("unexpected error from ListUserCredentials: %v", err)
		}
	})

	t.Run("user_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.listUsersErr = errors.New("list users failed")
		mock.getUserErr = errors.New("get user failed")
		mock.deleteUserErr = errors.New("delete user failed")
		mock.enableUserErr = errors.New("enable user failed")
		mock.disableUserErr = errors.New("disable user failed")
		mock.listUserCredentialsErr = errors.New("list credentials failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.ListUsers(ctx)
		if err == nil {
			t.Error("expected error from ListUsers")
		}

		_, err = adapter.GetUser(ctx, "testuser")
		if err == nil {
			t.Error("expected error from GetUser")
		}

		err = adapter.DeleteUser(ctx, "testuser")
		if err == nil {
			t.Error("expected error from DeleteUser")
		}

		err = adapter.EnableUser(ctx, "testuser")
		if err == nil {
			t.Error("expected error from EnableUser")
		}

		err = adapter.DisableUser(ctx, "testuser")
		if err == nil {
			t.Error("expected error from DisableUser")
		}

		_, err = adapter.ListUserCredentials(ctx, "testuser")
		if err == nil {
			t.Error("expected error from ListUserCredentials")
		}
	})

	t.Run("auth_operations", func(t *testing.T) {
		mock := newMockClient()
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.BeginRegistration(ctx, &xkms.BeginRegistrationRequest{})
		if err != nil {
			t.Errorf("unexpected error from BeginRegistration: %v", err)
		}

		_, err = adapter.FinishRegistration(ctx, &xkms.FinishRegistrationRequest{})
		if err != nil {
			t.Errorf("unexpected error from FinishRegistration: %v", err)
		}

		_, err = adapter.BeginAuthentication(ctx, &xkms.BeginAuthenticationRequest{})
		if err != nil {
			t.Errorf("unexpected error from BeginAuthentication: %v", err)
		}

		_, err = adapter.FinishAuthentication(ctx, &xkms.FinishAuthenticationRequest{})
		if err != nil {
			t.Errorf("unexpected error from FinishAuthentication: %v", err)
		}
	})

	t.Run("auth_errors", func(t *testing.T) {
		mock := newMockClient()
		mock.beginRegistrationErr = errors.New("begin registration failed")
		mock.finishRegistrationErr = errors.New("finish registration failed")
		mock.beginAuthenticationErr = errors.New("begin auth failed")
		mock.finishAuthenticationErr = errors.New("finish auth failed")
		adapter := createTestAdapterWithMock(t, mock)

		_, err := adapter.BeginRegistration(ctx, nil)
		if err == nil {
			t.Error("expected error from BeginRegistration")
		}

		_, err = adapter.FinishRegistration(ctx, nil)
		if err == nil {
			t.Error("expected error from FinishRegistration")
		}

		_, err = adapter.BeginAuthentication(ctx, nil)
		if err == nil {
			t.Error("expected error from BeginAuthentication")
		}

		_, err = adapter.FinishAuthentication(ctx, nil)
		if err == nil {
			t.Error("expected error from FinishAuthentication")
		}
	})
}

func TestAdapter_ConcurrentAccess(t *testing.T) {
	mock := newMockClient()
	adapter := createTestAdapterWithMock(t, mock)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Run concurrent operations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = adapter.Health(ctx)
			_ = adapter.IsStarted()
			_ = adapter.IsClosed()
			_ = adapter.IsEmbedded()
			_ = adapter.IsRemote()
			_ = adapter.Transport()
			_ = adapter.Config()
			_ = adapter.Client()
		}()
	}

	wg.Wait()
}
