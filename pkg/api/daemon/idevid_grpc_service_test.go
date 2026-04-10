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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock TPM2 Service for IDevID Tests
// =============================================================================

// idevIDTestTPM embeds TrustedPlatformModule interface and overrides needed methods.
type idevIDTestTPM struct {
	xkmssdk.TrustedPlatformModule

	// Key attribute functions
	ekAttributesResult     *xkmssdk.KeyAttributes
	ekAttributesErr        error
	iakAttributesResult    *xkmssdk.KeyAttributes
	iakAttributesErr       error
	idevidAttributesResult *xkmssdk.KeyAttributes
	idevidAttributesErr    error

	// Creation results
	createIAKResult    *xkmssdk.KeyAttributes
	createIAKErr       error
	createIDevIDResult *xkmssdk.KeyAttributes
	createIDevIDErr    error

	// Certificate functions
	readIDevIDCertResult *x509.Certificate
	readIDevIDCertErr    error
	writeIDevIDCertErr   error
	deleteIDevIDCertErr  error
	readIAKCertResult    *x509.Certificate
	readIAKCertErr       error
	writeIAKCertErr      error
	deleteIAKCertErr     error

	// Property results
	fixedPropsResult *xkmssdk.PropertiesFixed
	fixedPropsErr    error

	// Credential results
	activateCredResult []byte
	activateCredErr    error

	// CSR creation
	createTCGCSRResult xkmssdk.TCG_CSR_IDEVID
	createTCGCSRErr    error
}

func newIDevIDTestTPM() *idevIDTestTPM {
	return &idevIDTestTPM{
		ekAttributesResult: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000000),
			},
		},
		iakAttributesResult: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		idevidAttributesResult: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000002),
			},
		},
		createIAKResult: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		createIDevIDResult: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000002),
			},
		},
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "TEST",
			Family:       "2.0",
			FwMajor:      1,
			FwMinor:      0,
		},
		activateCredResult: []byte("decrypted-secret"),
	}
}

func (m *idevIDTestTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ekAttributesResult, m.ekAttributesErr
}

func (m *idevIDTestTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.iakAttributesResult, m.iakAttributesErr
}

func (m *idevIDTestTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.idevidAttributesResult, m.idevidAttributesErr
}

func (m *idevIDTestTPM) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	return m.createIAKResult, m.createIAKErr
}

func (m *idevIDTestTPM) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
	return m.createIDevIDResult, nil, m.createIDevIDErr
}

func (m *idevIDTestTPM) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, akAttrs *xkmssdk.KeyAttributes, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createTCGCSRErr != nil {
		return xkmssdk.TCG_CSR_IDEVID{}, m.createTCGCSRErr
	}
	return m.createTCGCSRResult, nil
}

func (m *idevIDTestTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return m.fixedPropsResult, m.fixedPropsErr
}

func (m *idevIDTestTPM) IDevIDCertificate() (*x509.Certificate, error) {
	if m.readIDevIDCertErr != nil {
		return nil, m.readIDevIDCertErr
	}
	if m.readIDevIDCertResult != nil {
		return m.readIDevIDCertResult, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *idevIDTestTPM) ProvisionIDevIDCert(cert *x509.Certificate) error {
	return m.writeIDevIDCertErr
}

func (m *idevIDTestTPM) DeleteIDevIDCertificate() error {
	return m.deleteIDevIDCertErr
}

func (m *idevIDTestTPM) IAKCertificate() (*x509.Certificate, error) {
	if m.readIAKCertErr != nil {
		return nil, m.readIAKCertErr
	}
	if m.readIAKCertResult != nil {
		return m.readIAKCertResult, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *idevIDTestTPM) ProvisionIAKCert(cert *x509.Certificate) error {
	return m.writeIAKCertErr
}

func (m *idevIDTestTPM) DeleteIAKCertificate() error {
	return m.deleteIAKCertErr
}

func (m *idevIDTestTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return m.activateCredResult, m.activateCredErr
}

// =============================================================================
// Helper Functions
// =============================================================================

func createIDevIDTestService(t *testing.T) *IDevIDGRPCService {
	t.Helper()
	logger := logging.DefaultLogger()
	return NewIDevIDGRPCService(logger)
}

func createIDevIDTestServiceWithTPM(t *testing.T) (*IDevIDGRPCService, *idevIDTestTPM) {
	t.Helper()
	logger := logging.DefaultLogger()
	svc := NewIDevIDGRPCService(logger)
	tpm := newIDevIDTestTPM()
	svc.SetTPM2Service(tpm)
	return svc, tpm
}

func createIDevIDTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-idevid",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func createIDevIDTestCertificatePEM(t *testing.T) []byte {
	t.Helper()
	cert := createIDevIDTestCertificate(t)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewIDevIDGRPCService(t *testing.T) {
	t.Run("creates service with logger", func(t *testing.T) {
		logger := logging.DefaultLogger()
		svc := NewIDevIDGRPCService(logger)

		assert.NotNil(t, svc)
		assert.Equal(t, logger, svc.logger)
		assert.Nil(t, svc.tpm2Service)
	})
}

func TestIDevIDGRPCService_SetTPM2Service(t *testing.T) {
	svc := createIDevIDTestService(t)
	assert.Nil(t, svc.tpm2Service)

	tpm := newIDevIDTestTPM()
	svc.SetTPM2Service(tpm)

	assert.NotNil(t, svc.tpm2Service)
}

// =============================================================================
// GenerateIDevID Tests
// =============================================================================

func TestIDevIDGRPCService_GenerateIDevID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("generates IDevID successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles EK attributes error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.ekAttributesErr = errors.New("EK not found")

		resp, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("handles IAK creation error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.createIAKErr = errors.New("IAK creation failed")

		resp, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("handles IDevID creation error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.createIDevIDErr = errors.New("IDevID creation failed")

		resp, err := svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})
}

// =============================================================================
// GetIDevIDInfo Tests
// =============================================================================

func TestIDevIDGRPCService_GetIDevIDInfo(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns IDevID info successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.KeyInfo)
	})

	t.Run("returns not found when IDevID not present", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.idevidAttributesErr = errors.New("IDevID not found")

		resp, err := svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns info with certificate when present", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.readIDevIDCertResult = createIDevIDTestCertificate(t)

		resp, err := svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.KeyInfo.HasCertificate)
		assert.NotNil(t, resp.KeyInfo.CertificateInfo)
	})
}

// =============================================================================
// HasIDevID Tests
// =============================================================================

func TestIDevIDGRPCService_HasIDevID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns true when IDevID exists", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Exists)
	})

	t.Run("returns false when IDevID does not exist", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.idevidAttributesErr = errors.New("not found")

		resp, err := svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})

		require.NoError(t, err)
		assert.False(t, resp.Exists)
	})
}

// =============================================================================
// DeleteIDevID Tests
// =============================================================================

func TestIDevIDGRPCService_DeleteIDevID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("deletes IDevID successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})

	t.Run("continues when certificate deletion fails", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.deleteIDevIDCertErr = errors.New("certificate not found")

		resp, err := svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})
}

// =============================================================================
// GenerateIAK Tests
// =============================================================================

func TestIDevIDGRPCService_GenerateIAK(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("generates IAK successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles EK attributes error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.ekAttributesErr = errors.New("EK not found")

		resp, err := svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("handles IAK creation error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.createIAKErr = errors.New("IAK creation failed")

		resp, err := svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})
}

// =============================================================================
// GetIAKInfo Tests
// =============================================================================

func TestIDevIDGRPCService_GetIAKInfo(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns IAK info successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.KeyInfo)
	})

	t.Run("returns not found when IAK not present", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.iakAttributesErr = errors.New("IAK not found")

		resp, err := svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// =============================================================================
// HasIAK Tests
// =============================================================================

func TestIDevIDGRPCService_HasIAK(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.HasIAK(ctx, &platformv1.HasIAKRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns true when IAK exists", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.HasIAK(ctx, &platformv1.HasIAKRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Exists)
	})

	t.Run("returns false when IAK does not exist", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.iakAttributesErr = errors.New("not found")

		resp, err := svc.HasIAK(ctx, &platformv1.HasIAKRequest{})

		require.NoError(t, err)
		assert.False(t, resp.Exists)
	})
}

// =============================================================================
// DeleteIAK Tests
// =============================================================================

func TestIDevIDGRPCService_DeleteIAK(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("deletes IAK successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})
}

// =============================================================================
// Certificate Operation Tests
// =============================================================================

func TestIDevIDGRPCService_InstallIDevIDCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty certificate", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
			CertificatePem: []byte{},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for invalid PEM", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
			CertificatePem: []byte("not-a-pem"),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("installs certificate successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles install error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.writeIDevIDCertErr = errors.New("install failed")

		resp, err := svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
	})
}

func TestIDevIDGRPCService_InstallIAKCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty certificate", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: []byte{},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for invalid PEM", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: []byte("not a valid PEM"),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for invalid certificate", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		invalidPEM := "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n"

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: []byte(invalidPEM),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when write fails", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.writeIAKCertErr = errors.New("write failed")

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("installs IAK certificate successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
			CertificatePem: createIDevIDTestCertificatePEM(t),
		})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})
}

func TestIDevIDGRPCService_GetIDevIDCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns certificate successfully", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.readIDevIDCertResult = createIDevIDTestCertificate(t)

		resp, err := svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp.Certificate)
	})

	t.Run("returns not found when certificate missing", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

func TestIDevIDGRPCService_GetIAKCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns not found when certificate missing", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns certificate successfully", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.readIAKCertResult = createIDevIDTestCertificate(t)

		resp, err := svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp.Certificate)
	})
}

func TestIDevIDGRPCService_DeleteIDevIDCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("deletes certificate successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})

	t.Run("handles deletion error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.deleteIDevIDCertErr = errors.New("deletion failed")

		resp, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})
}

func TestIDevIDGRPCService_DeleteIAKCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("handles deletion error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.deleteIAKCertErr = errors.New("deletion failed")

		resp, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("deletes certificate successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
	})
}

// =============================================================================
// Device Attribute Tests
// =============================================================================

func TestIDevIDGRPCService_GetDeviceAttributes(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns device attributes successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp.Attributes)
		assert.Equal(t, "TEST", resp.Attributes.TpmManufacturer)
	})

	t.Run("handles fixed properties error gracefully", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.fixedPropsErr = errors.New("properties unavailable")

		resp, err := svc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp.Attributes)
		// TPM fields should be empty but platform fields should be populated
		assert.Empty(t, resp.Attributes.TpmManufacturer)
	})
}

// =============================================================================
// ActivateCredential Tests
// =============================================================================

func TestIDevIDGRPCService_ActivateCredential(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
			CredentialBlob: []byte("cred"),
			Secret:         []byte("secret"),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for empty credential blob", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
			CredentialBlob: []byte{},
			Secret:         []byte("secret"),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty secret", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
			CredentialBlob: []byte("cred"),
			Secret:         []byte{},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("activates credential successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
			CredentialBlob: []byte("cred"),
			Secret:         []byte("secret"),
		})

		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.NotEmpty(t, resp.DecryptedSecret)
	})

	t.Run("handles activation error", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.activateCredErr = errors.New("activation failed")

		resp, err := svc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
			CredentialBlob: []byte("cred"),
			Secret:         []byte("secret"),
		})

		assert.Nil(t, resp)
		require.Error(t, err)
	})
}

// =============================================================================
// FlushTransientContexts Tests
// =============================================================================

func TestIDevIDGRPCService_FlushTransientContexts(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns unimplemented", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestIDevIDGRPCService_CertToProto(t *testing.T) {
	svc := createIDevIDTestService(t)

	t.Run("returns nil for nil certificate", func(t *testing.T) {
		result := svc.certToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("converts certificate to proto", func(t *testing.T) {
		cert := createIDevIDTestCertificate(t)
		result := svc.certToProto(cert)

		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Pem)
		assert.NotEmpty(t, result.Der)
		assert.NotEmpty(t, result.Fingerprint)
		assert.Equal(t, "test-idevid", result.SubjectCn)
		assert.Equal(t, "ECDSA", result.KeyType)
	})
}

func TestIDevIDGRPCService_MapTPM2Error(t *testing.T) {
	svc := createIDevIDTestService(t)

	tests := []struct {
		name       string
		err        error
		operation  string
		expectCode codes.Code
	}{
		{"nil error", nil, "test", codes.OK},
		{"not found error", errors.New("key not found"), "test", codes.NotFound},
		{"does not exist error", errors.New("file does not exist"), "test", codes.NotFound},
		{"already exists error", errors.New("key already exists"), "test", codes.AlreadyExists},
		{"duplicate error", errors.New("duplicate entry"), "test", codes.AlreadyExists},
		{"invalid error", errors.New("invalid input"), "test", codes.InvalidArgument},
		{"permission error", errors.New("permission denied"), "test", codes.PermissionDenied},
		{"timeout error", errors.New("operation timeout"), "test", codes.DeadlineExceeded},
		{"unavailable error", errors.New("TPM unavailable"), "test", codes.Unavailable},
		{"generic error", errors.New("something went wrong"), "test", codes.Internal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.mapTPM2Error(tc.err, tc.operation)
			if tc.err == nil {
				assert.Nil(t, result)
			} else {
				st, ok := status.FromError(result)
				require.True(t, ok)
				assert.Equal(t, tc.expectCode, st.Code())
			}
		})
	}
}

// =============================================================================
// CreateIDevIDCSR Tests
// =============================================================================

func TestIDevIDGRPCService_CreateIDevIDCSR(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when IDevID attributes not found", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.idevidAttributesErr = errors.New("IDevID not found")

		resp, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns error when IAK attributes not found", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.iakAttributesErr = errors.New("IAK not found")

		resp, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns error when CSR creation fails", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.createTCGCSRErr = errors.New("CSR creation failed")

		resp, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("creates IDevID CSR successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})
}

// =============================================================================
// CreateIAKCSR Tests
// =============================================================================

func TestIDevIDGRPCService_CreateIAKCSR(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when TPM2 service not initialized", func(t *testing.T) {
		svc := createIDevIDTestService(t)

		resp, err := svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when IAK attributes not found", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.iakAttributesErr = errors.New("IAK not found")

		resp, err := svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns error when CSR creation fails", func(t *testing.T) {
		svc, tpm := createIDevIDTestServiceWithTPM(t)
		tpm.createTCGCSRErr = errors.New("CSR creation failed")

		resp, err := svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
	})

	t.Run("creates IAK CSR successfully", func(t *testing.T) {
		svc, _ := createIDevIDTestServiceWithTPM(t)

		resp, err := svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Status.Success)
	})
}

// =============================================================================
// certToProto Tests - Additional Key Algorithm Coverage
// =============================================================================

func TestIDevIDGRPCService_CertToProto_KeyAlgorithms(t *testing.T) {
	svc := createIDevIDTestService(t)

	t.Run("handles nil certificate", func(t *testing.T) {
		result := svc.certToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("handles ECDSA certificate", func(t *testing.T) {
		cert := createIDevIDTestCertificate(t)
		result := svc.certToProto(cert)

		assert.NotNil(t, result)
		assert.Equal(t, "ECDSA", result.KeyAlgorithm)
		assert.NotEmpty(t, result.Pem)
		assert.NotEmpty(t, result.Der)
		assert.NotEmpty(t, result.Fingerprint)
		assert.NotEmpty(t, result.SerialNumber)
	})

	t.Run("handles RSA certificate", func(t *testing.T) {
		// Create RSA certificate
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test-rsa",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)

		result := svc.certToProto(cert)

		assert.NotNil(t, result)
		assert.Equal(t, "RSA", result.KeyAlgorithm)
		assert.Equal(t, "RSA", result.KeyType)
	})

	t.Run("handles Ed25519 certificate", func(t *testing.T) {
		// Create Ed25519 certificate
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test-ed25519",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)

		result := svc.certToProto(cert)

		assert.NotNil(t, result)
		assert.Equal(t, "Ed25519", result.KeyAlgorithm)
		assert.Equal(t, "Ed25519", result.KeyType)
	})
}
