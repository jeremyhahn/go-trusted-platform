package grpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// cov964Cause is the wrapped cause the typed-error tests unwrap to.
type cov964Cause struct{}

func (cov964Cause) Error() string { return "backend down" }

func TestCov964_TypedErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"attestation with cause", ErrAttestationOperationFailed{Operation: "quote", Cause: cov964Cause{}}, "attestation operation quote failed: backend down"},
		{"attestation without cause", ErrAttestationOperationFailed{Operation: "quote"}, "attestation operation quote failed"},
		{"attestation unavailable", ErrAttestationServiceUnavailable{}, "attestation service is unavailable"},
		{"sdn bridge not found", ErrSDNBridgeNotFound{BridgeName: "br0"}, "bridge not found: br0"},
		{"sdn port not found", ErrSDNPortNotFound{PortName: "eth1"}, "port not found: eth1"},
		{"sdn bridge exists", ErrSDNBridgeAlreadyExists{BridgeName: "br0"}, "bridge already exists: br0"},
		{"sdn port exists", ErrSDNPortAlreadyExists{PortName: "eth1"}, "port already exists: eth1"},
		{"sdn invalid request", ErrSDNInvalidRequest{Reason: "empty name"}, "invalid request: empty name"},
		{"sdn op with cause", ErrSDNOperationFailed{Operation: "add-flow", Cause: cov964Cause{}}, "SDN operation add-flow failed: backend down"},
		{"sdn op without cause", ErrSDNOperationFailed{Operation: "add-flow"}, "SDN operation add-flow failed"},
		{"authz check with cause", ErrAuthorizationCheckFailed{Method: "/svc/M", Cause: cov964Cause{}}, "authorization check failed for /svc/M: backend down"},
		{"authz check without cause", ErrAuthorizationCheckFailed{Method: "/svc/M"}, "authorization check failed for /svc/M"},
		{"proxy op with cause", ErrProxyOperationFailed{Operation: "list", Cause: cov964Cause{}}, "proxy operation list failed: backend down"},
		{"proxy op without cause", ErrProxyOperationFailed{Operation: "list"}, "proxy operation list failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestCov964_TypedErrorsUnwrapToCause(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"attestation", ErrAttestationOperationFailed{Operation: "quote", Cause: cov964Cause{}}},
		{"authorization check", ErrAuthorizationCheckFailed{Method: "/svc/M", Cause: cov964Cause{}}},
		{"proxy", ErrProxyOperationFailed{Operation: "list", Cause: cov964Cause{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cause cov964Cause
			assert.True(t, errors.As(tt.err, &cause))
			assert.True(t, errors.Is(tt.err, cov964Cause{}))
		})
	}

	t.Run("nil cause unwraps to nil", func(t *testing.T) {
		assert.Nil(t, errors.Unwrap(ErrAttestationOperationFailed{Operation: "quote"}))
		assert.Nil(t, errors.Unwrap(ErrAuthorizationCheckFailed{Method: "/svc/M"}))
		assert.Nil(t, errors.Unwrap(ErrProxyOperationFailed{Operation: "list"}))
	})
}

func TestCov964_RegistryConvertersNilInput(t *testing.T) {
	assert.Nil(t, protoLabelSelectorToRegistry(nil))
	assert.Nil(t, registryArtifactToProto(nil))
	assert.Nil(t, registryManifestToProto(nil))
	assert.Nil(t, registryArtifactDetailToProto(nil))
	assert.Nil(t, registryScanResultToProto(nil))
	assert.Nil(t, registryPaginationToProto(nil))
	assert.Nil(t, registryStorageStatsToProto(nil))
}

func TestCov964_ProtoLabelSelectorToRegistry(t *testing.T) {
	got := protoLabelSelectorToRegistry(&platformv1.LabelSelector{
		MatchLabels:      map[string]string{"app": "web"},
		MatchExpressions: []string{"tier in (front)"},
	})
	require.NotNil(t, got)
	assert.Equal(t, map[string]string{"app": "web"}, got.MatchLabels)
	assert.Equal(t, []string{"tier in (front)"}, got.MatchExpressions)
}

func TestCov964_RegistryArtifactDetailToProto(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanned := created.Add(time.Hour)
	detail := &RegistryArtifactDetail{
		Artifact: &RegistryArtifact{
			ID:           "art-1",
			Repository:   "platform/web",
			Tag:          "v1",
			Digest:       "sha256:aa",
			Type:         ArtifactType(1),
			State:        ArtifactState(2),
			Size:         4096,
			Labels:       map[string]string{"app": "web"},
			Annotations:  map[string]string{"note": "x"},
			OS:           "linux",
			Architecture: "arm64",
			Author:       "ci",
			CreatedAt:    created,
			UpdatedAt:    created,
			PushedAt:     created,
			LastPulledAt: created,
			PullCount:    7,
			Manifest: &RegistryArtifactManifest{
				Digest:       "sha256:mm",
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				Size:         512,
				ConfigDigest: "sha256:cc",
				Annotations:  map[string]string{"m": "1"},
				Layers: []*RegistryArtifactLayer{
					{Digest: "sha256:l1", Size: 100, MediaType: "layer", Compression: CompressionType(1)},
				},
			},
		},
		Signatures: []*RegistryArtifactSignature{
			{KeyID: "k1", Algorithm: "ES256", Signature: []byte{1, 2}, SignedAt: created, Signer: "ca"},
		},
		ScanResult: &RegistryScanResult{
			Scanner:   "trivy",
			ScannedAt: scanned,
			Vulnerabilities: []*RegistryVulnerability{
				{ID: "CVE-1", Severity: VulnerabilitySeverity(3), PackageName: "openssl", PackageVersion: "3.0", FixedVersion: "3.1", Description: "bug", Link: "https://cve"},
			},
			LowCount:      1,
			MediumCount:   2,
			HighCount:     3,
			CriticalCount: 4,
		},
		Tags: []string{"v1", "latest"},
	}

	got := registryArtifactDetailToProto(detail)
	require.NotNil(t, got)
	assert.Equal(t, []string{"v1", "latest"}, got.GetTags())

	a := got.GetArtifact()
	require.NotNil(t, a)
	assert.Equal(t, "art-1", a.GetId())
	assert.Equal(t, "platform/web", a.GetRepository())
	assert.Equal(t, "v1", a.GetTag())
	assert.Equal(t, "sha256:aa", a.GetDigest())
	assert.Equal(t, platformv1.ArtifactType(1), a.GetType())
	assert.Equal(t, platformv1.ArtifactState(2), a.GetState())
	assert.Equal(t, int64(4096), a.GetSize())
	assert.Equal(t, map[string]string{"app": "web"}, a.GetLabels())
	assert.Equal(t, map[string]string{"note": "x"}, a.GetAnnotations())
	assert.Equal(t, "linux", a.GetOs())
	assert.Equal(t, "arm64", a.GetArchitecture())
	assert.Equal(t, "ci", a.GetAuthor())
	assert.Equal(t, created, a.GetCreatedAt().AsTime())
	assert.Equal(t, created, a.GetLastPulledAt().AsTime())
	assert.Equal(t, int64(7), a.GetPullCount())

	m := a.GetManifest()
	require.NotNil(t, m)
	assert.Equal(t, "sha256:mm", m.GetDigest())
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", m.GetMediaType())
	assert.Equal(t, int64(512), m.GetSize())
	assert.Equal(t, "sha256:cc", m.GetConfigDigest())
	assert.Equal(t, map[string]string{"m": "1"}, m.GetAnnotations())
	require.Len(t, m.GetLayers(), 1)
	assert.Equal(t, "sha256:l1", m.GetLayers()[0].GetDigest())
	assert.Equal(t, int64(100), m.GetLayers()[0].GetSize())
	assert.Equal(t, platformv1.CompressionType(1), m.GetLayers()[0].GetCompression())

	require.Len(t, got.GetSignatures(), 1)
	assert.Equal(t, "k1", got.GetSignatures()[0].GetKeyId())
	assert.Equal(t, "ES256", got.GetSignatures()[0].GetAlgorithm())
	assert.Equal(t, []byte{1, 2}, got.GetSignatures()[0].GetSignature())
	assert.Equal(t, "ca", got.GetSignatures()[0].GetSigner())

	s := got.GetScanResult()
	require.NotNil(t, s)
	assert.Equal(t, "trivy", s.GetScanner())
	assert.Equal(t, scanned, s.GetScannedAt().AsTime())
	assert.Equal(t, int32(1), s.GetLowCount())
	assert.Equal(t, int32(2), s.GetMediumCount())
	assert.Equal(t, int32(3), s.GetHighCount())
	assert.Equal(t, int32(4), s.GetCriticalCount())
	require.Len(t, s.GetVulnerabilities(), 1)
	v := s.GetVulnerabilities()[0]
	assert.Equal(t, "CVE-1", v.GetId())
	assert.Equal(t, platformv1.VulnerabilitySeverity(3), v.GetSeverity())
	assert.Equal(t, "openssl", v.GetPackageName())
	assert.Equal(t, "3.1", v.GetFixedVersion())
	assert.Equal(t, "https://cve", v.GetLink())
}

func TestCov964_RegistryPaginationAndStorageStatsToProto(t *testing.T) {
	p := registryPaginationToProto(&RegistryPaginationResponse{Page: 2, PageSize: 50, TotalPages: 3, TotalItems: 120})
	require.NotNil(t, p)
	assert.Equal(t, uint32(2), p.GetPage())
	assert.Equal(t, uint32(50), p.GetPageSize())
	assert.Equal(t, uint32(3), p.GetTotalPages())
	assert.Equal(t, uint64(120), p.GetTotalItems())

	s := registryStorageStatsToProto(&RegistryStorageStats{
		TotalBytes: 1000, UsedBytes: 400, AvailableBytes: 600,
		ArtifactCount: 5, LayerCount: 9, RepositoryCount: 2,
	})
	require.NotNil(t, s)
	assert.Equal(t, int64(1000), s.GetTotalBytes())
	assert.Equal(t, int64(400), s.GetUsedBytes())
	assert.Equal(t, int64(600), s.GetAvailableBytes())
	assert.Equal(t, int64(5), s.GetArtifactCount())
	assert.Equal(t, int64(9), s.GetLayerCount())
	assert.Equal(t, int64(2), s.GetRepositoryCount())
}

// cov964Cert returns a self-signed in-memory certificate built from tmpl.
func cov964Cert(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCov964_CertMatchesIdentifier(t *testing.T) {
	cert := cov964Cert(t, &x509.Certificate{
		SerialNumber: big.NewInt(0xBEEF),
		Subject:      pkix.Name{CommonName: "node-01.example.com"},
	})
	s := &CAGRPCService{}

	tests := []struct {
		name       string
		identifier string
		want       bool
	}{
		{"hex serial", hex.EncodeToString(big.NewInt(0xBEEF).Bytes()), true},
		{"common name, other case", "NODE-01.Example.com", true},
		{"unrelated serial", "dead", false},
		{"unrelated name", "node-02.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, s.certMatchesIdentifier(cert, tt.identifier))
		})
	}
}

func TestCov964_GetCertificateType(t *testing.T) {
	tests := []struct {
		name string
		tmpl *x509.Certificate
		want platformv1.CertificateType
	}{
		{"ca", &x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, platformv1.CertificateType_CERTIFICATE_TYPE_CA},
		{"server", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, platformv1.CertificateType_CERTIFICATE_TYPE_SERVER},
		{"client", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, platformv1.CertificateType_CERTIFICATE_TYPE_CLIENT},
		{"code signing", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}, platformv1.CertificateType_CERTIFICATE_TYPE_CODE_SIGNING},
		{"email", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}, platformv1.CertificateType_CERTIFICATE_TYPE_EMAIL},
		{"unclassified usage", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, platformv1.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED},
		{"no usage", &x509.Certificate{}, platformv1.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED},
	}
	s := &CAGRPCService{}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.tmpl.SerialNumber = big.NewInt(int64(i + 1))
			tt.tmpl.Subject = pkix.Name{CommonName: tt.name}
			assert.Equal(t, tt.want, s.getCertificateType(cov964Cert(t, tt.tmpl)))
		})
	}
}
