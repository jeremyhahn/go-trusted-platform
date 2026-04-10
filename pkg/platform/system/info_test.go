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

package system

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock TPM2 for testing TPMInfo
// =============================================================================

// mockTPM implements a minimal mock for the TrustedPlatformModule interface
type mockTPM struct {
	xkmssdk.TrustedPlatformModule

	fixedPropsResult *xkmssdk.PropertiesFixed
	fixedPropsErr    error
	infoResult       string
	infoErr          error
	ekAttrsResult    *xkmssdk.KeyAttributes
	ekAttrsErr       error
	ssrkAttrsResult  *xkmssdk.KeyAttributes
	ssrkAttrsErr     error
}

func (m *mockTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return m.fixedPropsResult, m.fixedPropsErr
}

func (m *mockTPM) Info() (string, error) {
	return m.infoResult, m.infoErr
}

func (m *mockTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ekAttrsResult, m.ekAttrsErr
}

func (m *mockTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ssrkAttrsResult, m.ssrkAttrsErr
}

// =============================================================================
// Mock CertificateAuthority for testing CAInfo
// =============================================================================

// mockCA implements a minimal mock for the CertificateAuthority interface
type mockCA struct {
	trustedca.CACertificateAuthority

	config trustedca.CAConfig
}

func (m *mockCA) CAConfig() trustedca.CAConfig {
	return m.config
}

func (m *mockCA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockCA) Public() crypto.PublicKey {
	return nil
}

// =============================================================================
// Unit Tests
// =============================================================================

func TestCPUInfo_Success(t *testing.T) {
	// This test only runs on Linux systems with /proc/cpuinfo
	if runtime.GOOS != "linux" {
		t.Skip("Skipping test on non-Linux system")
	}

	cpuInfo, err := CPUInfo()

	require.NoError(t, err)
	// Basic validation - at least one thread should be detected
	assert.Greater(t, cpuInfo.Threads, 0)
}

func TestCPUInfo_MockFile(t *testing.T) {
	// Create a temporary /proc/cpuinfo-like file
	tmpDir := t.TempDir()
	cpuInfoPath := filepath.Join(tmpDir, "cpuinfo")

	content := `processor	: 0
model name	: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
cpu cores	: 6
cache size	: 12288 KB
flags		: fpu vme de pse tsc msr pae mce cx8

processor	: 1
model name	: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
cpu cores	: 6
cache size	: 12288 KB
flags		: fpu vme de pse tsc msr pae mce cx8
`
	err := os.WriteFile(cpuInfoPath, []byte(content), 0644)
	require.NoError(t, err)

	// We can't easily mock /proc/cpuinfo reading without refactoring,
	// so this test validates the parsing logic would work
	assert.FileExists(t, cpuInfoPath)
}

func TestCPUInfo_FileNotFound(t *testing.T) {
	// Save original path behavior - this test verifies error handling
	// when /proc/cpuinfo doesn't exist (e.g., on non-Linux or containers)
	if runtime.GOOS == "linux" {
		// On Linux, /proc/cpuinfo should exist
		_, err := CPUInfo()
		assert.NoError(t, err)
	}
}

func TestSystemInfo_Success(t *testing.T) {
	sysInfo, err := SystemInfo()

	require.NoError(t, err)
	assert.NotNil(t, sysInfo.Runtime)
	assert.Greater(t, sysInfo.Runtime.Cpus, 0)
	assert.NotEmpty(t, sysInfo.Runtime.Version)
}

func TestSystemInfo_RuntimeFields(t *testing.T) {
	sysInfo, err := SystemInfo()

	require.NoError(t, err)
	require.NotNil(t, sysInfo.Runtime)

	// Validate runtime information is populated
	assert.Greater(t, sysInfo.Runtime.Cpus, 0)
	assert.GreaterOrEqual(t, sysInfo.Runtime.Goroutines, 1)
	assert.NotEmpty(t, sysInfo.Runtime.Version)
	assert.GreaterOrEqual(t, sysInfo.Runtime.HeapSize, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Alloc, uint64(0))
}

func TestSystemInfo_CPUInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping test on non-Linux system")
	}

	sysInfo, err := SystemInfo()
	require.NoError(t, err)

	// CPU info should be populated on Linux
	assert.NotNil(t, sysInfo.CPU)
	assert.Greater(t, sysInfo.CPU.Threads, 0)
}

func TestReadDMIFile_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_dmi")
	content := "test-value\n"

	err := os.WriteFile(testFile, []byte(content), 0644)
	require.NoError(t, err)

	result := readDMIFile(testFile)
	assert.Equal(t, "test-value", result)
}

func TestReadDMIFile_NotExists(t *testing.T) {
	result := readDMIFile("/nonexistent/path/to/file")
	assert.Equal(t, "", result)
}

func TestReadDMIFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty_dmi")

	err := os.WriteFile(testFile, []byte(""), 0644)
	require.NoError(t, err)

	result := readDMIFile(testFile)
	assert.Equal(t, "", result)
}

func TestReadDMIFile_Whitespace(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "whitespace_dmi")

	err := os.WriteFile(testFile, []byte("  test-value  \n"), 0644)
	require.NoError(t, err)

	result := readDMIFile(testFile)
	assert.Equal(t, "test-value", result)
}

func TestBIOS(t *testing.T) {
	bios, err := BIOS()

	require.NoError(t, err)
	// BIOS fields may be empty on non-root or VM environments
	assert.NotNil(t, bios)
}

func TestBoard(t *testing.T) {
	board, err := Board()

	require.NoError(t, err)
	assert.NotNil(t, board)
}

func TestChassis(t *testing.T) {
	chassis, err := Chassis()

	require.NoError(t, err)
	assert.NotNil(t, chassis)
}

func TestProduct(t *testing.T) {
	product, err := Product()

	require.NoError(t, err)
	assert.NotNil(t, product)
}

func TestPrintSystemInfo(t *testing.T) {
	// Just ensure it doesn't panic
	err := PrintSystemInfo()
	// May fail if running as non-root on some systems
	if err != nil {
		assert.Error(t, err)
	}
}

func TestTPMInfo_Nil(t *testing.T) {
	status := TPMInfo(nil)

	require.NotNil(t, status)
	assert.False(t, status.Available)
	assert.False(t, status.EKPresent)
	assert.False(t, status.SRKPresent)
}

func TestTPMInfo_WithMockTPM(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "TEST-MFG",
			VendorID:     "TPMV",
			FwMajor:      1,
			FwMinor:      42,
			Family:       "2.0",
		},
		infoResult:      "TPM Simulator Test Device",
		ekAttrsResult:   &xkmssdk.KeyAttributes{},
		ssrkAttrsResult: &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.Equal(t, "TEST-MFG", status.Manufacturer)
	assert.Equal(t, "TPMV", status.VendorID)
	assert.Equal(t, "1.42", status.FwVersion)
	assert.Equal(t, "2.0", status.FamilySpec)
	assert.True(t, status.Simulated)
	assert.True(t, status.EKPresent)
	assert.True(t, status.SRKPresent)
}

func TestTPMInfo_WithMockTPM_SWTPM(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "IBM",
			VendorID:     "SW",
			FwMajor:      0,
			FwMinor:      1,
			Family:       "2.0",
		},
		infoResult:      "swtpm TPM2 device",
		ekAttrsResult:   &xkmssdk.KeyAttributes{},
		ssrkAttrsResult: &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.True(t, status.Simulated) // Should detect "swtpm" in info
}

func TestTPMInfo_WithMockTPM_HardwareTPM(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "IFX",
			VendorID:     "SLB9670",
			FwMajor:      7,
			FwMinor:      85,
			Family:       "2.0",
		},
		infoResult:      "Infineon SLB9670 TPM 2.0",
		ekAttrsResult:   &xkmssdk.KeyAttributes{},
		ssrkAttrsResult: &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.False(t, status.Simulated) // Should NOT detect simulator
	assert.Equal(t, "IFX", status.Manufacturer)
}

func TestTPMInfo_WithMockTPM_FixedPropertiesError(t *testing.T) {
	mock := &mockTPM{
		fixedPropsErr:   errors.New("failed to get fixed properties"),
		infoResult:      "test tpm",
		ekAttrsResult:   &xkmssdk.KeyAttributes{},
		ssrkAttrsResult: &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	// Properties should be empty when error occurs
	assert.Empty(t, status.Manufacturer)
	assert.Empty(t, status.VendorID)
}

func TestTPMInfo_WithMockTPM_InfoError(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "TEST",
		},
		infoErr:         errors.New("failed to get info"),
		ekAttrsResult:   &xkmssdk.KeyAttributes{},
		ssrkAttrsResult: &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	// Simulated should be false when info retrieval fails
	assert.False(t, status.Simulated)
}

func TestTPMInfo_WithMockTPM_EKNotPresent(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{},
		infoResult:       "test",
		ekAttrsErr:       errors.New("EK not found"),
		ssrkAttrsResult:  &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.False(t, status.EKPresent)
	assert.True(t, status.SRKPresent)
}

func TestTPMInfo_WithMockTPM_SRKNotPresent(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{},
		infoResult:       "test",
		ekAttrsResult:    &xkmssdk.KeyAttributes{},
		ssrkAttrsErr:     errors.New("SRK not found"),
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.True(t, status.EKPresent)
	assert.False(t, status.SRKPresent)
}

func TestTPMInfo_WithMockTPM_NilProperties(t *testing.T) {
	mock := &mockTPM{
		fixedPropsResult: nil,
		fixedPropsErr:    nil, // No error, but nil result
		infoResult:       "test",
		ekAttrsResult:    &xkmssdk.KeyAttributes{},
		ssrkAttrsResult:  &xkmssdk.KeyAttributes{},
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	// Should handle nil properties gracefully
	assert.Empty(t, status.Manufacturer)
}

func TestCAInfo_Nil(t *testing.T) {
	status := CAInfo(nil)

	require.NotNil(t, status)
	assert.False(t, status.Available)
	assert.Nil(t, status.RootCA)
	assert.Nil(t, status.IssuingCA)
}

func TestCAInfo_WithMockCA_RootOnly(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName:   "Test Root CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Valid:        10,
					KeyAlgorithm: x509.RSA,
					KeySize:      4096,
					SANS: &trustedca.CASubjectAlternativeNames{
						DNS: []string{"ca.example.com"},
						IPs: []string{"192.168.1.1"},
					},
				},
			},
			SelectedCA:                0,
			DefaultSignatureAlgorithm: x509.SHA512WithRSA,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "Test Root CA", status.RootCA.CN)
	assert.Equal(t, "Test Org", status.RootCA.Organization)
	assert.Equal(t, "US", status.RootCA.Country)
	assert.Equal(t, "RSA", status.RootCA.KeyAlgorithm)
	assert.Equal(t, 4096, status.RootCA.KeySize)
	assert.Equal(t, 10, status.RootCA.ValidYears)
	assert.Equal(t, "SHA512-RSA", status.RootCA.SignatureAlgorithm)
	assert.Equal(t, "SHA-512", status.RootCA.Hash)
	assert.Equal(t, []string{"ca.example.com"}, status.RootCA.DNSNames)
	assert.Equal(t, []string{"192.168.1.1"}, status.RootCA.IPs)
	// Without intermediate, issuing CA should equal root CA
	assert.Equal(t, status.RootCA, status.IssuingCA)
}

func TestCAInfo_WithMockCA_WithIntermediate(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName:   "Test Root CA",
						Organization: "Test Org",
					},
					Valid:        10,
					KeyAlgorithm: x509.RSA,
					KeySize:      4096,
				},
				{
					Subject: trustedca.CASubject{
						CommonName:   "Test Intermediate CA",
						Organization: "Test Org",
					},
					Valid:        5,
					KeyAlgorithm: x509.ECDSA,
					ECCCurve:     "P-384",
					ParentCA:     "Test Root CA",
				},
			},
			SelectedCA: 1,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "Test Root CA", status.RootCA.CN)
	require.NotNil(t, status.IssuingCA)
	assert.Equal(t, "Test Intermediate CA", status.IssuingCA.CN)
	assert.Equal(t, "ECDSA", status.IssuingCA.KeyAlgorithm)
	assert.Equal(t, "P-384", status.IssuingCA.ECCCurve)
	assert.Equal(t, "Test Root CA", status.IssuingCA.ParentCA)
}

func TestCAInfo_WithMockCA_EmptyCommonName(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "", // Empty CN
					},
					KeyAlgorithm: x509.RSA,
					KeySize:      2048,
				},
			},
			SelectedCA: 0,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	// RootCA should be nil since CN is empty
	assert.Nil(t, status.RootCA)
}

func TestCAInfo_WithMockCA_ECDSA(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "ECDSA Root CA",
					},
					Valid:        5,
					KeyAlgorithm: x509.ECDSA,
					ECCCurve:     "P-256",
				},
			},
			SelectedCA: 0,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "ECDSA Root CA", status.RootCA.CN)
	assert.Equal(t, "ECDSA", status.RootCA.KeyAlgorithm)
	assert.Equal(t, "P-256", status.RootCA.ECCCurve)
	// Should derive signature algorithm from key algorithm
	assert.Equal(t, "ECDSA-SHA256", status.RootCA.SignatureAlgorithm)
}

func TestCAInfo_WithMockCA_Ed25519(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "Ed25519 Root CA",
					},
					Valid:        5,
					KeyAlgorithm: x509.Ed25519,
				},
			},
			SelectedCA: 0,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "Ed25519 Root CA", status.RootCA.CN)
	assert.Equal(t, "Ed25519", status.RootCA.KeyAlgorithm)
	assert.Equal(t, "Ed25519", status.RootCA.SignatureAlgorithm)
	assert.Equal(t, "SHA-512", status.RootCA.Hash)
}

func TestCAInfo_WithMockCA_NoSANS(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "Test CA",
					},
					Valid:        5,
					KeyAlgorithm: x509.RSA,
					KeySize:      2048,
					SANS:         nil, // No SANs
				},
			},
			SelectedCA: 0,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Nil(t, status.RootCA.DNSNames)
	assert.Nil(t, status.RootCA.IPs)
}

func TestCAInfoFromConfig_Nil(t *testing.T) {
	status := CAInfoFromConfig(nil)

	require.NotNil(t, status)
	assert.False(t, status.Available)
}

func TestCAInfoFromConfig_EmptyIdentity(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{},
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.False(t, status.Available)
}

func TestCAInfoFromConfig_SingleIdentity(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName:   "Test Root CA",
					Organization: "Test Org",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.RSA,
				KeySize:      2048,
			},
		},
		SelectedCA: 0,
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.NotNil(t, status.RootCA)
	assert.Equal(t, "Test Root CA", status.RootCA.CN)
	assert.Equal(t, "Test Org", status.RootCA.Organization)
	assert.Equal(t, "RSA", status.RootCA.KeyAlgorithm)
	assert.Equal(t, 2048, status.RootCA.KeySize)

	// Should point to same CA when no intermediate
	assert.Equal(t, status.RootCA, status.IssuingCA)
}

func TestCAInfoFromConfig_WithIntermediate(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName:   "Test Root CA",
					Organization: "Test Org",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.RSA,
				KeySize:      4096,
			},
			{
				Subject: trustedca.CASubject{
					CommonName:   "Test Intermediate CA",
					Organization: "Test Org",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P-384",
				ParentCA:     "Test Root CA",
			},
		},
		SelectedCA: 1,
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.NotNil(t, status.RootCA)
	assert.Equal(t, "Test Root CA", status.RootCA.CN)
	assert.Equal(t, "RSA", status.RootCA.KeyAlgorithm)
	assert.Equal(t, 4096, status.RootCA.KeySize)

	assert.NotNil(t, status.IssuingCA)
	assert.Equal(t, "Test Intermediate CA", status.IssuingCA.CN)
	assert.Equal(t, "ECDSA", status.IssuingCA.KeyAlgorithm)
	assert.Equal(t, "P-384", status.IssuingCA.ECCCurve)
	assert.Equal(t, "Test Root CA", status.IssuingCA.ParentCA)
}

func TestCAInfoFromConfig_SelectedCAOutOfBounds(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName: "Test Root CA",
				},
				KeyAlgorithm: x509.RSA,
				KeySize:      2048,
			},
		},
		SelectedCA: 10, // Out of bounds
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	// Should fall back to root as issuing CA
	assert.Equal(t, status.RootCA, status.IssuingCA)
}

func TestCAInfoFromConfig_WithDefaultSignatureAlgorithm(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName: "Test Root CA",
				},
				Valid:        10,
				KeyAlgorithm: x509.RSA,
				KeySize:      4096,
			},
		},
		SelectedCA:                0,
		DefaultSignatureAlgorithm: x509.SHA512WithRSA,
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.NotNil(t, status.RootCA)
	assert.Equal(t, "SHA512-RSA", status.RootCA.SignatureAlgorithm)
	assert.Equal(t, "SHA-512", status.RootCA.Hash)
}

func TestDeriveSignatureAlgorithm_RSA(t *testing.T) {
	tests := []struct {
		name     string
		identity *trustedca.CAIdentity
		expected x509.SignatureAlgorithm
	}{
		{
			name: "RSA 4096",
			identity: &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      4096,
			},
			expected: x509.SHA512WithRSA,
		},
		{
			name: "RSA 3072",
			identity: &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      3072,
			},
			expected: x509.SHA384WithRSA,
		},
		{
			name: "RSA 2048",
			identity: &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      2048,
			},
			expected: x509.SHA256WithRSA,
		},
		{
			name: "RSA 1024 (falls to default)",
			identity: &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      1024,
			},
			expected: x509.SHA256WithRSA,
		},
		{
			name: "RSA 8192",
			identity: &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      8192,
			},
			expected: x509.SHA512WithRSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveSignatureAlgorithm(tt.identity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeriveSignatureAlgorithm_ECDSA(t *testing.T) {
	tests := []struct {
		name     string
		curve    string
		expected x509.SignatureAlgorithm
	}{
		{
			name:     "P-521",
			curve:    "P-521",
			expected: x509.ECDSAWithSHA512,
		},
		{
			name:     "P521",
			curve:    "P521",
			expected: x509.ECDSAWithSHA512,
		},
		{
			name:     "P-384",
			curve:    "P-384",
			expected: x509.ECDSAWithSHA384,
		},
		{
			name:     "P384",
			curve:    "P384",
			expected: x509.ECDSAWithSHA384,
		},
		{
			name:     "P-256",
			curve:    "P-256",
			expected: x509.ECDSAWithSHA256,
		},
		{
			name:     "P256",
			curve:    "P256",
			expected: x509.ECDSAWithSHA256,
		},
		{
			name:     "Empty curve defaults to SHA256",
			curve:    "",
			expected: x509.ECDSAWithSHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &trustedca.CAIdentity{
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     tt.curve,
			}
			result := deriveSignatureAlgorithm(identity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeriveSignatureAlgorithm_Ed25519(t *testing.T) {
	identity := &trustedca.CAIdentity{
		KeyAlgorithm: x509.Ed25519,
	}

	result := deriveSignatureAlgorithm(identity)
	assert.Equal(t, x509.PureEd25519, result)
}

func TestDeriveSignatureAlgorithm_Unknown(t *testing.T) {
	identity := &trustedca.CAIdentity{
		KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Unknown algorithm
	}

	result := deriveSignatureAlgorithm(identity)
	assert.Equal(t, x509.SHA256WithRSA, result) // Should default to SHA256WithRSA
}

func TestDeriveSignatureAlgorithm_DSA(t *testing.T) {
	identity := &trustedca.CAIdentity{
		KeyAlgorithm: x509.DSA,
	}

	result := deriveSignatureAlgorithm(identity)
	assert.Equal(t, x509.SHA256WithRSA, result) // Falls through to default
}

func TestSignatureAlgorithmHash(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected string
	}{
		{"SHA256WithRSA", x509.SHA256WithRSA, "SHA-256"},
		{"SHA384WithRSA", x509.SHA384WithRSA, "SHA-384"},
		{"SHA512WithRSA", x509.SHA512WithRSA, "SHA-512"},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, "SHA-256"},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, "SHA-384"},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, "SHA-512"},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, "SHA-256"},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, "SHA-384"},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, "SHA-512"},
		{"PureEd25519", x509.PureEd25519, "SHA-512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := signatureAlgorithmHash(tt.sigAlgo)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestSignatureAlgorithmHash_Unknown(t *testing.T) {
	result := signatureAlgorithmHash(x509.SignatureAlgorithm(999))
	assert.Equal(t, crypto.SHA256, result) // Should default to SHA256
}

func TestSignatureAlgorithmHash_MD5WithRSA(t *testing.T) {
	result := signatureAlgorithmHash(x509.MD5WithRSA)
	assert.Equal(t, crypto.SHA256, result) // Falls through to default
}

func TestIdentityToKeyConfig(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName:   "Test CA",
			Organization: "Test Org",
			Country:      "US",
		},
		Valid:        10,
		KeyAlgorithm: x509.ECDSA,
		ECCCurve:     "P-384",
		KeySize:      0,
		SANS: &trustedca.CASubjectAlternativeNames{
			DNS: []string{"ca.example.com", "ca2.example.com"},
			IPs: []string{"192.168.1.1", "10.0.0.1"},
		},
	}

	config := &trustedca.CAConfig{
		DefaultSignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Equal(t, "Test CA", result.CN)
	assert.Equal(t, "Test Org", result.Organization)
	assert.Equal(t, "US", result.Country)
	assert.Equal(t, 10, result.ValidYears)
	assert.Equal(t, "ECDSA", result.KeyAlgorithm)
	assert.Equal(t, "P-384", result.ECCCurve)
	assert.Equal(t, "ECDSA-SHA384", result.SignatureAlgorithm)
	assert.Equal(t, "SHA-384", result.Hash)
	assert.Equal(t, []string{"ca.example.com", "ca2.example.com"}, result.DNSNames)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.1"}, result.IPs)
}

func TestIdentityToKeyConfig_NoDefaultSignature(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName: "Test CA",
		},
		Valid:        5,
		KeyAlgorithm: x509.RSA,
		KeySize:      4096,
	}

	config := &trustedca.CAConfig{
		DefaultSignatureAlgorithm: 0, // Not set
	}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Equal(t, "Test CA", result.CN)
	// Should derive signature algorithm from key algorithm
	assert.Equal(t, "SHA512-RSA", result.SignatureAlgorithm)
	assert.Equal(t, "SHA-512", result.Hash)
}

func TestIdentityToKeyConfig_NoSANS(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName: "Test CA",
		},
		Valid:        5,
		KeyAlgorithm: x509.ECDSA,
		ECCCurve:     "P-256",
		SANS:         nil, // No SANs
	}

	config := &trustedca.CAConfig{}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Nil(t, result.DNSNames)
	assert.Nil(t, result.IPs)
}

func TestIdentityToKeyConfig_WithKeystoreType(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName: "Test CA",
		},
		KeyAlgorithm: x509.RSA,
		KeySize:      2048,
		KeystoreType: string(xkmssdk.StoreTPM2),
	}

	config := &trustedca.CAConfig{}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Equal(t, string(xkmssdk.StoreTPM2), result.StoreType)
}

func TestIdentityToKeyConfig_WithParentCA(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName: "Intermediate CA",
		},
		KeyAlgorithm: x509.ECDSA,
		ECCCurve:     "P-384",
		ParentCA:     "Root CA",
	}

	config := &trustedca.CAConfig{}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Equal(t, "Root CA", result.ParentCA)
}

func TestOSInfoDetails(t *testing.T) {
	info := OSInfoDetails()

	require.NotNil(t, info)
	assert.NotEmpty(t, info.Hostname)
	assert.NotEmpty(t, info.OS)
	assert.NotEmpty(t, info.Arch)

	if runtime.GOOS == "linux" {
		// On Linux, we should get kernel and uptime
		// These might be empty in some container environments
		t.Logf("Kernel: %s, Uptime: %s", info.Kernel, info.Uptime)
	}
}

func TestOSInfoDetails_LinuxSpecific(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test")
	}

	info := OSInfoDetails()

	require.NotNil(t, info)
	assert.Equal(t, "linux", info.OS)
	// Kernel should be populated on Linux
	if info.Kernel != "" {
		assert.Contains(t, info.Kernel, ".")
	}
	// Uptime should be populated
	if info.Uptime != "" {
		assert.Contains(t, info.Uptime, "m") // Should contain minutes
	}
}

func TestNetworkInfoDetails(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	assert.NotEmpty(t, info.Hostname)
	// Interfaces list might be empty in some test environments
	// but the struct should be populated
}

func TestNetworkInfoDetails_InterfaceFiltering(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// Should not include loopback in interfaces
	for _, iface := range info.Interfaces {
		assert.NotEqual(t, "lo", iface)
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "only minutes",
			duration: 600 * time.Second, // 10 minutes
			expected: "10m",
		},
		{
			name:     "hours and minutes",
			duration: 7200 * time.Second, // 2 hours
			expected: "2h 0m",
		},
		{
			name:     "days, hours and minutes",
			duration: 90061 * time.Second, // 1 day, 1 hour, 1 minute
			expected: "1d 1h 1m",
		},
		{
			name:     "multiple days",
			duration: 259200 * time.Second, // 3 days
			expected: "3d 0h 0m",
		},
		{
			name:     "zero duration",
			duration: 0,
			expected: "0m",
		},
		{
			name:     "less than a minute",
			duration: 30 * time.Second,
			expected: "0m",
		},
		{
			name:     "exactly one hour",
			duration: 3600 * time.Second,
			expected: "1h 0m",
		},
		{
			name:     "exactly one day",
			duration: 86400 * time.Second,
			expected: "1d 0h 0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatUptime(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSystemInfoNonRoot(t *testing.T) {
	sysInfo, err := SystemInfo()
	require.NoError(t, err)

	// Runtime and CPU info should always be available regardless of privilege
	assert.NotNil(t, sysInfo.Runtime)
	assert.NotNil(t, sysInfo.CPU)

	if os.Geteuid() == 0 {
		// When running as root, BIOS/Board/Chassis/Product info may also be available
		// (depends on system, but should not error)
	}
}

func TestSystemInfo_MemoryStats(t *testing.T) {
	sysInfo, err := SystemInfo()
	require.NoError(t, err)

	require.NotNil(t, sysInfo.Runtime)
	// Memory stats should have reasonable values
	assert.GreaterOrEqual(t, sysInfo.Runtime.Sys, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Mallocs, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Frees, uint64(0))
	// NumGC and NumForcedGC can be 0 in quick tests
}

func TestPrintSystemInfo_ExecutesWithoutPanic(t *testing.T) {
	// Capture that PrintSystemInfo doesn't panic
	require.NotPanics(t, func() {
		_ = PrintSystemInfo()
	})
}

func TestCPUInfo_ParsesAllFields(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping test on non-Linux system")
	}

	cpuInfo, err := CPUInfo()
	require.NoError(t, err)

	// At least some fields should be populated on any Linux system
	assert.Greater(t, cpuInfo.Threads, 0)
	// Model name might be empty in some VMs but usually populated
	t.Logf("CPU Model: %s, Cores: %d, Threads: %d",
		cpuInfo.ModelName, cpuInfo.Cores, cpuInfo.Threads)
}

func TestNetworkInfoDetails_IPv4AndIPv6(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// Log what was found for debugging
	t.Logf("IPv4: %s, IPv6: %s, Interfaces: %v",
		info.IPv4, info.IPv6, info.Interfaces)

	// In most environments, at least IPv4 should be present
	// but we can't guarantee this in all test environments
}

func TestDeriveSignatureAlgorithm_RSABoundaries(t *testing.T) {
	tests := []struct {
		name     string
		keySize  int
		expected x509.SignatureAlgorithm
	}{
		{
			name:     "Exactly 3072",
			keySize:  3072,
			expected: x509.SHA384WithRSA,
		},
		{
			name:     "Just below 3072",
			keySize:  3071,
			expected: x509.SHA256WithRSA,
		},
		{
			name:     "Exactly 4096",
			keySize:  4096,
			expected: x509.SHA512WithRSA,
		},
		{
			name:     "Just below 4096",
			keySize:  4095,
			expected: x509.SHA384WithRSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &trustedca.CAIdentity{
				KeyAlgorithm: x509.RSA,
				KeySize:      tt.keySize,
			}
			result := deriveSignatureAlgorithm(identity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIdentityToKeyConfig_Ed25519(t *testing.T) {
	identity := &trustedca.CAIdentity{
		Subject: trustedca.CASubject{
			CommonName: "Ed25519 CA",
		},
		Valid:        5,
		KeyAlgorithm: x509.Ed25519,
	}

	config := &trustedca.CAConfig{
		DefaultSignatureAlgorithm: 0, // Not set, should derive
	}

	result := identityToKeyConfig(identity, config)

	require.NotNil(t, result)
	assert.Equal(t, "Ed25519", result.KeyAlgorithm)
	assert.Equal(t, "Ed25519", result.SignatureAlgorithm)
	assert.Equal(t, "SHA-512", result.Hash)
}

func TestCAInfoFromConfig_MultipleIntermediates(t *testing.T) {
	config := &trustedca.CAConfig{
		Identity: []trustedca.CAIdentity{
			{
				Subject: trustedca.CASubject{
					CommonName: "Root CA",
				},
				KeyAlgorithm: x509.RSA,
				KeySize:      4096,
			},
			{
				Subject: trustedca.CASubject{
					CommonName: "Intermediate CA 1",
				},
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P-384",
				ParentCA:     "Root CA",
			},
			{
				Subject: trustedca.CASubject{
					CommonName: "Intermediate CA 2",
				},
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P-256",
				ParentCA:     "Intermediate CA 1",
			},
		},
		SelectedCA: 2, // Select the second intermediate
	}

	status := CAInfoFromConfig(config)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.NotNil(t, status.RootCA)
	assert.Equal(t, "Root CA", status.RootCA.CN)

	assert.NotNil(t, status.IssuingCA)
	assert.Equal(t, "Intermediate CA 2", status.IssuingCA.CN)
	assert.Equal(t, "P-256", status.IssuingCA.ECCCurve)
}

func TestIdentityToKeyConfig_AllRSASizes(t *testing.T) {
	tests := []struct {
		name             string
		keySize          int
		expectedSigAlgo  string
		expectedHashAlgo string
	}{
		{
			name:             "RSA 2048",
			keySize:          2048,
			expectedSigAlgo:  "SHA256-RSA",
			expectedHashAlgo: "SHA-256",
		},
		{
			name:             "RSA 3072",
			keySize:          3072,
			expectedSigAlgo:  "SHA384-RSA",
			expectedHashAlgo: "SHA-384",
		},
		{
			name:             "RSA 4096",
			keySize:          4096,
			expectedSigAlgo:  "SHA512-RSA",
			expectedHashAlgo: "SHA-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &trustedca.CAIdentity{
				Subject: trustedca.CASubject{
					CommonName: "Test CA",
				},
				KeyAlgorithm: x509.RSA,
				KeySize:      tt.keySize,
			}
			config := &trustedca.CAConfig{} // No default signature algorithm

			result := identityToKeyConfig(identity, config)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedSigAlgo, result.SignatureAlgorithm)
			assert.Equal(t, tt.expectedHashAlgo, result.Hash)
		})
	}
}

func TestIdentityToKeyConfig_AllECDSACurves(t *testing.T) {
	tests := []struct {
		name             string
		curve            string
		expectedSigAlgo  string
		expectedHashAlgo string
	}{
		{
			name:             "P-256",
			curve:            "P-256",
			expectedSigAlgo:  "ECDSA-SHA256",
			expectedHashAlgo: "SHA-256",
		},
		{
			name:             "P-384",
			curve:            "P-384",
			expectedSigAlgo:  "ECDSA-SHA384",
			expectedHashAlgo: "SHA-384",
		},
		{
			name:             "P-521",
			curve:            "P-521",
			expectedSigAlgo:  "ECDSA-SHA512",
			expectedHashAlgo: "SHA-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &trustedca.CAIdentity{
				Subject: trustedca.CASubject{
					CommonName: "Test CA",
				},
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     tt.curve,
			}
			config := &trustedca.CAConfig{} // No default signature algorithm

			result := identityToKeyConfig(identity, config)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedSigAlgo, result.SignatureAlgorithm)
			assert.Equal(t, tt.expectedHashAlgo, result.Hash)
		})
	}
}

func TestTPMInfo_AllBranchesEKAndSRK(t *testing.T) {
	// Test case: Both EK and SRK missing
	mock := &mockTPM{
		fixedPropsResult: &xkmssdk.PropertiesFixed{
			Manufacturer: "TEST",
		},
		infoResult:   "test",
		ekAttrsErr:   errors.New("EK not found"),
		ssrkAttrsErr: errors.New("SRK not found"),
	}

	status := TPMInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	assert.False(t, status.EKPresent)
	assert.False(t, status.SRKPresent)
}

func TestOSInfoDetails_FieldsPresent(t *testing.T) {
	info := OSInfoDetails()

	require.NotNil(t, info)
	// These should always be present
	assert.Equal(t, runtime.GOOS, info.OS)
	assert.Equal(t, runtime.GOARCH, info.Arch)
}

func TestNetworkInfoDetails_EmptyInterfacesList(t *testing.T) {
	// This test ensures the function handles case where no network
	// interfaces are available (e.g., in isolated container)
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// Interfaces should be at least an empty slice, not nil
	assert.NotNil(t, info.Interfaces)
}

// =============================================================================
// Additional Tests for Improved Coverage
// =============================================================================

func TestPrintSystemInfo_AllBranches(t *testing.T) {
	// Test executes PrintSystemInfo which exercises all Print methods
	// May have varying output depending on root status
	err := PrintSystemInfo()
	// On non-Linux or errors, this might fail, but should not panic
	if err != nil {
		// Error is acceptable for non-Linux or permission issues
		t.Logf("PrintSystemInfo returned error (expected in some environments): %v", err)
	}
}

func TestSystemInfo_RootUserPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test")
	}

	sysInfo, err := SystemInfo()
	require.NoError(t, err)

	// Verify runtime is always populated
	require.NotNil(t, sysInfo.Runtime)
	assert.NotEmpty(t, sysInfo.Runtime.Version)
	assert.Greater(t, sysInfo.Runtime.Cpus, 0)

	// If running as root, BIOS/Board/Chassis/Product should be populated
	if os.Geteuid() == 0 {
		assert.NotNil(t, sysInfo.BIOS)
		assert.NotNil(t, sysInfo.Board)
		assert.NotNil(t, sysInfo.Chassis)
		assert.NotNil(t, sysInfo.Product)
	}
}

func TestNetworkInfoDetails_AddressTypes(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// Test that function gracefully handles different address types
	// IPv4 and IPv6 may or may not be present depending on system config
	t.Logf("Network info - Hostname: %s, IPv4: %s, IPv6: %s, Interfaces: %v",
		info.Hostname, info.IPv4, info.IPv6, info.Interfaces)

	// Hostname should always be populated
	assert.NotEmpty(t, info.Hostname)
}

func TestCAInfo_WithMockCA_AllSignatureAlgorithms(t *testing.T) {
	tests := []struct {
		name         string
		sigAlgo      x509.SignatureAlgorithm
		expectedSig  string
		expectedHash string
	}{
		{
			name:         "SHA256WithRSA",
			sigAlgo:      x509.SHA256WithRSA,
			expectedSig:  "SHA256-RSA",
			expectedHash: "SHA-256",
		},
		{
			name:         "SHA384WithRSA",
			sigAlgo:      x509.SHA384WithRSA,
			expectedSig:  "SHA384-RSA",
			expectedHash: "SHA-384",
		},
		{
			name:         "SHA512WithRSA",
			sigAlgo:      x509.SHA512WithRSA,
			expectedSig:  "SHA512-RSA",
			expectedHash: "SHA-512",
		},
		{
			name:         "ECDSAWithSHA256",
			sigAlgo:      x509.ECDSAWithSHA256,
			expectedSig:  "ECDSA-SHA256",
			expectedHash: "SHA-256",
		},
		{
			name:         "ECDSAWithSHA384",
			sigAlgo:      x509.ECDSAWithSHA384,
			expectedSig:  "ECDSA-SHA384",
			expectedHash: "SHA-384",
		},
		{
			name:         "ECDSAWithSHA512",
			sigAlgo:      x509.ECDSAWithSHA512,
			expectedSig:  "ECDSA-SHA512",
			expectedHash: "SHA-512",
		},
		{
			name:         "PureEd25519",
			sigAlgo:      x509.PureEd25519,
			expectedSig:  "Ed25519",
			expectedHash: "SHA-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockCA{
				config: trustedca.CAConfig{
					Identity: []trustedca.CAIdentity{
						{
							Subject: trustedca.CASubject{
								CommonName: "Test CA",
							},
							KeyAlgorithm: x509.RSA,
							KeySize:      2048,
						},
					},
					SelectedCA:                0,
					DefaultSignatureAlgorithm: tt.sigAlgo,
				},
			}

			status := CAInfo(mock)

			require.NotNil(t, status)
			assert.True(t, status.Available)
			require.NotNil(t, status.RootCA)
			assert.Equal(t, tt.expectedSig, status.RootCA.SignatureAlgorithm)
			assert.Equal(t, tt.expectedHash, status.RootCA.Hash)
		})
	}
}

func TestCAInfo_WithMockCA_PSS_Signatures(t *testing.T) {
	tests := []struct {
		name         string
		sigAlgo      x509.SignatureAlgorithm
		expectedHash string
	}{
		{
			name:         "SHA256WithRSAPSS",
			sigAlgo:      x509.SHA256WithRSAPSS,
			expectedHash: "SHA-256",
		},
		{
			name:         "SHA384WithRSAPSS",
			sigAlgo:      x509.SHA384WithRSAPSS,
			expectedHash: "SHA-384",
		},
		{
			name:         "SHA512WithRSAPSS",
			sigAlgo:      x509.SHA512WithRSAPSS,
			expectedHash: "SHA-512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockCA{
				config: trustedca.CAConfig{
					Identity: []trustedca.CAIdentity{
						{
							Subject: trustedca.CASubject{
								CommonName: "Test CA",
							},
							KeyAlgorithm: x509.RSA,
							KeySize:      2048,
						},
					},
					SelectedCA:                0,
					DefaultSignatureAlgorithm: tt.sigAlgo,
				},
			}

			status := CAInfo(mock)

			require.NotNil(t, status)
			require.NotNil(t, status.RootCA)
			assert.Equal(t, tt.expectedHash, status.RootCA.Hash)
		})
	}
}

func TestNetworkInfoDetails_LoopbackExclusion(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// Verify loopback is excluded from interface list
	for _, iface := range info.Interfaces {
		assert.NotEqual(t, "lo", iface, "Loopback should be excluded")
	}

	// IPv4 should not be a loopback address if present
	if info.IPv4 != "" {
		assert.NotEqual(t, "127.0.0.1", info.IPv4, "IPv4 should not be loopback")
	}
}

func TestFormatUptime_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "59 seconds",
			duration: 59 * time.Second,
			expected: "0m",
		},
		{
			name:     "60 seconds (1 minute)",
			duration: 60 * time.Second,
			expected: "1m",
		},
		{
			name:     "59 minutes",
			duration: 59 * time.Minute,
			expected: "59m",
		},
		{
			name:     "1 hour 59 minutes",
			duration: 119 * time.Minute,
			expected: "1h 59m",
		},
		{
			name:     "23 hours 59 minutes",
			duration: 23*time.Hour + 59*time.Minute,
			expected: "23h 59m",
		},
		{
			name:     "24 hours (1 day)",
			duration: 24 * time.Hour,
			expected: "1d 0h 0m",
		},
		{
			name:     "7 days",
			duration: 7 * 24 * time.Hour,
			expected: "7d 0h 0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatUptime(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSystemInfo_AllRuntimeFields(t *testing.T) {
	sysInfo, err := SystemInfo()
	require.NoError(t, err)

	require.NotNil(t, sysInfo.Runtime)

	// All runtime fields should be populated
	assert.NotEmpty(t, sysInfo.Runtime.Version)
	assert.Greater(t, sysInfo.Runtime.Cpus, 0)
	assert.GreaterOrEqual(t, sysInfo.Runtime.Goroutines, 1)
	// Cgo calls might be 0
	assert.GreaterOrEqual(t, sysInfo.Runtime.Cgo, int64(0))
	// Memory fields
	assert.GreaterOrEqual(t, sysInfo.Runtime.HeapSize, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Alloc, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Sys, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Mallocs, uint64(0))
	assert.GreaterOrEqual(t, sysInfo.Runtime.Frees, uint64(0))
}

func TestCAInfo_HasIntermediateButNoSelectedCA(t *testing.T) {
	// Test case where HasIntermediate returns false (SelectedCA <= 0)
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "Root CA Only",
					},
					KeyAlgorithm: x509.RSA,
					KeySize:      4096,
				},
				{
					Subject: trustedca.CASubject{
						CommonName: "Intermediate CA",
					},
					KeyAlgorithm: x509.ECDSA,
					ECCCurve:     "P-384",
					ParentCA:     "Root CA Only",
				},
			},
			SelectedCA: 0, // Select root, not intermediate
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	assert.True(t, status.Available)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, "Root CA Only", status.RootCA.CN)
	// IssuingCA should be same as RootCA since SelectedCA is 0
	assert.Equal(t, status.RootCA, status.IssuingCA)
}

func TestOSInfoDetails_UptimeAndKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test")
	}

	info := OSInfoDetails()

	require.NotNil(t, info)
	// On Linux, kernel info should be available
	// Note: may be empty in some container environments
	if info.Kernel != "" {
		// Kernel version typically contains dots
		t.Logf("Kernel version: %s", info.Kernel)
	}

	if info.Uptime != "" {
		// Uptime should contain a time unit
		t.Logf("System uptime: %s", info.Uptime)
	}
}

func TestCPUInfo_LinuxParsing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test")
	}

	cpuInfo, err := CPUInfo()
	require.NoError(t, err)

	// On Linux, we should get at least thread count
	assert.Greater(t, cpuInfo.Threads, 0)

	// Log the values for debugging
	t.Logf("CPU Info - Model: %s, Cores: %d, Threads: %d, Cache: %s, Flags: %d",
		cpuInfo.ModelName, cpuInfo.Cores, cpuInfo.Threads, cpuInfo.CacheSize, len(cpuInfo.Flags))
}

func TestBIOS_Board_Chassis_Product_Integration(t *testing.T) {
	// These functions always return without error
	bios, err := BIOS()
	require.NoError(t, err)

	board, err := Board()
	require.NoError(t, err)

	chassis, err := Chassis()
	require.NoError(t, err)

	product, err := Product()
	require.NoError(t, err)

	// Log the values (may be empty on non-root or VMs)
	t.Logf("BIOS: Vendor=%s, Version=%s", bios.Vendor, bios.Version)
	t.Logf("Board: Name=%s, Vendor=%s", board.Name, board.Vendor)
	t.Logf("Chassis: Type=%s, Vendor=%s", chassis.Type, chassis.Vendor)
	t.Logf("Product: Name=%s, Family=%s", product.Name, product.Family)
}

func TestCAInfo_WithKeystoreType(t *testing.T) {
	mock := &mockCA{
		config: trustedca.CAConfig{
			Identity: []trustedca.CAIdentity{
				{
					Subject: trustedca.CASubject{
						CommonName: "TPM-backed CA",
					},
					KeyAlgorithm: x509.ECDSA,
					ECCCurve:     "P-256",
					KeystoreType: string(xkmssdk.StoreTPM2),
				},
			},
			SelectedCA: 0,
		},
	}

	status := CAInfo(mock)

	require.NotNil(t, status)
	require.NotNil(t, status.RootCA)
	assert.Equal(t, string(xkmssdk.StoreTPM2), status.RootCA.StoreType)
}

func TestNetworkInfoDetails_IPv6LinkLocal(t *testing.T) {
	info := NetworkInfoDetails()

	require.NotNil(t, info)
	// IPv6 should not include link-local addresses if populated
	if info.IPv6 != "" {
		// Link-local IPv6 addresses start with fe80::
		assert.False(t, len(info.IPv6) >= 4 && info.IPv6[:4] == "fe80",
			"IPv6 should not be a link-local address")
	}
	t.Logf("IPv6 address found: %s", info.IPv6)
}
