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

package vtpm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewEKCertInjector(t *testing.T) {
	socketPath := "/tmp/swtpm.sock"

	// Test with nil logger - should use default
	injector := NewEKCertInjector(socketPath, nil)
	if injector == nil {
		t.Fatal("NewEKCertInjector returned nil")
	}

	if injector.socketPath != socketPath {
		t.Errorf("socketPath = %v, want %v", injector.socketPath, socketPath)
	}

	if injector.logger == nil {
		t.Error("logger should be set to default when nil")
	}

	if injector.nvBufferMax != DefaultNVBufferMax {
		t.Errorf("nvBufferMax = %v, want %v", injector.nvBufferMax, DefaultNVBufferMax)
	}
}

func TestNewEKCertInjector_WithLogger(t *testing.T) {
	socketPath := "/var/run/swtpm.sock"
	logger := logging.DefaultLogger()

	injector := NewEKCertInjector(socketPath, logger)
	if injector == nil {
		t.Fatal("NewEKCertInjector returned nil")
	}

	if injector.socketPath != socketPath {
		t.Errorf("socketPath = %v, want %v", injector.socketPath, socketPath)
	}

	if injector.logger != logger {
		t.Error("logger should be the provided logger")
	}
}

func TestNewEKCertInjector_EmptySocketPath(t *testing.T) {
	injector := NewEKCertInjector("", nil)
	if injector == nil {
		t.Fatal("NewEKCertInjector returned nil")
	}

	if injector.socketPath != "" {
		t.Errorf("socketPath = %v, want empty string", injector.socketPath)
	}
}

func TestNewEKCertInjector_VariousSocketPaths(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
	}{
		{
			name:       "standard swtpm socket",
			socketPath: "/var/run/swtpm/swtpm.sock",
		},
		{
			name:       "user temp directory",
			socketPath: "/tmp/vtpm-12345.sock",
		},
		{
			name:       "home directory socket",
			socketPath: "/var/lib/user/.vtpm/socket",
		},
		{
			name:       "relative path",
			socketPath: "relative/path/socket.sock",
		},
		{
			name:       "empty path",
			socketPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injector := NewEKCertInjector(tt.socketPath, nil)
			if injector.socketPath != tt.socketPath {
				t.Errorf("socketPath = %v, want %v", injector.socketPath, tt.socketPath)
			}
		})
	}
}

func TestEKCertInjector_SetNVBufferMax(t *testing.T) {
	injector := NewEKCertInjector("/tmp/swtpm.sock", nil)

	// Set custom buffer size
	customSize := uint16(2048)
	injector.SetNVBufferMax(customSize)

	if injector.nvBufferMax != customSize {
		t.Errorf("nvBufferMax = %v, want %v", injector.nvBufferMax, customSize)
	}
}

func TestEKCertInjector_SetNVBufferMax_VariousSizes(t *testing.T) {
	injector := NewEKCertInjector("/tmp/swtpm.sock", nil)

	tests := []struct {
		name     string
		size     uint16
		expected uint16
	}{
		{
			name:     "minimum value",
			size:     1,
			expected: 1,
		},
		{
			name:     "small value",
			size:     512,
			expected: 512,
		},
		{
			name:     "default value",
			size:     DefaultNVBufferMax,
			expected: DefaultNVBufferMax,
		},
		{
			name:     "larger value",
			size:     2048,
			expected: 2048,
		},
		{
			name:     "maximum uint16 value",
			size:     65535,
			expected: 65535,
		},
		{
			name:     "zero value",
			size:     0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injector.SetNVBufferMax(tt.size)
			if injector.nvBufferMax != tt.expected {
				t.Errorf("nvBufferMax = %v, want %v", injector.nvBufferMax, tt.expected)
			}
		})
	}
}

func TestNVIndexConstants(t *testing.T) {
	// Verify TCG-defined NV indices
	if NVIndexRSAEKCert != 0x01C00002 {
		t.Errorf("NVIndexRSAEKCert = 0x%08X, want 0x01C00002", NVIndexRSAEKCert)
	}

	if NVIndexECCEKCert != 0x01C0000A {
		t.Errorf("NVIndexECCEKCert = 0x%08X, want 0x01C0000A", NVIndexECCEKCert)
	}
}

func TestDefaultNVBufferMax(t *testing.T) {
	if DefaultNVBufferMax != 1024 {
		t.Errorf("DefaultNVBufferMax = %v, want 1024", DefaultNVBufferMax)
	}
}

func TestDefaultNVBufferMax_ReasonableValue(t *testing.T) {
	// DefaultNVBufferMax should be a reasonable value for most TPMs
	// Most TPMs support at least 512 bytes and up to 4096 per NV write
	if DefaultNVBufferMax < 512 {
		t.Errorf("DefaultNVBufferMax = %d, should be at least 512 for compatibility", DefaultNVBufferMax)
	}
	if DefaultNVBufferMax > 4096 {
		t.Errorf("DefaultNVBufferMax = %d, should be at most 4096 for compatibility", DefaultNVBufferMax)
	}
}

func TestIsNVDefinedError(t *testing.T) {
	// Test with non-TPM error
	regularErr := ErrInvalidConfig{Field: "test", Reason: "test"}
	if isNVDefinedError(regularErr) {
		t.Error("isNVDefinedError should return false for non-TPM errors")
	}

	// Test with nil
	if isNVDefinedError(nil) {
		t.Error("isNVDefinedError should return false for nil")
	}
}

func TestIsNVDefinedError_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "error containing NV_DEFINED",
			err:      errors.New("TPM error: NV_DEFINED"),
			expected: true,
		},
		{
			name:     "error containing already defined",
			err:      errors.New("NV index already defined"),
			expected: true,
		},
		{
			name:     "wrapped error with NV_DEFINED",
			err:      errors.New("failed: NV_DEFINED in response"),
			expected: true,
		},
		{
			name:     "ErrInvalidConfig type",
			err:      ErrInvalidConfig{Field: "test", Reason: "test"},
			expected: false,
		},
		{
			name:     "ErrBundleNotFound type",
			err:      ErrBundleNotFound{ID: "test"},
			expected: false,
		},
		{
			name:     "error with lowercase nv_defined",
			err:      errors.New("nv_defined"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNVDefinedError(tt.err)
			if result != tt.expected {
				t.Errorf("isNVDefinedError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsNVUndefinedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "error containing HANDLE",
			err:      errors.New("TPM error: HANDLE out of range"),
			expected: true,
		},
		{
			name:     "error containing NV_UNDEFINED",
			err:      errors.New("NV index NV_UNDEFINED"),
			expected: true,
		},
		{
			name:     "error containing handle lowercase",
			err:      errors.New("invalid handle"),
			expected: true,
		},
		{
			name:     "error containing undefined",
			err:      errors.New("NV index undefined"),
			expected: true,
		},
		{
			name:     "wrapped error with HANDLE",
			err:      errors.New("failed to read: HANDLE error"),
			expected: true,
		},
		{
			name:     "ErrInvalidConfig type",
			err:      ErrInvalidConfig{Field: "test", Reason: "test"},
			expected: false,
		},
		{
			name:     "error with resource not found",
			err:      errors.New("resource not found, undefined handle"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNVUndefinedError(tt.err)
			if result != tt.expected {
				t.Errorf("isNVUndefinedError() = %v, want %v for error %q", result, tt.expected, tt.err)
			}
		})
	}
}

func TestEKAlgorithm_NVIndex_IntegrationWithNVRAM(t *testing.T) {
	// Verify that EKAlgorithm.NVIndex() returns correct NVRAM indices
	tests := []struct {
		algorithm EKAlgorithm
		expected  uint32
	}{
		{
			algorithm: EKAlgorithmRSA,
			expected:  NVIndexRSAEKCert,
		},
		{
			algorithm: EKAlgorithmECC,
			expected:  NVIndexECCEKCert,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			result := tt.algorithm.NVIndex()
			if result != tt.expected {
				t.Errorf("NVIndex() = 0x%08X, want 0x%08X", result, tt.expected)
			}
		})
	}
}

func TestInjectCertificate_NilCertificate(t *testing.T) {
	injector := NewEKCertInjector("/nonexistent.sock", nil)

	ctx := context.Background()
	err := injector.InjectCertificate(ctx, nil, EKAlgorithmRSA)
	if err == nil {
		t.Error("InjectCertificate should fail with nil certificate")
	}

	// Verify it returns the correct error type
	var ekErr ErrEKCertInjectionFailed
	if !errors.As(err, &ekErr) {
		t.Errorf("Expected ErrEKCertInjectionFailed, got %T", err)
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("Error should mention nil certificate, got: %v", err)
	}
}

func TestNVRAMErrorMessages(t *testing.T) {
	// Test that NVRAM-related error messages are informative
	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name: "ErrNVRAMWriteFailed with RSA index",
			err:  ErrNVRAMWriteFailed{NVIndex: NVIndexRSAEKCert, Cause: errors.New("write failed")},
			contains: []string{
				"0x01C00002",
				"write failed",
				"NV RAM",
			},
		},
		{
			name: "ErrNVRAMWriteFailed with ECC index",
			err:  ErrNVRAMWriteFailed{NVIndex: NVIndexECCEKCert, Cause: errors.New("permission denied")},
			contains: []string{
				"0x01C0000A",
				"permission denied",
			},
		},
		{
			name: "ErrEKCertInjectionFailed with cause",
			err:  ErrEKCertInjectionFailed{Cause: errors.New("socket not found")},
			contains: []string{
				"EK certificate",
				"injection failed",
				"socket not found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errMsg, s) {
					t.Errorf("Error message %q should contain %q", errMsg, s)
				}
			}
		})
	}
}

func TestNVNamedHandle_HandleValue(t *testing.T) {
	// Test the nvNamedHandle type's HandleValue method
	tests := []struct {
		name     string
		handle   tpm2.TPMHandle
		expected uint32
	}{
		{
			name:     "RSA EK cert index",
			handle:   tpm2.TPMHandle(NVIndexRSAEKCert),
			expected: NVIndexRSAEKCert,
		},
		{
			name:     "ECC EK cert index",
			handle:   tpm2.TPMHandle(NVIndexECCEKCert),
			expected: NVIndexECCEKCert,
		},
		{
			name:     "zero handle",
			handle:   tpm2.TPMHandle(0),
			expected: 0,
		},
		{
			name:     "max handle value",
			handle:   tpm2.TPMHandle(0xFFFFFFFF),
			expected: 0xFFFFFFFF,
		},
		{
			name:     "custom NV index",
			handle:   tpm2.TPMHandle(0x01C00010),
			expected: 0x01C00010,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nh := nvNamedHandle{
				handle: tt.handle,
				name:   tpm2.TPM2BName{},
			}
			result := nh.HandleValue()
			if result != tt.expected {
				t.Errorf("HandleValue() = 0x%08X, want 0x%08X", result, tt.expected)
			}
		})
	}
}

func TestNVNamedHandle_KnownName(t *testing.T) {
	// Test the nvNamedHandle type's KnownName method
	expectedName := tpm2.TPM2BName{
		Buffer: []byte{0x00, 0x0B, 0x01, 0x02, 0x03, 0x04},
	}

	nh := nvNamedHandle{
		handle: tpm2.TPMHandle(NVIndexRSAEKCert),
		name:   expectedName,
	}

	result := nh.KnownName()
	if result == nil {
		t.Fatal("KnownName() returned nil")
	}

	if len(result.Buffer) != len(expectedName.Buffer) {
		t.Errorf("KnownName().Buffer length = %d, want %d", len(result.Buffer), len(expectedName.Buffer))
	}

	for i, b := range result.Buffer {
		if b != expectedName.Buffer[i] {
			t.Errorf("KnownName().Buffer[%d] = 0x%02X, want 0x%02X", i, b, expectedName.Buffer[i])
		}
	}
}

func TestNVNamedHandle_KnownName_EmptyName(t *testing.T) {
	nh := nvNamedHandle{
		handle: tpm2.TPMHandle(NVIndexRSAEKCert),
		name:   tpm2.TPM2BName{},
	}

	result := nh.KnownName()
	if result == nil {
		t.Fatal("KnownName() returned nil for empty name")
	}

	if len(result.Buffer) != 0 {
		t.Errorf("KnownName().Buffer should be empty, got length %d", len(result.Buffer))
	}
}

func TestNVIndex_PlatformRange(t *testing.T) {
	// NV indices for EK certificates should be in the TCG-defined platform range
	// Platform NV indices start at 0x01C00000
	platformStart := uint32(0x01C00000)
	platformEnd := uint32(0x01C0FFFF)

	if NVIndexRSAEKCert < platformStart || NVIndexRSAEKCert > platformEnd {
		t.Errorf("NVIndexRSAEKCert 0x%08X not in platform range [0x%08X, 0x%08X]",
			NVIndexRSAEKCert, platformStart, platformEnd)
	}

	if NVIndexECCEKCert < platformStart || NVIndexECCEKCert > platformEnd {
		t.Errorf("NVIndexECCEKCert 0x%08X not in platform range [0x%08X, 0x%08X]",
			NVIndexECCEKCert, platformStart, platformEnd)
	}
}

func TestNVIndex_Uniqueness(t *testing.T) {
	// RSA and ECC EK cert indices must be different
	if NVIndexRSAEKCert == NVIndexECCEKCert {
		t.Error("NVIndexRSAEKCert and NVIndexECCEKCert must be different")
	}
}

func TestEKCertInjector_LoggerSetCorrectly(t *testing.T) {
	// Test with nil logger (should use default)
	injector1 := NewEKCertInjector("/tmp/test.sock", nil)
	if injector1.logger == nil {
		t.Error("logger should be set to default logger when nil is provided")
	}

	// Test with explicit logger
	customLogger := logging.DefaultLogger()
	injector2 := NewEKCertInjector("/tmp/test.sock", customLogger)
	if injector2.logger != customLogger {
		t.Error("logger should be set to the provided logger")
	}
}

func TestVerifyCertificate_RequiresSocketConnection(t *testing.T) {
	// VerifyCertificate requires a running swtpm, so we can only
	// test that it fails gracefully when no connection is available
	injector := NewEKCertInjector("/nonexistent/socket.sock", nil)

	ctx := context.Background()

	// Test with nil expected certificate
	err := injector.VerifyCertificate(ctx, nil, EKAlgorithmRSA)
	// This will fail at the ReadCertificate step (socket connection)
	if err == nil {
		t.Error("VerifyCertificate should fail with socket connection error")
	}
}

func TestCheckEKCertificateExists_RequiresSocketConnection(t *testing.T) {
	// CheckEKCertificateExists requires a running swtpm, so we can only
	// test that it fails gracefully when no connection is available
	injector := NewEKCertInjector("/nonexistent/socket.sock", nil)

	ctx := context.Background()
	_, _, err := injector.CheckEKCertificateExists(ctx, EKAlgorithmRSA)
	// This will fail at the socket connection step
	if err == nil {
		t.Error("CheckEKCertificateExists should fail with socket connection error")
	}
}

func TestReadCertificate_RequiresSocketConnection(t *testing.T) {
	// ReadCertificate requires a running swtpm, so we can only
	// test that it fails gracefully when no connection is available
	injector := NewEKCertInjector("/nonexistent/socket.sock", nil)

	ctx := context.Background()
	_, err := injector.ReadCertificate(ctx, EKAlgorithmRSA)
	// This will fail at the socket connection step
	if err == nil {
		t.Error("ReadCertificate should fail with socket connection error")
	}
}

func TestInjectCertificate_SocketConnectionError(t *testing.T) {
	// InjectCertificate should fail gracefully when socket doesn't exist
	injector := NewEKCertInjector("/nonexistent/path/to/socket.sock", nil)

	// Create a minimal test certificate
	ctx := context.Background()

	// We can't easily create a valid x509.Certificate without more setup,
	// but we can test the nil case which is validated first
	err := injector.InjectCertificate(ctx, nil, EKAlgorithmRSA)
	if err == nil {
		t.Error("InjectCertificate should fail for nil certificate")
	}

	// Verify error type
	var ekErr ErrEKCertInjectionFailed
	if !errors.As(err, &ekErr) {
		t.Errorf("Expected ErrEKCertInjectionFailed, got %T", err)
	}
}

// =============================================================================
// Additional NVRAM Tests for Coverage
// =============================================================================

func TestIsNVDefinedError_TPMRCError(t *testing.T) {
	// Test with TPMRC error code for NV_DEFINED (0x149)
	err := tpm2.TPMRC(0x149)
	if !isNVDefinedError(err) {
		t.Error("isNVDefinedError should return true for TPM_RC_NV_DEFINED (0x149)")
	}

	// Test with unrelated TPMRC error
	err = tpm2.TPMRC(0x100) // TPM_RC_INITIALIZE
	if isNVDefinedError(err) {
		t.Error("isNVDefinedError should return false for TPM_RC_INITIALIZE")
	}
}

func TestIsNVUndefinedError_TPMRCError(t *testing.T) {
	// Test with TPMRC error code for HANDLE (0x08B)
	err := tpm2.TPMRC(0x08B)
	if !isNVUndefinedError(err) {
		t.Error("isNVUndefinedError should return true for TPM_RC_HANDLE (0x08B)")
	}

	// Test with TPMRC error code 0x14B
	err = tpm2.TPMRC(0x14B)
	if !isNVUndefinedError(err) {
		t.Error("isNVUndefinedError should return true for 0x14B")
	}

	// Test with unrelated TPMRC error
	err = tpm2.TPMRC(0x100)
	if isNVUndefinedError(err) {
		t.Error("isNVUndefinedError should return false for TPM_RC_INITIALIZE")
	}
}

func TestNVNamedHandle_Completeness(t *testing.T) {
	// Test that nvNamedHandle implements necessary interface
	testName := tpm2.TPM2BName{
		Buffer: []byte{0x00, 0x0B, 0x01, 0x02, 0x03},
	}
	nh := nvNamedHandle{
		handle: tpm2.TPMHandle(0x01C00002),
		name:   testName,
	}

	// Verify HandleValue
	if nh.HandleValue() != 0x01C00002 {
		t.Errorf("HandleValue = 0x%08X, want 0x01C00002", nh.HandleValue())
	}

	// Verify KnownName returns pointer to name
	knownName := nh.KnownName()
	if knownName == nil {
		t.Fatal("KnownName should not return nil")
	}
	if len(knownName.Buffer) != len(testName.Buffer) {
		t.Errorf("KnownName buffer length = %d, want %d", len(knownName.Buffer), len(testName.Buffer))
	}
}

func TestEKCertInjector_Fields(t *testing.T) {
	injector := NewEKCertInjector("/test/socket.sock", nil)

	// Test initial state
	if injector.socketPath != "/test/socket.sock" {
		t.Errorf("socketPath = %v, want /test/socket.sock", injector.socketPath)
	}
	if injector.nvBufferMax != DefaultNVBufferMax {
		t.Errorf("nvBufferMax = %d, want %d", injector.nvBufferMax, DefaultNVBufferMax)
	}

	// Test SetNVBufferMax
	injector.SetNVBufferMax(512)
	if injector.nvBufferMax != 512 {
		t.Errorf("nvBufferMax after set = %d, want 512", injector.nvBufferMax)
	}
}

func TestIsNVDefinedError_StringMatching(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "uppercase NV_DEFINED",
			err:      errors.New("command failed: NV_DEFINED"),
			expected: true,
		},
		{
			name:     "already defined phrase",
			err:      errors.New("NV index is already defined"),
			expected: true,
		},
		{
			name:     "no match",
			err:      errors.New("some unrelated error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNVDefinedError(tt.err)
			if result != tt.expected {
				t.Errorf("isNVDefinedError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsNVUndefinedError_StringMatching(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "uppercase HANDLE",
			err:      errors.New("TPM returned: HANDLE error"),
			expected: true,
		},
		{
			name:     "lowercase handle",
			err:      errors.New("invalid handle specified"),
			expected: true,
		},
		{
			name:     "undefined keyword",
			err:      errors.New("NV index is undefined"),
			expected: true,
		},
		{
			name:     "NV_UNDEFINED constant",
			err:      errors.New("error NV_UNDEFINED occurred"),
			expected: true,
		},
		{
			name:     "no match",
			err:      errors.New("authentication failed"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNVUndefinedError(tt.err)
			if result != tt.expected {
				t.Errorf("isNVUndefinedError() = %v, want %v for error %q", result, tt.expected, tt.err)
			}
		})
	}
}
